"""Tests for provision_accounts.py (U6) — Supabase Admin API provisioning.

All HTTP is mocked via httpx.MockTransport; no network. The security
assertions (service-role key never on stdout/stderr, .env never partially
written, 0o600 mode requested) are the load-bearing ones.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest

import provision_accounts as pa

PROJECT_URL = "https://abcdefghijklmnopqrst.supabase.co"
SERVICE_KEY = "sb_secret_test_service_role_key_value_123456"


class _AdminStub:
    """Stateful GoTrue Admin API + Management API stub for httpx.MockTransport."""

    def __init__(self, management_key: str | None = None, filler_user_count: int = 0):
        self.users: dict[str, dict] = {}  # id -> {email, payload}
        self.requests: list[httpx.Request] = []
        self.management_key = management_key
        # Unrelated users listed BEFORE the test accounts, to push them onto
        # later pages (real GoTrue pagination is contiguous).
        self.filler_user_count = filler_user_count
        self._counter = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.url.host == "api.supabase.com":
            if self.management_key is None:
                return httpx.Response(401, json={"message": "bad token"})
            return httpx.Response(200, json=[
                {"name": "anon", "type": "publishable", "api_key": "anon-key"},
                {"name": "service_role", "type": "secret", "api_key": self.management_key},
            ])
        if request.method == "POST" and path == "/auth/v1/admin/users":
            payload = json.loads(request.content)
            email = payload["email"]
            for uid, u in self.users.items():
                if u["email"] == email:
                    return httpx.Response(
                        422, json={"msg": "A user with this email address has already been registered"}
                    )
            self._counter += 1
            uid = f"uid-{self._counter:04d}"
            self.users[uid] = {"email": email, "payload": payload}
            return httpx.Response(200, json={"id": uid, "email": email})
        if request.method == "GET" and path == "/auth/v1/admin/users":
            page = int(request.url.params.get("page", "1"))
            per_page = int(request.url.params.get("per_page", "50"))
            all_users = [
                {"id": f"filler-{i}", "email": f"filler-{i}@example.com"}
                for i in range(self.filler_user_count)
            ] + [{"id": uid, "email": u["email"]} for uid, u in self.users.items()]
            start = (page - 1) * per_page
            return httpx.Response(200, json={"users": all_users[start:start + per_page]})
        if request.method == "PUT" and path.startswith("/auth/v1/admin/users/"):
            uid = path.rsplit("/", 1)[1]
            if uid not in self.users:
                return httpx.Response(404, json={"msg": "user not found"})
            self.users[uid]["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"id": uid})
        if request.method == "DELETE" and path.startswith("/auth/v1/admin/users/"):
            uid = path.rsplit("/", 1)[1]
            if uid in self.users:
                del self.users[uid]
                return httpx.Response(200, json={})
            return httpx.Response(404, json={"msg": "user not found"})
        return httpx.Response(500, json={"msg": f"unexpected: {request.method} {path}"})


@pytest.fixture
def stub():
    return _AdminStub()


@pytest.fixture
def client(stub):
    with httpx.Client(transport=httpx.MockTransport(stub.handler)) as c:
        yield c


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """Isolated .env preloaded with the connection config; no ambient env."""
    path = tmp_path / ".env"
    path.write_text(
        f"SUPABASE_PROJECT_URL={PROJECT_URL}\n"
        f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_KEY}\n",
        encoding="utf-8",
    )
    for key in (
        "SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ACCESS_TOKEN",
        "PENTEST_USER_A_EMAIL", "PENTEST_USER_A_PASSWORD", "PENTEST_USER_A_ID",
        "PENTEST_USER_B_EMAIL", "PENTEST_USER_B_PASSWORD", "PENTEST_USER_B_ID",
    ):
        monkeypatch.delenv(key, raising=False)
    return path


def _run(client, env_file, *extra) -> int:
    return pa.main(["--env-file", str(env_file), *extra], http=client)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_provision_creates_both_accounts_email_confirmed(client, stub, env_file, capsys):
    rc = _run(client, env_file)
    assert rc == 0
    creates = [r for r in stub.requests if r.method == "POST"]
    assert len(creates) == 2
    for req in creates:
        payload = json.loads(req.content)
        assert payload["email_confirm"] is True
        assert req.headers["apikey"] == SERVICE_KEY
        assert req.headers["authorization"] == f"Bearer {SERVICE_KEY}"

    values = pa.parse_env_file(env_file)
    assert values["PENTEST_USER_A_EMAIL"]
    assert values["PENTEST_USER_A_PASSWORD"]
    assert values["PENTEST_USER_B_EMAIL"]
    assert values["PENTEST_USER_B_PASSWORD"]
    assert values["PENTEST_USER_A_ID"] == "uid-0001"
    assert values["PENTEST_USER_B_ID"] == "uid-0002"
    # Pre-existing config lines preserved.
    assert values["SUPABASE_PROJECT_URL"] == PROJECT_URL


def test_provision_requests_0600_mode(client, env_file, monkeypatch):
    chmod_calls: list[tuple[str, int]] = []
    real_chmod = os.chmod
    monkeypatch.setattr(
        os, "chmod", lambda p, mode: (chmod_calls.append((str(p), mode)), real_chmod(p, mode))
    )
    assert _run(client, env_file) == 0
    assert chmod_calls, "os.chmod was never called on the .env write"
    assert all(mode == 0o600 for _, mode in chmod_calls)


def test_provision_reuses_existing_env_credentials(client, stub, env_file):
    env_file.write_text(
        env_file.read_text(encoding="utf-8")
        + "PENTEST_USER_A_EMAIL=keep-a@example.com\n"
        + "PENTEST_USER_A_PASSWORD=keep-pw-a\n",
        encoding="utf-8",
    )
    assert _run(client, env_file) == 0
    emails = [json.loads(r.content)["email"] for r in stub.requests if r.method == "POST"]
    assert "keep-a@example.com" in emails
    values = pa.parse_env_file(env_file)
    assert values["PENTEST_USER_A_PASSWORD"] == "keep-pw-a"


def test_rerun_is_idempotent_recovers_ids(client, stub, env_file):
    assert _run(client, env_file) == 0
    first = pa.parse_env_file(env_file)
    # Second run: same emails (reused from .env) -> 422 already-registered ->
    # recover the SAME ids via the list endpoint.
    assert _run(client, env_file) == 0
    second = pa.parse_env_file(env_file)
    assert second["PENTEST_USER_A_ID"] == first["PENTEST_USER_A_ID"]
    assert second["PENTEST_USER_B_ID"] == first["PENTEST_USER_B_ID"]
    assert len(stub.users) == 2  # no duplicates created


def test_recovery_resets_password_so_env_creds_are_live(client, stub, env_file):
    # First run provisions; then simulate a stale .env password by editing it.
    assert _run(client, env_file) == 0
    values = pa.parse_env_file(env_file)
    pa.update_env_file(env_file, {"PENTEST_USER_A_PASSWORD": "stale-but-new-password-xyz"})
    assert _run(client, env_file) == 0
    # Recovery must PUT the password being written to .env onto the recovered
    # user — otherwise provisioning reports [ok] with dead credentials.
    puts = [r for r in stub.requests if r.method == "PUT"]
    assert puts, "no Admin API password update on the recovery path"
    put_payloads = [json.loads(r.content) for r in puts]
    assert any(p.get("password") == "stale-but-new-password-xyz" for p in put_payloads)
    uid_a = values["PENTEST_USER_A_ID"]
    assert any(r.url.path.endswith(f"/{uid_a}") for r in puts)


def test_deterministic_emails_recover_after_total_env_loss(client, stub, env_file):
    assert _run(client, env_file) == 0
    first = pa.parse_env_file(env_file)
    # Simulate a lost .env: keep only the connection config.
    env_file.write_text(
        f"SUPABASE_PROJECT_URL={PROJECT_URL}\n"
        f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_KEY}\n",
        encoding="utf-8",
    )
    assert _run(client, env_file) == 0
    second = pa.parse_env_file(env_file)
    # Same deterministic emails -> already-registered -> recovered, not orphaned.
    assert second["PENTEST_USER_A_ID"] == first["PENTEST_USER_A_ID"]
    assert len(stub.users) == 2  # no orphan duplicates


def test_fetch_service_role_key_via_access_token(tmp_path, monkeypatch, capsys):
    fetched_key = "sb_secret_fetched_via_management_api_9876543210"
    stub = _AdminStub(management_key=fetched_key)
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"SUPABASE_PROJECT_URL={PROJECT_URL}\n"
        "SUPABASE_ACCESS_TOKEN=sbp_management_pat_token_abcdef123456\n",
        encoding="utf-8",
    )
    for key in ("SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ACCESS_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    with httpx.Client(transport=httpx.MockTransport(stub.handler)) as client:
        rc = _run(client, env_file)
    assert rc == 0
    # The fetched key was used against the Admin API; the PAT was not.
    creates = [r for r in stub.requests if r.method == "POST"]
    assert all(r.headers["apikey"] == fetched_key for r in creates)
    mgmt = [r for r in stub.requests if r.url.host == "api.supabase.com"]
    assert mgmt and all(
        r.headers["authorization"] == "Bearer sbp_management_pat_token_abcdef123456" for r in mgmt
    )
    # Neither secret reaches output.
    out = capsys.readouterr()
    combined = out.out + out.err
    assert fetched_key not in combined
    assert "sbp_management_pat_token_abcdef123456" not in combined


def test_fetch_service_role_key_failure_does_not_leak_token(tmp_path, monkeypatch, capsys):
    stub = _AdminStub(management_key=None)  # Management API 401s
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"SUPABASE_PROJECT_URL={PROJECT_URL}\n"
        "SUPABASE_ACCESS_TOKEN=sbp_management_pat_token_abcdef123456\n",
        encoding="utf-8",
    )
    for key in ("SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ACCESS_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    with httpx.Client(transport=httpx.MockTransport(stub.handler)) as client:
        rc = _run(client, env_file)
    assert rc == 1
    out = capsys.readouterr()
    assert "sbp_management_pat_token_abcdef123456" not in out.out + out.err


def test_recover_id_found_on_second_list_page(env_file, capsys):
    # 50 unrelated users fill page 1; the target account lands on page 2.
    stub = _AdminStub(filler_user_count=50)
    # Pre-seed the user so create returns already-registered.
    stub.users["uid-preexisting"] = {"email": "stackbadger-pentest-a@example.com", "payload": {}}
    with httpx.Client(transport=httpx.MockTransport(stub.handler)) as client:
        rc = _run(client, env_file)
    assert rc == 0
    values = pa.parse_env_file(env_file)
    assert values["PENTEST_USER_A_ID"] == "uid-preexisting"


def test_already_registered_but_unfindable_errors_clearly(env_file, capsys):
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(422, json={"msg": "already been registered"})
        if request.method == "GET":
            return httpx.Response(200, json={"users": []})
        return httpx.Response(500, json={})

    with httpx.Client(transport=httpx.MockTransport(_handler)) as client:
        rc = _run(client, env_file)
    assert rc == 1
    assert "already registered but could not be found" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Error paths — never partial, never leak
# ---------------------------------------------------------------------------

def test_missing_service_role_key_names_it_and_writes_nothing(client, tmp_path, monkeypatch, capsys):
    env_file = tmp_path / ".env"
    env_file.write_text(f"SUPABASE_PROJECT_URL={PROJECT_URL}\n", encoding="utf-8")
    for key in ("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ACCESS_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    before = env_file.read_text(encoding="utf-8")
    rc = _run(client, env_file)
    assert rc == 1
    assert "SUPABASE_SERVICE_ROLE_KEY" in capsys.readouterr().err
    assert env_file.read_text(encoding="utf-8") == before  # untouched


def test_admin_api_error_surfaces_status_without_leaking_key(env_file, capsys):
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"msg": "forbidden", "hint": "bad key"})

    with httpx.Client(transport=httpx.MockTransport(_handler)) as client:
        rc = _run(client, env_file)
    assert rc == 1
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "403" in combined
    assert SERVICE_KEY not in combined
    # No partial write: managed keys absent.
    values = pa.parse_env_file(env_file)
    assert "PENTEST_USER_A_EMAIL" not in values
    assert "PENTEST_USER_A_ID" not in values


def test_second_account_failure_leaves_env_unwritten(env_file, capsys):
    calls = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(200, json={"id": "uid-a", "email": "a"})
            return httpx.Response(500, json={"msg": "boom"})
        return httpx.Response(500, json={})

    before = env_file.read_text(encoding="utf-8")
    with httpx.Client(transport=httpx.MockTransport(_handler)) as client:
        rc = _run(client, env_file)
    assert rc == 1
    # Account A succeeded remotely but .env must not carry a half-written pair.
    assert env_file.read_text(encoding="utf-8") == before


def test_traceback_redacts_service_role_key(env_file, capsys):
    def _handler(request: httpx.Request) -> httpx.Response:
        raise RuntimeError(f"transport blew up with header {SERVICE_KEY} embedded")

    with httpx.Client(transport=httpx.MockTransport(_handler)) as client:
        rc = _run(client, env_file)
    assert rc == 1
    out = capsys.readouterr()
    combined = out.out + out.err
    assert SERVICE_KEY not in combined
    assert "[REDACTED_SERVICE_ROLE_KEY]" in combined


def test_manual_provider_prints_steps_and_exits_2(capsys):
    # Exit 2 (not 0): printing instructions is not provisioning success — an
    # agent gating on "exit 0 -> accounts exist" must see the difference.
    rc = pa.main(["--provider", "clerk"])
    assert rc == pa.EXIT_MANUAL_STEPS == 2
    out = capsys.readouterr().out
    assert "dashboard" in out.lower()
    assert "PENTEST_USER_" in out


def test_manual_provider_cleanup_prints_deletion_guidance_exits_2(capsys):
    rc = pa.main(["--provider", "firebase", "--cleanup"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "delete" in out.lower()
    assert "dashboard" in out.lower()


def test_error_body_echoing_password_is_scrubbed(tmp_path, monkeypatch, capsys):
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"SUPABASE_PROJECT_URL={PROJECT_URL}\n"
        f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_KEY}\n"
        "PENTEST_USER_A_PASSWORD=preset-password-secret-123\n",
        encoding="utf-8",
    )
    for key in ("SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY",
                "PENTEST_USER_A_PASSWORD"):
        monkeypatch.delenv(key, raising=False)

    def _echoing_handler(request: httpx.Request) -> httpx.Response:
        # Hostile/buggy endpoint that echoes the submitted payload back.
        return httpx.Response(500, json={"msg": f"rejected: {request.content.decode()}"})

    with httpx.Client(transport=httpx.MockTransport(_echoing_handler)) as client:
        rc = _run(client, env_file)
    assert rc == 1
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "preset-password-secret-123" not in combined
    assert "[REDACTED_PASSWORD]" in combined


# ---------------------------------------------------------------------------
# Project-URL host gate — the service-role key must never be sent to an
# arbitrary host (typo / attacker-supplied SUPABASE_PROJECT_URL).
# ---------------------------------------------------------------------------

def _host_gate_env(tmp_path, monkeypatch, url: str) -> Path:
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"SUPABASE_PROJECT_URL={url}\n"
        f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_KEY}\n",
        encoding="utf-8",
    )
    for key in ("SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ACCESS_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    return env_file


def test_non_supabase_host_is_refused_before_any_request(tmp_path, monkeypatch, capsys):
    env_file = _host_gate_env(tmp_path, monkeypatch, "https://evil.example.com")

    def _no_network(request):
        raise AssertionError("the service-role key must not be sent to an unrecognized host")

    with httpx.Client(transport=httpx.MockTransport(_no_network)) as client:
        rc = pa.main(["--env-file", str(env_file)], http=client)
    assert rc == 1
    err = capsys.readouterr().err
    assert "Refusing to send the service-role key" in err
    assert "--allow-custom-domain" in err
    assert SERVICE_KEY not in err


def test_cleanup_also_refuses_non_supabase_host(tmp_path, monkeypatch, capsys):
    env_file = _host_gate_env(tmp_path, monkeypatch, "https://evil.example.com")
    env_file.write_text(
        env_file.read_text(encoding="utf-8") + "PENTEST_USER_A_ID=uid-a\n", encoding="utf-8"
    )

    def _no_network(request):
        raise AssertionError("cleanup must not send the key to an unrecognized host")

    with httpx.Client(transport=httpx.MockTransport(_no_network)) as client:
        rc = pa.main(["--cleanup", "--env-file", str(env_file)], http=client)
    assert rc == 1
    assert "Refusing to send the service-role key" in capsys.readouterr().err


def test_allow_custom_domain_opt_in_permits_other_hosts(tmp_path, monkeypatch):
    env_file = _host_gate_env(tmp_path, monkeypatch, "https://supabase.selfhosted.example")
    stub = _AdminStub()
    with httpx.Client(transport=httpx.MockTransport(stub.handler)) as client:
        rc = pa.main(["--env-file", str(env_file), "--allow-custom-domain"], http=client)
    assert rc == 0
    assert len(stub.users) == 2


def test_rx_supabase_host_gate_vectors():
    # [RX-TEST] match/no-match vectors for the host gate.
    assert pa._SUPABASE_HOST_RE.match("https://abcdefghijklmnopqrst.supabase.co")
    assert pa._SUPABASE_HOST_RE.match("https://my-branch-ref.supabase.co")
    assert not pa._SUPABASE_HOST_RE.match("https://ref.supabase.co.evil.com")   # suffix attack
    assert not pa._SUPABASE_HOST_RE.match("https://evil.com/ref.supabase.co")   # path trick
    assert not pa._SUPABASE_HOST_RE.match("https://ref.supabase.co:8443")       # port
    assert not pa._SUPABASE_HOST_RE.match("https://sub.ref.supabase.co")        # extra label
    assert not pa._SUPABASE_HOST_RE.match("http://ref.supabase.co")             # scheme
    assert not pa._SUPABASE_HOST_RE.match("https://evil-supabase.co")           # lookalike


# ---------------------------------------------------------------------------
# update_env_file unit behavior
# ---------------------------------------------------------------------------

def test_update_env_file_drops_duplicate_managed_keys(tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        "PENTEST_USER_A_EMAIL=old-1@example.com\n"
        "OTHER=keep\n"
        "PENTEST_USER_A_EMAIL=old-2@example.com\n",
        encoding="utf-8",
    )
    pa.update_env_file(path, {"PENTEST_USER_A_EMAIL": "new@example.com"})
    text = path.read_text(encoding="utf-8")
    # bash `source` is last-wins: a surviving duplicate would shadow the new value.
    assert text.count("PENTEST_USER_A_EMAIL") == 1
    assert "new@example.com" in text
    assert "old-2@example.com" not in text
    assert "OTHER=keep" in text


def test_update_env_file_none_removes_line_but_preserves_comments(tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        "# PENTEST_USER_A_ID is written by provisioning\n"
        "PENTEST_USER_A_ID=uid-1\n"
        "OTHER=keep\n",
        encoding="utf-8",
    )
    pa.update_env_file(path, {"PENTEST_USER_A_ID": None})
    text = path.read_text(encoding="utf-8")
    assert "PENTEST_USER_A_ID=uid-1" not in text
    assert "# PENTEST_USER_A_ID is written by provisioning" in text  # comment kept
    assert "OTHER=keep" in text


# ---------------------------------------------------------------------------
# [RX-TEST] regex vectors — match/no-match pairs for every regex this module
# ships (mirrors the tests/test_scrub.py convention).
# ---------------------------------------------------------------------------

def test_rx_scrub_sb_secret_pattern():
    assert "[REDACTED_SERVICE_ROLE_KEY]" in pa._scrub("key=sb_secret_AbC123_-xyz end")
    assert pa._scrub("sb_public_not_a_secret") == "sb_public_not_a_secret"  # no-match


def test_rx_scrub_jwt_boundary():
    assert pa._scrub("eyJ" + "a" * 19) == "eyJ" + "a" * 19          # 19 chars: no match
    assert pa._scrub("eyJ" + "a" * 20) == "[REDACTED_JWT]"          # 20 chars: match


def test_rx_already_registered_matcher():
    import re as _re
    pattern = r"already (been )?registered|already exists"
    assert _re.search(pattern, "A user with this email address has already been registered", _re.I)
    assert _re.search(pattern, "user already exists", _re.I)
    assert not _re.search(pattern, "user created successfully", _re.I)  # no-match


def test_rx_project_ref_from_url():
    assert pa._project_ref_from_url("https://abcdefghijklmnopqrst.supabase.co") == "abcdefghijklmnopqrst"
    assert pa._project_ref_from_url("https://other.example.com") is None  # no-match


# ---------------------------------------------------------------------------
# Cleanup (--cleanup) — exercised again via teardown.py in test_teardown.py
# ---------------------------------------------------------------------------

def test_cleanup_deletes_by_stored_id_and_clears_provisioned_values(client, stub, env_file, capsys):
    assert _run(client, env_file) == 0
    assert len(stub.users) == 2
    rc = _run(client, env_file, "--cleanup")
    assert rc == 0
    assert stub.users == {}
    values = pa.parse_env_file(env_file)
    assert "PENTEST_USER_A_ID" not in values
    assert "PENTEST_USER_B_ID" not in values
    # Script-named (deterministic) accounts are fully cleared — the deleted
    # accounts' credentials are dead, and clearing them makes a second
    # teardown a true no-op.
    assert "PENTEST_USER_A_EMAIL" not in values
    assert "PENTEST_USER_A_PASSWORD" not in values
    combined = capsys.readouterr()
    assert SERVICE_KEY not in combined.out + combined.err


def test_cleanup_keeps_custom_credentials(client, stub, env_file):
    env_file.write_text(
        env_file.read_text(encoding="utf-8")
        + "PENTEST_USER_A_EMAIL=custom-a@corp.example\n"
        + "PENTEST_USER_A_PASSWORD=custom-pw\n"
        + "PENTEST_USER_B_EMAIL=custom-b@corp.example\n"
        + "PENTEST_USER_B_PASSWORD=custom-pw-b\n",
        encoding="utf-8",
    )
    assert _run(client, env_file) == 0
    assert _run(client, env_file, "--cleanup") == 0
    values = pa.parse_env_file(env_file)
    # Operator-supplied custom emails/passwords are preserved; only IDs clear.
    assert values["PENTEST_USER_A_EMAIL"] == "custom-a@corp.example"
    assert values["PENTEST_USER_A_PASSWORD"] == "custom-pw"
    assert "PENTEST_USER_A_ID" not in values


def test_cleanup_falls_back_to_deterministic_email_lookup(client, stub, env_file, capsys):
    # Simulate a first run that created the accounts but DIED before writing
    # .env: accounts exist remotely, .env has creds for A only via emails.
    stub.users["uid-orphan-a"] = {"email": "stackbadger-pentest-a@example.com", "payload": {}}
    env_file.write_text(
        env_file.read_text(encoding="utf-8")
        + "PENTEST_USER_A_EMAIL=stackbadger-pentest-a@example.com\n",
        encoding="utf-8",
    )
    rc = _run(client, env_file, "--cleanup")
    assert rc == 0
    assert "uid-orphan-a" not in stub.users  # found by email, deleted
    values = pa.parse_env_file(env_file)
    assert "PENTEST_USER_A_EMAIL" not in values


def test_cleanup_never_deletes_custom_email_by_lookup(client, stub, env_file):
    # A custom (non-deterministic) email with no stored ID must NOT trigger
    # the delete-by-email fallback — it may be a manually-created account.
    stub.users["uid-manual"] = {"email": "real-user@corp.example", "payload": {}}
    env_file.write_text(
        env_file.read_text(encoding="utf-8")
        + "PENTEST_USER_A_EMAIL=real-user@corp.example\n",
        encoding="utf-8",
    )
    rc = _run(client, env_file, "--cleanup")
    assert rc == 0
    assert "uid-manual" in stub.users  # untouched


def test_cleanup_sweeps_orphans_when_env_was_never_written(client, stub, env_file, capsys):
    # THE orphan state: provision created the accounts but died before its
    # single .env write. Nothing local points at them — teardown must still
    # find and delete them via the deterministic default emails.
    stub.users["uid-orphan-a"] = {"email": "stackbadger-pentest-a@example.com", "payload": {}}
    stub.users["uid-orphan-b"] = {"email": "stackbadger-pentest-b@example.com", "payload": {}}
    rc = _run(client, env_file, "--cleanup")  # .env has only connection config
    assert rc == 0
    assert stub.users == {}
    assert "teardown complete" in capsys.readouterr().out


def test_cleanup_with_nothing_stored_sweeps_then_reports_nothing(client, stub, env_file, capsys):
    # Connection config available, nothing recorded, nothing standing: the
    # default-email sweep runs (lookups only) and reports a clean no-op.
    rc = _run(client, env_file, "--cleanup")
    assert rc == 0
    assert "nothing to tear down" in capsys.readouterr().out
    assert not any(r.method == "DELETE" for r in stub.requests)


def test_cleanup_without_config_and_nothing_recorded_is_friendly_noop(tmp_path, monkeypatch, capsys):
    env_file = tmp_path / ".env"
    env_file.write_text("UNRELATED=1\n", encoding="utf-8")
    for key in ("SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ACCESS_TOKEN",
                "PENTEST_USER_A_ID", "PENTEST_USER_B_ID",
                "PENTEST_USER_A_EMAIL", "PENTEST_USER_B_EMAIL"):
        monkeypatch.delenv(key, raising=False)

    def _no_network(request):
        raise AssertionError("no network expected without connection config")

    with httpx.Client(transport=httpx.MockTransport(_no_network)) as client:
        rc = pa.main(["--cleanup", "--env-file", str(env_file)], http=client)
    assert rc == 0
    assert "nothing recorded" in capsys.readouterr().out


def test_cleanup_confirmed_absent_clears_dead_deterministic_creds(client, stub, env_file):
    # Stored deterministic email + no ID, account confirmed absent remotely:
    # the dead credentials are cleared so the next teardown can fast-path.
    env_file.write_text(
        env_file.read_text(encoding="utf-8")
        + "PENTEST_USER_A_EMAIL=stackbadger-pentest-a@example.com\n"
        + "PENTEST_USER_A_PASSWORD=dead-password-123\n",
        encoding="utf-8",
    )
    rc = _run(client, env_file, "--cleanup")  # stub has no users -> absent
    assert rc == 0
    values = pa.parse_env_file(env_file)
    assert "PENTEST_USER_A_EMAIL" not in values
    assert "PENTEST_USER_A_PASSWORD" not in values


def test_cleanup_with_ids_but_no_config_fails_loudly(tmp_path, monkeypatch, capsys):
    env_file = tmp_path / ".env"
    env_file.write_text("PENTEST_USER_A_ID=uid-a\n", encoding="utf-8")
    for key in ("SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ACCESS_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500))) as client:
        rc = pa.main(["--cleanup", "--env-file", str(env_file)], http=client)
    assert rc == 1  # something IS recorded -> must not silently no-op
    assert "project URL" in capsys.readouterr().err


def test_cleanup_mixed_outcome_clears_absent_slot_keeps_failed_slot(client, stub, env_file, capsys):
    # Slot A: deterministic email, confirmed absent -> creds cleared.
    # Slot B: stored ID whose deletion 500s -> rc 1, ID retained for retry.
    env_file.write_text(
        env_file.read_text(encoding="utf-8")
        + "PENTEST_USER_A_EMAIL=stackbadger-pentest-a@example.com\n"
        + "PENTEST_USER_B_ID=uid-b-stuck\n",
        encoding="utf-8",
    )

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            return httpx.Response(500, json={"msg": "boom"})
        return httpx.Response(200, json={"users": []})

    with httpx.Client(transport=httpx.MockTransport(_handler)) as client2:
        rc = pa.main(["--cleanup", "--env-file", str(env_file)], http=client2)
    assert rc == 1
    values = pa.parse_env_file(env_file)
    assert "PENTEST_USER_A_EMAIL" not in values      # absent slot cleared
    assert values["PENTEST_USER_B_ID"] == "uid-b-stuck"  # failed slot retained
    assert "uid-b-stuck" in capsys.readouterr().err


def test_recovery_does_not_reset_password_of_custom_email(client, stub, env_file, capsys):
    # An operator-supplied custom email that already exists must NOT have its
    # password silently reset (a typo'd real user's email would lock them out).
    stub.users["uid-real"] = {"email": "real-user@corp.example", "payload": {}}
    env_file.write_text(
        env_file.read_text(encoding="utf-8")
        + "PENTEST_USER_A_EMAIL=real-user@corp.example\n",
        encoding="utf-8",
    )
    rc = _run(client, env_file)
    assert rc == 0
    real_user_puts = [
        r for r in stub.requests if r.method == "PUT" and r.url.path.endswith("/uid-real")
    ]
    assert not real_user_puts  # never reset
    assert "password NOT changed" in capsys.readouterr().err
    values = pa.parse_env_file(env_file)
    assert values["PENTEST_USER_A_ID"] == "uid-real"  # ID still recovered
