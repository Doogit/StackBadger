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
    """Stateful GoTrue Admin API stub for httpx.MockTransport."""

    def __init__(self):
        self.users: dict[str, dict] = {}  # id -> {email, password}
        self.requests: list[httpx.Request] = []
        self._counter = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
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
            users = [{"id": uid, "email": u["email"]} for uid, u in self.users.items()]
            return httpx.Response(200, json={"users": users if page == 1 else []})
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


def test_manual_provider_prints_steps_and_exits_zero(capsys):
    rc = pa.main(["--provider", "clerk"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dashboard" in out.lower()
    assert "PENTEST_USER_" in out


# ---------------------------------------------------------------------------
# Cleanup (--cleanup) — exercised again via teardown.py in test_teardown.py
# ---------------------------------------------------------------------------

def test_cleanup_deletes_by_stored_id_and_clears_ids(client, stub, env_file, capsys):
    assert _run(client, env_file) == 0
    assert len(stub.users) == 2
    rc = _run(client, env_file, "--cleanup")
    assert rc == 0
    assert stub.users == {}
    values = pa.parse_env_file(env_file)
    assert "PENTEST_USER_A_ID" not in values
    assert "PENTEST_USER_B_ID" not in values
    combined = capsys.readouterr()
    assert SERVICE_KEY not in combined.out + combined.err


def test_cleanup_with_nothing_stored_is_a_noop(client, env_file, capsys):
    rc = _run(client, env_file, "--cleanup")
    assert rc == 0
    assert "nothing to tear down" in capsys.readouterr().out
