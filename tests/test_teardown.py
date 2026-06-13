"""Tests for teardown.py (U8) — idempotent removal of seeded accounts."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

import provision_accounts as pa
import teardown

PROJECT_URL = "https://abcdefghijklmnopqrst.supabase.co"
SERVICE_KEY = "sb_secret_test_service_role_key_value_123456"


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text(
        f"SUPABASE_PROJECT_URL={PROJECT_URL}\n"
        f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_KEY}\n"
        "PENTEST_USER_A_ID=uid-a\n"
        "PENTEST_USER_B_ID=uid-b\n",
        encoding="utf-8",
    )
    for key in (
        "SUPABASE_PROJECT_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ACCESS_TOKEN",
        "PENTEST_USER_A_ID", "PENTEST_USER_B_ID",
    ):
        monkeypatch.delenv(key, raising=False)
    return path


def _run_teardown(env_file: Path, handler) -> int:
    # teardown.main delegates to provision_accounts.main; inject the mocked
    # client through the same seam the provisioning tests use.
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return pa.main(["--cleanup", "--env-file", str(env_file)], http=client)


def test_teardown_main_injects_cleanup_flag(monkeypatch):
    captured = {}

    def _fake_main(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return 0

    monkeypatch.setattr(pa, "main", _fake_main)
    rc = teardown.main(["--project-url", PROJECT_URL])
    assert rc == 0
    assert captured["argv"][0] == "--cleanup"
    assert "--project-url" in captured["argv"]
    # teardown reframes the shared parser's --help via prog/description.
    assert captured["kwargs"].get("prog") == "teardown.py"


def test_teardown_help_shows_teardown_identity(capsys):
    # End-to-end through the real ArgumentParser: teardown's prog/description
    # must reach --help, not just the delegation seam. A dropped/misspelled
    # description kwarg would surface here.
    with pytest.raises(SystemExit) as exc:
        teardown.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "teardown.py" in out  # prog
    assert "Delete the two StackBadger" in out  # description


def test_teardown_does_not_duplicate_cleanup_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(pa, "main", lambda argv, **kwargs: captured.setdefault("argv", argv) and 0 or 0)
    teardown.main(["--cleanup"])
    assert captured["argv"].count("--cleanup") == 1


def test_teardown_deletes_both_accounts_by_id(env_file, capsys):
    deleted: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        deleted.append(request.url.path.rsplit("/", 1)[1])
        return httpx.Response(200, json={})

    rc = _run_teardown(env_file, _handler)
    assert rc == 0
    assert sorted(deleted) == ["uid-a", "uid-b"]
    values = pa.parse_env_file(env_file)
    assert "PENTEST_USER_A_ID" not in values
    assert "PENTEST_USER_B_ID" not in values
    out = capsys.readouterr()
    assert SERVICE_KEY not in out.out + out.err


def test_teardown_treats_404_as_already_gone(env_file):
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"msg": "user not found"})

    assert _run_teardown(env_file, _handler) == 0
    values = pa.parse_env_file(env_file)
    assert "PENTEST_USER_A_ID" not in values


def test_teardown_failure_is_nonzero_and_names_remaining(env_file, capsys):
    def _handler(request: httpx.Request) -> httpx.Response:
        uid = request.url.path.rsplit("/", 1)[1]
        if uid == "uid-b":
            return httpx.Response(500, json={"msg": "boom"})
        return httpx.Response(200, json={})

    rc = _run_teardown(env_file, _handler)
    assert rc == 1
    err = capsys.readouterr().err
    assert "uid-b" in err
    # The deleted account's ID is cleared; the failed one is retained for retry.
    values = pa.parse_env_file(env_file)
    assert "PENTEST_USER_A_ID" not in values
    assert values["PENTEST_USER_B_ID"] == "uid-b"


def test_second_teardown_is_a_noop(env_file, capsys):
    def _ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    assert _run_teardown(env_file, _ok) == 0
    deletes = {"n": 0}

    def _second(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            deletes["n"] += 1
            return httpx.Response(200, json={})
        # Default-email sweep lookups are allowed; nothing is found.
        return httpx.Response(200, json={"users": []})

    assert _run_teardown(env_file, _second) == 0
    assert deletes["n"] == 0  # nothing left to delete
    assert "nothing to tear down" in capsys.readouterr().out
