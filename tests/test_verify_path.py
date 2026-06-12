"""Tests for auth.verify_path (U7) — validation, carry-through, fast-fail.

Covers: load_profile validation, profile_assembler null-default carry (no
inference), doctor's per-account verify_path check, and the structural
contract that run.sh runs the verify step after both sign-ins.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import httpx
import pytest

import doctor
from profile import load_profile
from profile_assembler import assemble_profile
from tests.shell_harness import _REPO_ROOT

TARGET = "https://stub.invalid"


def _write_profile(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "profile.yaml"
    path.write_text(
        'target:\n  base_url: "https://example.com"\n' + extra,
        encoding="utf-8",
    )
    return path


def _empty_discovery() -> dict:
    return {
        "supabase_url": None,
        "supabase_anon_key": None,
        "clerk_publishable_key": None,
        "clerk_fapi_host": None,
        "api_prefix": None,
        "providers": None,
    }


# ---------------------------------------------------------------------------
# load_profile validation
# ---------------------------------------------------------------------------

def test_load_profile_accepts_valid_verify_path(tmp_path):
    profile = load_profile(_write_profile(tmp_path, "auth:\n  verify_path: /api/me\n"))
    assert profile.auth.verify_path == "/api/me"


def test_load_profile_accepts_absent_auth_block(tmp_path):
    profile = load_profile(_write_profile(tmp_path))
    assert profile.auth is None


def test_load_profile_accepts_null_verify_path(tmp_path):
    # The frozen runtime profile carries an explicit null default.
    profile = load_profile(_write_profile(tmp_path, "auth:\n  verify_path: null\n"))
    assert profile.auth.verify_path is None


def test_load_profile_rejects_non_string_verify_path(tmp_path):
    with pytest.raises(ValueError, match="auth.verify_path"):
        load_profile(_write_profile(tmp_path, "auth:\n  verify_path: [a, b]\n"))


def test_load_profile_rejects_relative_verify_path(tmp_path):
    with pytest.raises(ValueError, match="starting with '/'"):
        load_profile(_write_profile(tmp_path, "auth:\n  verify_path: api/me\n"))


def test_load_profile_rejects_non_mapping_auth_block(tmp_path):
    with pytest.raises(ValueError, match="'auth' must be a mapping"):
        load_profile(_write_profile(tmp_path, "auth: verify-me\n"))


# ---------------------------------------------------------------------------
# profile_assembler carry-through (null default, no inference)
# ---------------------------------------------------------------------------

@mock.patch("profile_assembler.discover_live")
def test_assembler_defaults_verify_path_to_null(mock_discover, monkeypatch):
    for var in ("TARGET_BASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_PROJECT_URL", "CLERK_FAPI_HOST"):
        monkeypatch.delenv(var, raising=False)
    mock_discover.return_value = _empty_discovery()
    profile = assemble_profile(TARGET)
    assert profile.raw()["auth"] == {"verify_path": None}  # present, null, not guessed


@mock.patch("profile_assembler.discover_live")
def test_assembler_carries_yaml_verify_path(mock_discover, monkeypatch, tmp_path):
    for var in ("TARGET_BASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_PROJECT_URL", "CLERK_FAPI_HOST"):
        monkeypatch.delenv(var, raising=False)
    mock_discover.return_value = _empty_discovery()
    yaml_path = _write_profile(tmp_path, "auth:\n  verify_path: /api/me\n")
    profile = assemble_profile(TARGET, yaml_path=str(yaml_path))
    assert profile.auth.verify_path == "/api/me"


# ---------------------------------------------------------------------------
# doctor: per-account verify_path check
# ---------------------------------------------------------------------------

class _FakeAdapter:
    def __init__(self):
        self.closed = False

    def get_headers(self, account):
        return {"Authorization": f"Bearer fake-{account}"}

    def close(self):
        self.closed = True


def _patch_doctor(monkeypatch, verify_path, responder):
    monkeypatch.setattr(
        doctor, "_build_adapter",
        lambda url, prof: (_FakeAdapter(), "supabase-auth", verify_path),
    )
    monkeypatch.setattr(httpx, "get", responder)


def test_doctor_verify_path_2xx_passes(monkeypatch):
    _patch_doctor(
        monkeypatch, "/api/me",
        lambda url, **kw: httpx.Response(200, request=httpx.Request("GET", url)),
    )
    results = doctor.check_logins(TARGET, None)
    assert [r.passed for r in results] == [True, True]
    assert "/api/me" in results[0].detail


def test_doctor_verify_path_403_fails_user_b_distinguishes_adapter(monkeypatch):
    calls = {"n": 0}

    def _responder(url, **kw):
        calls["n"] += 1
        status = 200 if calls["n"] == 1 else 403  # A passes, B rejected
        return httpx.Response(status, request=httpx.Request("GET", url))

    _patch_doctor(monkeypatch, "/api/me", _responder)
    results = doctor.check_logins(TARGET, None)
    assert results[0].passed
    assert not results[1].passed
    assert results[1].exit_code == doctor.EXIT_USER_B_LOGIN
    assert "User B" in results[1].detail
    assert "wrong adapter" in results[1].fix


def test_doctor_verify_path_unset_skips_the_extra_request(monkeypatch):
    def _no_network(*a, **kw):
        raise AssertionError("verify_path request fired despite being unset")

    _patch_doctor(monkeypatch, None, _no_network)
    results = doctor.check_logins(TARGET, None)
    assert all(r.passed for r in results)


def test_doctor_verify_path_other_status_is_inconclusive_pass(monkeypatch):
    _patch_doctor(
        monkeypatch, "/api/me",
        lambda url, **kw: httpx.Response(404, request=httpx.Request("GET", url)),
    )
    results = doctor.check_logins(TARGET, None)
    assert all(r.passed for r in results)
    assert "inconclusive" in results[0].detail


def test_doctor_verify_path_401_fails_like_403(monkeypatch):
    _patch_doctor(
        monkeypatch, "/api/me",
        lambda url, **kw: httpx.Response(401, request=httpx.Request("GET", url)),
    )
    results = doctor.check_logins(TARGET, None)
    assert not results[0].passed
    assert results[0].exit_code == doctor.EXIT_USER_A_LOGIN


def test_doctor_verify_path_network_error_fails(monkeypatch):
    def _boom(url, **kw):
        raise httpx.ConnectError("refused")

    _patch_doctor(monkeypatch, "/api/me", _boom)
    results = doctor.check_logins(TARGET, None)
    assert not results[0].passed
    assert "request failed" in results[0].detail


def test_verify_path_resolves_against_origin_for_subpath_deployments(monkeypatch):
    # verify_path is ROOT-relative: a base URL carrying a path prefix
    # (https://example.com/app) must NOT leak into the probe URL — naive
    # concatenation would request /app/api/me and fail the preflight falsely.
    captured = {}

    def _get(url, **kw):
        captured["url"] = url
        return httpx.Response(200, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", _get)
    ok, detail, _ = doctor._check_verify_path(
        "https://example.com/app", "/api/me", {"Authorization": "Bearer x"}, "User A"
    )
    assert ok
    assert captured["url"] == "https://example.com/api/me"


def test_verify_path_join_without_prefix_unchanged(monkeypatch):
    captured = {}

    def _get(url, **kw):
        captured["url"] = url
        return httpx.Response(200, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", _get)
    ok, _, _ = doctor._check_verify_path("https://example.com/", "/api/me", {}, "User A")
    assert ok
    assert captured["url"] == "https://example.com/api/me"


def test_doctor_verify_path_does_not_follow_redirects(monkeypatch):
    # A 302 -> login -> 200 chain must NOT read as a pass: redirects are not
    # followed and 3xx is inconclusive (with an explanatory detail), never OK.
    captured = {}

    def _responder(url, **kw):
        captured.update(kw)
        return httpx.Response(
            302, headers={"location": "/login"}, request=httpx.Request("GET", url)
        )

    _patch_doctor(monkeypatch, "/api/me", _responder)
    results = doctor.check_logins(TARGET, None)
    assert captured.get("follow_redirects") is False
    assert all(r.passed for r in results)  # inconclusive warn, not a fail
    assert "redirect" in results[0].detail


# ---------------------------------------------------------------------------
# run.sh: structural contract (sign-ins happen before the verify step,
# and a verify failure routes through the preflight exit)
# ---------------------------------------------------------------------------

def test_run_sh_verify_step_after_both_sign_ins():
    script = (_REPO_ROOT / "run.sh").read_text(encoding="utf-8")
    a_signin = script.index("adapter.get_token('user_a')")
    b_verify = script.index("adapter.get_headers('user_b')")
    vp_step = script.index("auth.verify_path check failed")
    assert a_signin < b_verify < vp_step
    assert "fail_preflight \"auth.verify_path check failed" in script
    # Unset must warn + skip, not fail.
    assert "auth.verify_path not set" in script
