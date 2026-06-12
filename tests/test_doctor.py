"""Tests for doctor.py (U1) — preflight checks + run.sh delegation.

Unit tests drive doctor's check functions directly (no network); the
integration tests at the bottom verify run.sh aborts/proceeds on doctor's
exit code via the shell sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

import doctor
from tests.shell_harness import make_sandbox, requires_bash, run_sh, stub_doctor

TARGET = "https://stub.invalid"

ALL_CREDS = {
    "PENTEST_USER_A_EMAIL": "a@example.com",
    "PENTEST_USER_A_PASSWORD": "pw-a",
    "PENTEST_USER_B_EMAIL": "b@example.com",
    "PENTEST_USER_B_PASSWORD": "pw-b",
}


def _write_env_example(tmp_path: Path) -> Path:
    example = tmp_path / ".env.example"
    example.write_text(
        "# required\n"
        "PENTEST_USER_A_EMAIL=\n"
        "PENTEST_USER_A_PASSWORD=\n"
        "PENTEST_USER_B_EMAIL=\n"
        "PENTEST_USER_B_PASSWORD=\n"
        "# --- Optional ---\n"
        "# SUPABASE_ACCESS_TOKEN=\n",
        encoding="utf-8",
    )
    return example


class _FakeAdapter:
    """Adapter double: per-account header behaviour, tracks close()."""

    def __init__(self, ok_accounts=("user_a", "user_b")):
        self.ok_accounts = ok_accounts
        self.closed = False

    def get_headers(self, account):
        if account in self.ok_accounts:
            return {"Authorization": "Bearer fake"}
        raise RuntimeError(f"401 for {account}")

    def close(self):
        self.closed = True


# ---------------------------------------------------------------------------
# Unit: individual checks
# ---------------------------------------------------------------------------

def test_python_version_check_passes_here():
    result = doctor.check_python_version()
    assert result.passed  # the suite itself requires >= 3.11


def test_env_complete_names_the_missing_key(tmp_path):
    example = _write_env_example(tmp_path)
    env = dict(ALL_CREDS)
    del env["PENTEST_USER_B_PASSWORD"]
    result = doctor.check_env_complete(env, example)
    assert not result.passed
    assert "PENTEST_USER_B_PASSWORD" in result.detail
    assert result.exit_code == doctor.EXIT_ENV_INCOMPLETE


def test_env_complete_passes_with_all_keys(tmp_path):
    example = _write_env_example(tmp_path)
    result = doctor.check_env_complete(dict(ALL_CREDS), example)
    assert result.passed


def test_required_keys_fall_back_when_example_missing(tmp_path):
    keys = doctor.required_env_keys(tmp_path / "nope.example")
    assert set(keys) == set(ALL_CREDS)


def test_default_env_paths_resolve_to_script_dir_not_cwd():
    # Standalone use (`python path/to/doctor.py` from any cwd) must look for
    # .env / .env.example next to the script, not in the caller's cwd.
    assert doctor._DEFAULT_ENV_FILE == doctor._SCRIPT_DIR / ".env"
    assert doctor._DEFAULT_ENV_EXAMPLE == doctor._SCRIPT_DIR / ".env.example"
    assert doctor._DEFAULT_ENV_FILE.is_absolute()


def test_main_uses_script_dir_env_defaults_from_foreign_cwd(tmp_path, monkeypatch):
    # Invoke main() from an unrelated cwd with no args overriding env paths;
    # the env_file/env_example handed to run_doctor must be the script-dir
    # defaults (absolute), not tmp_path/.env.
    monkeypatch.chdir(tmp_path)
    captured = {}

    def _capture(target_url, profile, *, env_file, env_example):
        captured["env_file"] = env_file
        captured["env_example"] = env_example
        return doctor.EXIT_OK, []

    monkeypatch.setattr(doctor, "run_doctor", _capture)
    doctor.main([TARGET])
    assert captured["env_file"] == doctor._DEFAULT_ENV_FILE
    assert captured["env_example"] == doctor._DEFAULT_ENV_EXAMPLE
    assert Path(captured["env_file"]).is_absolute()


def test_load_dotenv_does_not_override_existing_env(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "PENTEST_USER_A_EMAIL=file@example.com\nPENTEST_USER_A_PASSWORD=file-pw\n",
        encoding="utf-8",
    )
    env = {"PENTEST_USER_A_EMAIL": "shell@example.com"}
    doctor.load_dotenv(env_file, env)
    assert env["PENTEST_USER_A_EMAIL"] == "shell@example.com"  # caller wins
    assert env["PENTEST_USER_A_PASSWORD"] == "file-pw"         # gap filled


def test_load_dotenv_overwrites_present_but_empty_value(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("PENTEST_USER_A_EMAIL=file@example.com\n", encoding="utf-8")
    env = {"PENTEST_USER_A_EMAIL": ""}  # present but empty — must be filled
    doctor.load_dotenv(env_file, env)
    assert env["PENTEST_USER_A_EMAIL"] == "file@example.com"


def test_target_unreachable_fails_with_fix(monkeypatch):
    def _boom(*args, **kwargs):
        raise httpx.ConnectError("dns failure")

    monkeypatch.setattr(httpx, "get", _boom)
    result = doctor.check_target_reachable(TARGET)
    assert not result.passed
    assert result.exit_code == doctor.EXIT_TARGET_UNREACHABLE
    assert result.fix


def test_target_reachable_passes_on_any_http_response(monkeypatch):
    monkeypatch.setattr(
        httpx, "get", lambda *a, **k: httpx.Response(403, request=httpx.Request("GET", TARGET))
    )
    result = doctor.check_target_reachable(TARGET)
    assert result.passed


def test_user_b_failure_names_user_b(monkeypatch):
    adapter = _FakeAdapter(ok_accounts=("user_a",))
    monkeypatch.setattr(doctor, "_build_adapter", lambda url, prof: (adapter, "clerk", None))
    results = doctor.check_logins(TARGET, None)
    assert [r.name for r in results] == ["user-a-login", "user-b-login"]
    assert results[0].passed
    assert not results[1].passed
    assert "User B" in results[1].detail
    assert results[1].exit_code == doctor.EXIT_USER_B_LOGIN
    assert adapter.closed


def test_wrong_adapter_failure_points_at_stack_auth(monkeypatch):
    from auth.base import AuthConfigError

    def _raise(url, prof):
        raise AuthConfigError("Clerk FAPI host not available")

    monkeypatch.setattr(doctor, "_build_adapter", _raise)
    results = doctor.check_logins(TARGET, None)
    assert len(results) == 1
    assert not results[0].passed
    assert results[0].exit_code == doctor.EXIT_USER_A_LOGIN
    assert "stack.auth" in results[0].fix
    assert "Step 0" in results[0].fix


# ---------------------------------------------------------------------------
# Unit: runner ordering / halting
# ---------------------------------------------------------------------------

def test_halts_at_env_check_before_any_network(tmp_path, monkeypatch):
    def _no_network(*args, **kwargs):
        raise AssertionError("network check ran after env FAIL")

    monkeypatch.setattr(doctor, "check_target_reachable", _no_network)
    exit_code, results = doctor.run_doctor(
        TARGET,
        env_file=tmp_path / "absent.env",
        env_example=_write_env_example(tmp_path),
        environ={},
    )
    assert exit_code == doctor.EXIT_ENV_INCOMPLETE
    assert [r.name for r in results] == ["python-version", "env-complete"]


def test_unreachable_target_skips_login_checks(tmp_path, monkeypatch):
    monkeypatch.setattr(
        doctor,
        "check_target_reachable",
        lambda url: doctor.CheckResult(
            "target-reachable", False, "down", fix="check URL",
            exit_code=doctor.EXIT_TARGET_UNREACHABLE,
        ),
    )
    monkeypatch.setattr(
        doctor, "check_logins",
        lambda *a: (_ for _ in ()).throw(AssertionError("login ran after reachability FAIL")),
    )
    exit_code, results = doctor.run_doctor(
        TARGET,
        env_file=tmp_path / "absent.env",
        env_example=_write_env_example(tmp_path),
        environ=dict(ALL_CREDS),
    )
    assert exit_code == doctor.EXIT_TARGET_UNREACHABLE
    assert results[-1].name == "target-reachable"


def test_happy_path_all_pass_exit_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(
        doctor, "check_target_reachable",
        lambda url: doctor.CheckResult("target-reachable", True, "HTTP 200"),
    )
    monkeypatch.setattr(
        doctor, "_build_adapter", lambda url, prof: (_FakeAdapter(), "supabase-auth", None)
    )
    exit_code, results = doctor.run_doctor(
        TARGET,
        env_file=tmp_path / "absent.env",
        env_example=_write_env_example(tmp_path),
        environ=dict(ALL_CREDS),
    )
    assert exit_code == doctor.EXIT_OK
    assert [r.name for r in results] == [
        "python-version", "env-complete", "target-reachable",
        "user-a-login", "user-b-login",
    ]
    assert all(r.passed for r in results)


def test_exit_codes_stay_in_10_19_range():
    codes = {
        doctor.EXIT_PYTHON_VERSION, doctor.EXIT_ENV_INCOMPLETE,
        doctor.EXIT_TARGET_UNREACHABLE, doctor.EXIT_USER_A_LOGIN,
        doctor.EXIT_USER_B_LOGIN, doctor.EXIT_INTERNAL_ERROR,
    }
    assert all(10 <= c <= 19 for c in codes)
    assert len(codes) == 6  # all distinct


# ---------------------------------------------------------------------------
# Unit: CLI / output format
# ---------------------------------------------------------------------------

def test_json_output_is_machine_readable(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        doctor, "run_doctor",
        lambda *a, **k: (
            doctor.EXIT_USER_B_LOGIN,
            [
                doctor.CheckResult("python-version", True, "Python 3.12"),
                doctor.CheckResult(
                    "user-b-login", False, "401", fix="check creds",
                    exit_code=doctor.EXIT_USER_B_LOGIN,
                ),
            ],
        ),
    )
    rc = doctor.main([TARGET, "--json"])
    assert rc == doctor.EXIT_USER_B_LOGIN
    out = capsys.readouterr()
    payload = json.loads(out.out)  # stdout is pure JSON in --json mode
    assert payload["passed"] is False
    assert payload["exit_code"] == doctor.EXIT_USER_B_LOGIN
    assert payload["checks"][1]["name"] == "user-b-login"
    # Human [PASS]/[FAIL] lines moved to stderr.
    assert "[FAIL] user-b-login" in out.err


def test_internal_error_emits_json_in_json_mode(monkeypatch, capsys):
    def _boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(doctor, "run_doctor", _boom)
    rc = doctor.main([TARGET, "--json"])
    assert rc == doctor.EXIT_INTERNAL_ERROR
    out = capsys.readouterr()
    payload = json.loads(out.out)  # stdout must still be valid JSON
    assert payload["passed"] is False
    assert payload["exit_code"] == doctor.EXIT_INTERNAL_ERROR
    assert "kaboom" in payload["error"]


def test_internal_error_human_mode_emits_no_json(monkeypatch, capsys):
    def _boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(doctor, "run_doctor", _boom)
    rc = doctor.main([TARGET])  # no --json
    assert rc == doctor.EXIT_INTERNAL_ERROR
    out = capsys.readouterr()
    assert out.out == ""  # nothing on stdout in human mode
    assert "doctor-internal" in out.err
    assert "kaboom" in out.err


def test_human_output_pass_fail_lines(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        doctor, "run_doctor",
        lambda *a, **k: (
            doctor.EXIT_ENV_INCOMPLETE,
            [
                doctor.CheckResult("python-version", True, "Python 3.12"),
                doctor.CheckResult(
                    "env-complete", False, "missing PENTEST_USER_B_EMAIL",
                    fix="set it in .env", exit_code=doctor.EXIT_ENV_INCOMPLETE,
                ),
            ],
        ),
    )
    rc = doctor.main([TARGET])
    assert rc == doctor.EXIT_ENV_INCOMPLETE
    out = capsys.readouterr().out
    assert "[PASS] python-version" in out
    assert "[FAIL] env-complete — missing PENTEST_USER_B_EMAIL. Fix: set it in .env" in out


# ---------------------------------------------------------------------------
# Integration: run.sh delegation (sandboxed shell)
# ---------------------------------------------------------------------------

GATES = {"CONFIRM_TARGET": "stub.invalid", "CONFIRM_AUTHORIZED": "stub.invalid"}


@requires_bash
def test_run_sh_aborts_with_preflight_exit_when_doctor_fails(tmp_path):
    sandbox = make_sandbox(tmp_path)
    stub_doctor(sandbox, doctor.EXIT_USER_A_LOGIN)
    result = run_sh(sandbox, [TARGET], env_overrides=GATES)
    # Fixed preflight exit — never aggregate's 0/1/2/3.
    assert result.returncode == 10
    assert "Preflight failed" in result.stderr
    assert "Discovering public config" not in result.stdout


@requires_bash
def test_run_sh_proceeds_when_doctor_passes(tmp_path):
    sandbox = make_sandbox(tmp_path)
    stub_doctor(sandbox, 0)
    result = run_sh(sandbox, [TARGET], env_overrides=GATES)
    combined = result.stdout + result.stderr
    assert "Preflight passed" in combined
    # Proceeds to discovery (which then fails on the unresolvable host).
    assert "Discovery / profile assembly failed" in combined


@requires_bash
def test_run_sh_real_doctor_fails_env_check_without_creds(tmp_path):
    # Real doctor.py (no stub): with no PENTEST_* creds it must fail the
    # env-complete check (before any network) and run.sh must abort with the
    # preflight exit, proving the inline creds-check replacement still gates.
    sandbox = make_sandbox(tmp_path)
    result = run_sh(sandbox, ["http://localhost:9"])
    assert result.returncode == 10
    combined = result.stdout + result.stderr
    assert "[FAIL] env-complete" in combined
    assert "Preflight failed" in combined


@requires_bash
def test_run_sh_signs_in_user_b(tmp_path):
    # The sign-in stage must exercise user_b. We can't reach it without real
    # accounts, so assert the contract structurally: run.sh contains the
    # user_b verification step after the user_a sign-in.
    script = (make_sandbox(tmp_path) / "run.sh").read_text(encoding="utf-8")
    a_signin = script.index("adapter.get_token('user_a')")
    b_verify = script.index("adapter.get_headers('user_b')")
    assert b_verify > a_signin
    assert "user_b sign-in failed" in script
