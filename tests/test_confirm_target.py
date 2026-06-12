"""Shell-level tests for the CONFIRM_TARGET gate in run.sh (U2).

Every remote run — read-only included — must refuse unless CONFIRM_TARGET
exact-matches the resolved target host. ``--yes`` does not bypass; localhost
is exempt; no subdomain cross-match.

Strategy: run.sh in a sandbox copy (see shell_harness). A *refused* run exits
10 with the distinctive "CONFIRM_TARGET gate refused" message before any
remote contact. A run that *passes* the gates proceeds to the next stage
(stub doctor, then discovery against an unresolvable ``.invalid`` host) and
fails THERE — proving the gate let it through without real network traffic.
"""

from __future__ import annotations

import pytest

from tests.shell_harness import make_sandbox, requires_bash, run_sh, stub_doctor

pytestmark = requires_bash

REMOTE = "https://stub.invalid"
HOST = "stub.invalid"

# Both gates share the matcher; CONFIRM_AUTHORIZED is held correct here so
# these tests isolate CONFIRM_TARGET (see test_authorization_gate.py for the
# other gate).
_AUTHORIZED = {"CONFIRM_AUTHORIZED": HOST}


@pytest.fixture()
def sandbox(tmp_path):
    return make_sandbox(tmp_path)


def test_remote_run_with_confirm_target_unset_refuses(sandbox):
    result = run_sh(sandbox, [REMOTE], env_overrides=_AUTHORIZED)
    assert result.returncode == 10
    assert "CONFIRM_TARGET gate refused" in result.stderr
    # Message must show the exact value to set.
    assert f"CONFIRM_TARGET={HOST}" in result.stderr


def test_full_yes_does_not_bypass_mismatched_confirm_target(sandbox):
    result = run_sh(
        sandbox,
        [REMOTE, "--full", "--yes"],
        env_overrides={"CONFIRM_TARGET": "other.invalid", **_AUTHORIZED},
    )
    assert result.returncode == 10
    assert "CONFIRM_TARGET gate refused" in result.stderr


def test_no_subdomain_cross_match(sandbox):
    result = run_sh(
        sandbox,
        ["https://api.stub.invalid"],
        env_overrides={"CONFIRM_TARGET": HOST, "CONFIRM_AUTHORIZED": "api.stub.invalid"},
    )
    assert result.returncode == 10
    assert "CONFIRM_TARGET gate refused" in result.stderr
    assert "api.stub.invalid" in result.stderr


def test_gate_uses_cli_host_not_a_different_confirm_value(sandbox):
    # The contract is the CLI host: confirming a DIFFERENT host (e.g. the www
    # form of an apex you passed) is refused, and the refusal names the CLI host
    # the operator must confirm. This pins the "CLI host, not post-redirect host"
    # contract so the documented guidance and the code cannot drift apart.
    result = run_sh(
        sandbox,
        ["https://stub.invalid"],
        env_overrides={"CONFIRM_TARGET": "www.stub.invalid", "CONFIRM_AUTHORIZED": "www.stub.invalid"},
    )
    assert result.returncode == 10
    assert "CONFIRM_TARGET gate refused" in result.stderr
    assert f"export CONFIRM_TARGET={HOST}" in result.stderr  # names the CLI host


def test_scheme_case_port_insensitive_match_proceeds(sandbox):
    stub_doctor(sandbox, 0)
    result = run_sh(
        sandbox,
        ["HTTPS://Stub.INVALID:443"],
        env_overrides={"CONFIRM_TARGET": HOST, **_AUTHORIZED},
    )
    combined = result.stdout + result.stderr
    assert "gate refused" not in combined
    # Proves the run got past the gates: it reached discovery and failed
    # there (stub.invalid never resolves), not at the gate.
    assert "Discovery / profile assembly failed" in combined
    assert result.returncode == 1


def test_matching_confirm_target_proceeds_in_read_only(sandbox):
    stub_doctor(sandbox, 0)
    result = run_sh(sandbox, [REMOTE], env_overrides={"CONFIRM_TARGET": HOST, **_AUTHORIZED})
    combined = result.stdout + result.stderr
    assert "gate refused" not in combined
    assert "Target + authorization gates passed" in combined
    assert "Discovery / profile assembly failed" in combined


def test_localhost_is_exempt(sandbox):
    stub_doctor(sandbox, 0)
    # No CONFIRM_* vars at all — localhost must not require them.
    result = run_sh(sandbox, ["http://localhost:9"])
    combined = result.stdout + result.stderr
    assert "gate refused" not in combined
    # Proceeds to discovery, which fails on the closed port — not the gate.
    assert "Discovery / profile assembly failed" in combined


def test_ipv6_loopback_is_exempt(sandbox):
    stub_doctor(sandbox, 0)
    result = run_sh(sandbox, ["http://[::1]:9"])
    combined = result.stdout + result.stderr
    assert "gate refused" not in combined
    assert "Discovery / profile assembly failed" in combined


def test_routable_ipv6_is_gated_and_matchable(sandbox):
    # A non-loopback IPv6 literal must be gated; the bracket-preserving
    # normalizer must let CONFIRM_TARGET=[2001:db8::1] match it (port stripped).
    stub_doctor(sandbox, 0)
    refused = run_sh(sandbox, ["http://[2001:db8::1]:8443"])
    assert refused.returncode == 10
    assert "CONFIRM_TARGET gate refused" in refused.stderr
    assert "[2001:db8::1]" in refused.stderr

    proceeded = run_sh(
        sandbox,
        ["http://[2001:db8::1]:8443"],
        env_overrides={
            "CONFIRM_TARGET": "[2001:db8::1]",
            "CONFIRM_AUTHORIZED": "[2001:db8::1]",
        },
    )
    combined = proceeded.stdout + proceeded.stderr
    assert "gate refused" not in combined
    assert "Target + authorization gates passed" in combined


def test_fragment_does_not_confuse_gate_host(sandbox):
    # 'https://stub.invalid#@evil.invalid' — an HTTP client connects to
    # stub.invalid (fragment dropped). The gate must normalize to the same
    # host, NOT evil.invalid. So CONFIRM_TARGET=stub.invalid proceeds...
    stub_doctor(sandbox, 0)
    ok = run_sh(
        sandbox,
        ["https://stub.invalid#@evil.invalid"],
        env_overrides={"CONFIRM_TARGET": HOST, "CONFIRM_AUTHORIZED": HOST},
    )
    assert "gate refused" not in (ok.stdout + ok.stderr)
    # ...and confirming the attacker-supplied fragment host is REFUSED.
    bad = run_sh(
        sandbox,
        ["https://stub.invalid#@evil.invalid"],
        env_overrides={"CONFIRM_TARGET": "evil.invalid", "CONFIRM_AUTHORIZED": "evil.invalid"},
    )
    assert bad.returncode == 10
    assert "CONFIRM_TARGET gate refused" in bad.stderr


def test_gate_runs_before_branch_lifecycle(sandbox):
    # A refused --branch run must not attempt branch creation (remote side
    # effect). The refusal message appears and no branch step is reached.
    result = run_sh(
        sandbox,
        [REMOTE, "--branch", "--yes"],
        env_overrides={**_AUTHORIZED, "SUPABASE_ACCESS_TOKEN": "sbp_dummy"},
    )
    assert result.returncode == 10
    assert "CONFIRM_TARGET gate refused" in result.stderr
    assert "Creating disposable Supabase branch" not in result.stdout
