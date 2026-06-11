"""Shell-level tests for the CONFIRM_AUTHORIZED gate in run.sh (U9).

CONFIRM_AUTHORIZED is the human-set "I am authorized to test this host"
control. It uses the same exact-host matcher as CONFIRM_TARGET but answers a
different question — both must pass before any discovery/scan.
"""

from __future__ import annotations

import pytest

from tests.shell_harness import make_sandbox, requires_bash, run_sh, stub_doctor

pytestmark = requires_bash

REMOTE = "https://stub.invalid"
HOST = "stub.invalid"


@pytest.fixture()
def sandbox(tmp_path):
    return make_sandbox(tmp_path)


def test_unset_confirm_authorized_refuses_before_discovery(sandbox):
    result = run_sh(sandbox, [REMOTE], env_overrides={"CONFIRM_TARGET": HOST})
    assert result.returncode == 10
    assert "CONFIRM_AUTHORIZED gate refused" in result.stderr
    assert f"CONFIRM_AUTHORIZED={HOST}" in result.stderr
    # Refused before discovery (and before preflight).
    combined = result.stdout + result.stderr
    assert "Discovering public config" not in combined
    assert "Running preflight checks" not in combined


def test_mismatched_confirm_authorized_refuses(sandbox):
    result = run_sh(
        sandbox,
        [REMOTE],
        env_overrides={"CONFIRM_TARGET": HOST, "CONFIRM_AUTHORIZED": "other.invalid"},
    )
    assert result.returncode == 10
    assert "CONFIRM_AUTHORIZED gate refused" in result.stderr


def test_matching_confirm_authorized_proceeds(sandbox):
    stub_doctor(sandbox, 0)
    result = run_sh(
        sandbox,
        [REMOTE],
        env_overrides={"CONFIRM_TARGET": HOST, "CONFIRM_AUTHORIZED": HOST},
    )
    combined = result.stdout + result.stderr
    assert "gate refused" not in combined
    assert "Target + authorization gates passed" in combined
    # Got past both gates; fails later at discovery (unresolvable host).
    assert "Discovery / profile assembly failed" in combined
