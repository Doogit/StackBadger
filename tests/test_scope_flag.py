"""Shell-level tests for the --scope axis in run.sh (Tier-2).

The scope axis is orthogonal to the read-only/write safety axis: ``core``
(default) runs today's targeted suite; ``asvs`` runs the heavy pre-audit
gap-finder and emits the coverage ledger. run.sh resolves it flag-first,
exports ``SCAN_SCOPE`` to the pytest subprocess, and prompts interactively only
when stdin is a TTY (never in CI / piped invocations).

Strategy mirrors the gate tests: an INVALID scope fails during arg validation
(exit 1) before any gate/network. A VALID scope is proven by driving the run
past both authorization gates (with a stub doctor) to the mode-selection block,
whose ``Scan scope:`` line reports the resolved value before discovery fails
against the unresolvable ``.invalid`` host.
"""

from __future__ import annotations

import pytest

from tests.shell_harness import make_sandbox, requires_bash, run_sh, stub_doctor

pytestmark = requires_bash

REMOTE = "https://stub.invalid"
HOST = "stub.invalid"

# Both gates held correct so these tests isolate the scope axis; see
# test_confirm_target.py / test_authorization_gate.py for the gates themselves.
_GATES_OK = {"CONFIRM_TARGET": HOST, "CONFIRM_AUTHORIZED": HOST}


@pytest.fixture()
def sandbox(tmp_path):
    return make_sandbox(tmp_path)


def test_invalid_scope_rejected_before_gates(sandbox):
    # Bad value fails during arg validation — before the CONFIRM_* gates, so no
    # gate env is needed and no network is touched.
    result = run_sh(sandbox, [REMOTE, "--scope", "bogus"])
    assert result.returncode == 1
    assert "Invalid --scope 'bogus'" in result.stderr
    combined = result.stdout + result.stderr
    assert "gate refused" not in combined


def test_scope_requires_a_value(sandbox):
    result = run_sh(sandbox, [REMOTE, "--scope"])
    assert result.returncode == 1
    assert "--scope requires a value" in result.stderr


def test_default_scope_is_core(sandbox):
    # No --scope, non-TTY stdin (subprocess) → no prompt, defaults to core.
    stub_doctor(sandbox, 0)
    result = run_sh(sandbox, [REMOTE], env_overrides=_GATES_OK)
    combined = result.stdout + result.stderr
    assert "Scan scope: core" in combined
    # Reached mode selection then failed at discovery (unresolvable host).
    assert "Discovery / profile assembly failed" in combined


def test_scope_asvs_is_wired_through(sandbox):
    stub_doctor(sandbox, 0)
    result = run_sh(sandbox, [REMOTE, "--scope", "asvs"], env_overrides=_GATES_OK)
    combined = result.stdout + result.stderr
    assert "Scan scope: asvs" in combined
    assert "Discovery / profile assembly failed" in combined


def test_scope_composes_with_read_only_default(sandbox):
    # Scope axis is independent of the safety axis: --scope asvs without --full
    # stays read-only.
    stub_doctor(sandbox, 0)
    result = run_sh(sandbox, [REMOTE, "--scope", "asvs"], env_overrides=_GATES_OK)
    combined = result.stdout + result.stderr
    assert "Scan scope: asvs" in combined
    assert "read-only mode" in combined
