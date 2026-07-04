"""End-to-end regression for the dual-mapped ASVS/CWE coverage ledger.

This is a META-test on the ledger *tooling*, not a security probe: it emits no
findings and carries no ASVS/CWE tags (so it never appears in the ledger it
verifies). It pins that the full five-view ledger still emits together, so a
refactor of the sidecar wiring or of any downstream view can't silently drop one.

Real path exercised (offline, deterministic):
  1. subprocess pytest (``sys.executable`` so it works in CI too) on ONE small
     tagged module under ``SCAN_SCOPE=asvs`` against the shipped example profile
     -> writes a pytest JSON report AND the ``.asvs-markers.json`` sidecar beside
     it (via ``tests/conftest.py``'s ``pytest_collection_finish`` hook).
  2. ``reports.ledger.main()`` joins report + sidecar and layers on the crosswalk
     (``asvs4`` / ``asvs4_dropped``) and manifest views.
  3. assert all five views are present and structurally sound, and that the
     manifest view expresses the ``not_covered`` / ``not_applicable`` states that
     cannot be derived from probe tags alone.

The example profile points at a reserved placeholder host, so its live probes
SKIP — a skip is a complete outcome and still flows through the ledger, so no
live target is ever contacted.

Robust to manifest growth: a sibling PR expanding the expected-controls manifest
must not break this test, so it asserts the PRESENCE and STRUCTURE of each view
and of the manifest states, never exact control counts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from reports import ledger as ledger_mod

# Repo root (this file lives in tests/). Used as the subprocess cwd so --profile
# and the tests/ conftest resolve exactly as a normal invocation would.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE_PROFILE = _REPO_ROOT / "profiles" / "clerk-supabase-example.yaml"
# ONE small module carrying asvs()/cwe() tags. Scoping the subprocess to a single
# module keeps it fast AND guards against pytest recursion — this meta-test is
# never in the collected set, so it cannot re-invoke itself.
_TAGGED_MODULE = "tests/test_session.py"

# The coverage-status vocabulary a tag-derived axis (asvs/cwe) rollup can emit
# (mirrors reports.ledger._STATUS_LABELS). Pinning the enum — not just "some
# string" — makes a rollup that emits a misspelled/unknown status a failure.
_AXIS_STATUSES = frozenset(
    {"covered_passing", "covered_failing", "incomplete", "skipped", "not_run"}
)


def _run_ledger_pipeline(tmp_path: Path) -> dict:
    """Drive the real sidecar->ledger path and return the emitted ledger dict."""
    report = tmp_path / "report.json"

    env = dict(os.environ)
    # SCAN_SCOPE is scoped to THIS subprocess only — the parent suite is
    # unaffected, so core-scope runs stay byte-identical.
    env["SCAN_SCOPE"] = "asvs"
    env["PENTEST_MODE"] = "read-only"  # never enable write probes from a meta-test

    proc = subprocess.run(
        [
            sys.executable, "-m", "pytest", _TAGGED_MODULE,
            "--profile", str(_EXAMPLE_PROFILE),
            "--json-report", f"--json-report-file={report}",
            "-p", "no:cacheprovider", "-q",
        ],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    # pytest exits 0 (all pass) or 1 (some fail); against the placeholder host the
    # tagged module skips/passes, so demand a clean collection either way.
    assert proc.returncode in (0, 1), (
        f"pytest subprocess failed to run (rc={proc.returncode}).\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert report.is_file(), f"pytest JSON report was not written to {report}"

    # The conftest hook writes the sidecar beside the report using the shared
    # suffix-swap convention; the ledger CLI derives the same path by default.
    sidecar = ledger_mod.sidecar_path_for(report)
    assert sidecar.is_file(), (
        f"marker sidecar {sidecar} missing — the SCAN_SCOPE=asvs collection hook "
        f"did not emit it.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )

    out = tmp_path / "coverage-ledger.json"
    # Derive the sidecar via the default convention (do not pass --marker-sidecar)
    # so the report<->sidecar path contract is exercised end to end.
    rc = ledger_mod.main(["--pytest-report", str(report), "--output", str(out)])
    assert rc == 0, f"ledger CLI exited {rc} (expected 0)"
    assert out.is_file(), f"ledger output not written to {out}"

    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def emitted_ledger(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Run the pipeline once and share the ledger across the assertions below."""
    return _run_ledger_pipeline(tmp_path_factory.mktemp("ledger_e2e"))


def _assert_axis(view: object, axis: str) -> None:
    """A coverage axis (asvs/cwe) is a non-empty dict of well-formed rollups."""
    assert isinstance(view, dict) and view, f"{axis} view must be a non-empty dict"
    for control_id, entry in view.items():
        assert isinstance(control_id, str) and control_id, f"{axis} id must be a str"
        assert isinstance(entry, dict), f"{axis}[{control_id}] must be a dict"
        assert entry.get("status") in _AXIS_STATUSES, (
            f"{axis}[{control_id}] has unknown status {entry.get('status')!r}"
        )
        for count_key in ("passed", "failed", "skipped", "not_run", "total"):
            assert isinstance(entry.get(count_key), int), (
                f"{axis}[{control_id}] missing int count '{count_key}'"
            )
        # The per-outcome counts must partition the total — a rollup that miscounts
        # would otherwise slip past the isinstance checks above.
        assert (
            entry["passed"] + entry["failed"] + entry["skipped"] + entry["not_run"]
            == entry["total"]
        ), f"{axis}[{control_id}] counts do not sum to total"

    # The join is the point of this e2e: prove the report's outcomes actually
    # reached the sidecar-indexed controls. If the report<->sidecar join breaks
    # (nodeid drift, a regressed path derivation, or a rollup that stops consulting
    # outcomes), every control silently falls back to 'not_run' with valid ints and
    # a str status — passing every structural check above while crediting zero real
    # coverage. Against the placeholder host the tagged probes SKIP, so at least one
    # control must carry a non-'not_run' status for the join to be considered wired.
    assert any(entry["status"] != "not_run" for entry in view.values()), (
        f"{axis} view credited no attributed outcome — the report<->sidecar join "
        "did not reach any tagged control"
    )


def test_all_five_views_present_and_structured(emitted_ledger: dict) -> None:
    """asvs, cwe, asvs4, asvs4_dropped, manifest all emit together, well-formed."""
    ledger = emitted_ledger

    for view_name in ("asvs", "cwe", "asvs4", "asvs4_dropped", "manifest"):
        assert view_name in ledger, f"ledger is missing the '{view_name}' view"

    _assert_axis(ledger["asvs"], "asvs")
    _assert_axis(ledger["cwe"], "cwe")

    # asvs4: the 4.0.3 projection of the tagged 5.0 controls.
    asvs4 = ledger["asvs4"]
    assert isinstance(asvs4, dict) and asvs4, "asvs4 view must be a non-empty dict"
    for req_id, entry in asvs4.items():
        assert isinstance(entry.get("status"), str), f"asvs4[{req_id}] needs a status"
        assert isinstance(entry.get("from_asvs5"), list), (
            f"asvs4[{req_id}] must carry a 'from_asvs5' provenance list"
        )

    # asvs4_dropped: the static 4.0.3-only supplement (id + reason per entry).
    dropped = ledger["asvs4_dropped"]
    assert isinstance(dropped, list) and dropped, "asvs4_dropped must be a non-empty list"
    for item in dropped:
        assert isinstance(item.get("id"), str) and isinstance(item.get("reason"), str), (
            "each asvs4_dropped entry needs string 'id' and 'reason'"
        )


def test_manifest_view_classifies_not_covered_and_not_applicable(
    emitted_ledger: dict,
) -> None:
    """The manifest view expresses the two states the sidecar alone cannot.

    A single tagged module can never cover every manifest control, and the
    committed manifest always carries justified n-a exclusions, so both states
    are present regardless of manifest size (robust to manifest growth).
    """
    manifest = emitted_ledger["manifest"]
    assert isinstance(manifest, dict) and manifest, "manifest view must be a non-empty dict"

    observed_states = set()
    for control_id, entry in manifest.items():
        assert isinstance(entry.get("status"), str), f"manifest[{control_id}] needs a status"
        assert isinstance(entry.get("manifest_status"), str), (
            f"manifest[{control_id}] needs a 'manifest_status'"
        )
        assert isinstance(entry.get("note"), str) and entry["note"], (
            f"manifest[{control_id}] needs a justification note"
        )
        observed_states.add(entry["status"])

    assert "not_covered" in observed_states, (
        "manifest view never classified a control as not_covered — the "
        "expected-vs-observed set-difference is not wired"
    )
    assert "not_applicable" in observed_states, (
        "manifest view never classified a control as not_applicable — the "
        "n-a justified-exclusion states are not carried through"
    )

    # And it is summarised alongside the tag-derived axes.
    summary = emitted_ledger.get("summary", {})
    assert "manifest" in summary, "ledger summary is missing the manifest rollup"
