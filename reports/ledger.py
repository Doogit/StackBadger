"""ASVS/CWE coverage ledger (Tier-2, scope=asvs).

Turns the per-probe ``@pytest.mark.asvs(id)`` / ``@pytest.mark.cwe(id)`` tags
into an emitted coverage ledger. ``pytest-json-report`` records marker *names*
but not their *arguments*, so the requirement/CWE ids are captured at collection
time into a sidecar JSON (``tests/conftest.py`` ``pytest_collection_finish``,
gated on ``SCAN_SCOPE=asvs``) and joined here against the run's pass/skip/fail
outcomes.

This is deliberately separate from ``reports/aggregate.py``: aggregate builds
*findings* (failed/error outcomes only) and owns the run.sh exit-1 severity gate;
the ledger builds *coverage accounting* and ingests ALL outcomes — a skip is NOT
coverage and is rendered as such, never as a pass.

Scope (PR1): ASVS-5.0 and CWE views rolled up from the tagged-node universe.
The expected-controls manifest (``not-covered`` / ``N-A`` by set-difference) and
the ASVS-4.0 crosswalk view are later tiers and not computed here.

Usage:
    python -m reports.ledger \\
        --pytest-report reports/pytest-report-<ts>.json \\
        [--marker-sidecar <path>]  \\
        [--output reports/output/coverage-ledger-<ts>.json]

If ``--marker-sidecar`` is omitted it is derived from ``--pytest-report`` by
swapping the suffix to ``.asvs-markers.json`` — the same rule the conftest hook
uses to write it, so the two agree without any env coordination.

Exit codes:
  0 — ledger emitted
  3 — infrastructure error (missing/unparseable pytest report or sidecar)
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Suffix the marker sidecar gets relative to the pytest JSON report it pairs
# with (report.json -> report.asvs-markers.json). One constant, shared by the
# conftest writer and the ledger reader so they agree on the path.
_SIDECAR_SUFFIX = ".asvs-markers.json"


# ---------------------------------------------------------------------------
# Sidecar path (shared contract with tests/conftest.py)
# ---------------------------------------------------------------------------

def sidecar_path_for(pytest_report_path: str | Path) -> Path:
    """Derive the marker-sidecar path that sits beside a pytest JSON report.

    ``report.json`` -> ``report.asvs-markers.json``;
    ``reports/pytest-report-<ts>.json`` -> ``reports/pytest-report-<ts>.asvs-markers.json``.
    Both the conftest writer and the ledger reader call this, so they always
    agree on the location.
    """
    return Path(pytest_report_path).with_suffix(_SIDECAR_SUFFIX)


# ---------------------------------------------------------------------------
# Collection-side extraction (called from conftest pytest_collection_finish)
# ---------------------------------------------------------------------------

def _marker_arg_ids(item: Any, name: str) -> list[str]:
    """Collect, in order and de-duplicated, every positional arg across all
    markers named ``name`` on a collected item.

    A node may carry the marker more than once (e.g. two ``asvs(...)`` ids), so
    this aggregates across markers rather than reading only the closest one.
    """
    ids: list[str] = []
    for marker in item.iter_markers(name):
        for arg in marker.args:
            value = str(arg).strip()
            if value and value not in ids:
                ids.append(value)
    return ids


def extract_marker_sidecar(items: Iterable[Any]) -> dict[str, dict[str, list[str]]]:
    """Build the ``node-id -> {asvs, cwe}`` sidecar from collected pytest items.

    Only nodes carrying at least one ``asvs`` or ``cwe`` tag are included — the
    sidecar is the coverage-tag index, not a full node listing. Items are duck
    typed (``.nodeid`` + ``.iter_markers(name)``) so the function is unit
    testable without a live pytest collection.
    """
    sidecar: dict[str, dict[str, list[str]]] = {}
    for item in items:
        asvs_ids = _marker_arg_ids(item, "asvs")
        cwe_ids = _marker_arg_ids(item, "cwe")
        if not asvs_ids and not cwe_ids:
            continue
        sidecar[item.nodeid] = {"asvs": asvs_ids, "cwe": cwe_ids}
    return sidecar


def write_sidecar(sidecar: dict[str, dict[str, list[str]]], path: str | Path) -> None:
    """Persist the marker sidecar as pretty JSON (parent dirs created)."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(sidecar, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_sidecar(path: str | Path) -> dict[str, dict[str, list[str]]]:
    """Load a marker sidecar; raise FileNotFoundError/json errors to the caller."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_pytest_report(path: str | Path) -> dict:
    """Parse a pytest-json-report file. Raises on missing/invalid input so the
    CLI can map it to the infra-error exit code (3)."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def outcomes_from_pytest(pytest_data: dict) -> dict[str, str]:
    """Map every reported test node id to its outcome (passed/failed/skipped/...)."""
    outcomes: dict[str, str] = {}
    for test in pytest_data.get("tests", []):
        node_id = test.get("nodeid")
        if node_id:
            outcomes[node_id] = test.get("outcome", "")
    return outcomes


# ---------------------------------------------------------------------------
# Coverage rollup (pure)
# ---------------------------------------------------------------------------

_STATUS_ORDER = ("covered_passing", "covered_failing", "skipped", "not_run")


def _natural_key(control_id: str) -> tuple:
    """Sort key giving natural order for dotted ASVS ids and numeric CWE ids.

    Each dot-separated segment sorts numerically when it is all digits, else
    lexically, so "2.3.1" < "2.4.1" < "15.3.2" and CWE "78" < "799".
    """
    parts: list[tuple[int, Any]] = []
    for seg in str(control_id).split("."):
        parts.append((0, int(seg)) if seg.isdigit() else (1, seg))
    return tuple(parts)


def _rollup(node_ids: list[str], outcomes: dict[str, str]) -> dict[str, Any]:
    """Roll a control's tagged nodes up into counts + a single coverage status.

    A control is ``covered`` only when a tagged probe actually ran: a failing
    run means the control was exercised and the target failed it (a finding),
    a passing run means exercised and passed. ``covered_passing`` therefore
    means at least one tagged node passed and none failed -- some nodes may
    still have skipped (provider/config absent), so the per-control counts keep
    the skip visible rather than the status implying every node ran. If *every*
    tagged probe skipped, the control is ``skipped`` (NOT coverage). ``not_run``
    means a tagged node is in the sidecar but has no outcome in the report (e.g.
    the run was interrupted before reaching it, or report and sidecar are from
    different runs). The harness uses no xfail/xpass markers, so any outcome
    other than passed/failed/error/skipped buckets as ``not_run``.
    """
    counts = {"passed": 0, "failed": 0, "skipped": 0, "not_run": 0}
    for node_id in node_ids:
        outcome = outcomes.get(node_id, "not_run")
        if outcome == "passed":
            counts["passed"] += 1
        elif outcome in ("failed", "error"):
            counts["failed"] += 1
        elif outcome == "skipped":
            counts["skipped"] += 1
        else:
            counts["not_run"] += 1

    if counts["failed"]:
        status = "covered_failing"
    elif counts["passed"]:
        status = "covered_passing"
    elif counts["skipped"]:
        status = "skipped"
    else:
        status = "not_run"

    return {
        "status": status,
        **counts,
        "total": len(node_ids),
        "nodes": sorted(node_ids),
    }


def _summarize(view: dict[str, dict[str, Any]]) -> dict[str, int]:
    summary = {status: 0 for status in _STATUS_ORDER}
    for entry in view.values():
        summary[entry["status"]] += 1
    return summary


def _build_axis(index: dict[str, list[str]], outcomes: dict[str, str]) -> dict[str, dict[str, Any]]:
    return {
        control_id: _rollup(index[control_id], outcomes)
        for control_id in sorted(index, key=_natural_key)
    }


def build_coverage_ledger(
    sidecar: dict[str, dict[str, list[str]]],
    outcomes: dict[str, str],
) -> dict[str, Any]:
    """Join the marker sidecar with run outcomes into ASVS-5.0 and CWE views."""
    asvs_index: dict[str, list[str]] = {}
    cwe_index: dict[str, list[str]] = {}
    for node_id, tags in sidecar.items():
        for asvs_id in tags.get("asvs", []):
            asvs_index.setdefault(asvs_id, []).append(node_id)
        for cwe_id in tags.get("cwe", []):
            cwe_index.setdefault(cwe_id, []).append(node_id)

    asvs_view = _build_axis(asvs_index, outcomes)
    cwe_view = _build_axis(cwe_index, outcomes)
    return {
        "asvs": asvs_view,
        "cwe": cwe_view,
        "summary": {"asvs": _summarize(asvs_view), "cwe": _summarize(cwe_view)},
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_STATUS_LABELS = {
    "covered_passing": "covered (passing)",
    "covered_failing": "covered (FINDING)",
    "skipped": "skipped (not coverage)",
    "not_run": "not run (absent from report)",
}


def render_summary(ledger: dict[str, Any]) -> str:
    """Compact text summary of the coverage ledger (one block per axis)."""
    lines: list[str] = []
    for axis, title in (("asvs", "ASVS 5.0"), ("cwe", "CWE")):
        view = ledger.get(axis, {})
        summary = ledger.get("summary", {}).get(axis, {})
        lines.append(f"{title} coverage (from probe tags) - {len(view)} control(s):")
        for status in _STATUS_ORDER:
            lines.append(f"  {_STATUS_LABELS[status]:<24} {summary.get(status, 0)}")
        for control_id, entry in view.items():
            lines.append(
                f"    {control_id:<10} {_STATUS_LABELS[entry['status']]:<24}"
                f" (pass={entry['passed']} fail={entry['failed']}"
                f" skip={entry['skipped']} n/a={entry['not_run']})"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit the ASVS/CWE coverage ledger from probe tags + pytest outcomes."
    )
    parser.add_argument(
        "--pytest-report",
        type=Path,
        required=True,
        help="Path to the pytest JSON report (required).",
    )
    parser.add_argument(
        "--marker-sidecar",
        type=Path,
        default=None,
        help="Path to the marker sidecar JSON (default: derived from --pytest-report).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write the ledger JSON to this path (default: stdout summary only).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    sidecar_path = args.marker_sidecar or sidecar_path_for(args.pytest_report)

    try:
        pytest_data = load_pytest_report(args.pytest_report)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[error] Could not read pytest report {args.pytest_report}: {exc}", file=sys.stderr)
        return 3
    try:
        sidecar = load_sidecar(sidecar_path)
    except FileNotFoundError:
        print(
            f"[error] Marker sidecar not found at {sidecar_path}. Run pytest with "
            "SCAN_SCOPE=asvs so the conftest hook emits it, then re-run the ledger.",
            file=sys.stderr,
        )
        return 3
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[error] Could not read marker sidecar {sidecar_path}: {exc}", file=sys.stderr)
        return 3

    outcomes = outcomes_from_pytest(pytest_data)
    ledger = build_coverage_ledger(sidecar, outcomes)
    ledger["generated_at"] = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(ledger, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except OSError as exc:
            print(f"[error] Could not write ledger to {args.output}: {exc}", file=sys.stderr)
            return 3
        print(f"[done] Coverage ledger -> {args.output}", file=sys.stderr)

    print(render_summary(ledger))
    return 0


if __name__ == "__main__":
    sys.exit(main())
