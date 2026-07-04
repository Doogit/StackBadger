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
  3 — infrastructure error (a pytest report or sidecar that is missing,
      unparseable, or the wrong JSON shape, or an --output file that could
      not be written)
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from reports import crosswalk

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
    for test in pytest_data.get("tests") or []:
        if not isinstance(test, dict):
            continue  # skip a malformed (non-object) entry rather than crash
        node_id = test.get("nodeid")
        if isinstance(node_id, str) and node_id:  # str guard: a non-str id (e.g.
            outcomes[node_id] = test.get("outcome", "")  # a list) is unhashable
    return outcomes


# ---------------------------------------------------------------------------
# Coverage rollup (pure)
# ---------------------------------------------------------------------------


def _natural_key(control_id: str) -> tuple:
    """Sort key giving natural order for dotted ASVS ids and numeric CWE ids.

    Each dot-separated segment sorts numerically when it is all ASCII digits,
    else lexically, so "2.3.1" < "2.4.1" < "15.3.2" and CWE "78" < "799".
    ``isascii()`` guards the ``int()`` — ``str.isdigit()`` is also true for
    non-decimal Unicode digits (e.g. superscripts) that ``int()`` rejects.
    """
    parts: list[tuple[int, Any]] = []
    for seg in str(control_id).split("."):
        parts.append((0, int(seg)) if seg.isascii() and seg.isdigit() else (1, seg))
    return tuple(parts)


def _rollup(node_ids: list[str], outcomes: dict[str, str]) -> dict[str, Any]:
    """Roll a control's tagged nodes up into counts + a single coverage status.

    Fail closed: a control counts as ``covered`` only when *every* one of its
    tagged probes produced an outcome in the report. Statuses, in precedence:

    - ``incomplete`` -- at least one tagged probe ran (passed/failed/skipped)
      but at least one other has NO outcome in the report (``not_run``). The
      evidence is partial, so the control is NOT credited as covered even if the
      probes that ran passed. Controls are deliberately spread across several
      probes (e.g. ASVS 8.2.1 across ``test_payment_gate.py``), so a stale or
      interrupted run that reaches only some of them would otherwise over-credit
      coverage. A genuine failure among the ran probes is still surfaced as a
      finding by ``reports/aggregate.py`` -- the ledger is coverage accounting,
      not the findings gate -- so demoting ``fail+not_run`` here hides nothing.
    - ``covered_failing`` -- all tagged probes ran and at least one failed.
    - ``covered_passing`` -- all tagged probes ran, at least one passed, none
      failed. Some may have skipped (provider/config absent); a skip is a
      *complete* outcome, so pass+skip is still covered, and the counts keep the
      skip visible.
    - ``skipped`` -- all tagged probes ran and every one skipped (NOT coverage).
    - ``not_run`` -- NO tagged probe has an outcome (the whole control is absent
      from the report: run interrupted before it, or report/sidecar mismatch).

    The harness uses no xfail/xpass markers, so any outcome other than
    passed/failed/error/skipped buckets as ``not_run``.
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

    ran = counts["passed"] + counts["failed"] + counts["skipped"]
    if counts["not_run"]:
        # Partial execution demotes to incomplete; a wholly-absent control stays
        # not_run. Either way the control is never credited as covered.
        status = "incomplete" if ran else "not_run"
    elif counts["failed"]:
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
    # _STATUS_LABELS is the single source of both the status set and its order
    # (dict insertion order); iterate it directly so the two never drift.
    summary = {status: 0 for status in _STATUS_LABELS}
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
        if not isinstance(tags, dict):
            continue  # the CLI rejects these before here; guard direct callers too
        for asvs_id in tags.get("asvs") or []:
            if isinstance(asvs_id, str):  # a non-string id is unhashable as a key
                asvs_index.setdefault(asvs_id, []).append(node_id)
        for cwe_id in tags.get("cwe") or []:
            if isinstance(cwe_id, str):
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
    "incomplete": "incomplete (partial run)",
    "skipped": "skipped (not coverage)",
    "not_run": "not run (absent from report)",
}

_MANIFEST_STATUS_LABELS = {
    **_STATUS_LABELS,
    "not_covered": "not covered (no tagged probe)",
    "not_applicable": "not applicable (justified exclusion)",
}


def render_summary(ledger: dict[str, Any]) -> str:
    """Compact text summary of the coverage ledger (one block per axis)."""
    lines: list[str] = []
    for axis, title in (("asvs", "ASVS 5.0"), ("cwe", "CWE")):
        view = ledger.get(axis, {})
        summary = ledger.get("summary", {}).get(axis, {})
        lines.append(f"{title} coverage (from probe tags) - {len(view)} control(s):")
        for status in _STATUS_LABELS:
            lines.append(f"  {_STATUS_LABELS[status]:<24} {summary.get(status, 0)}")
        for control_id, entry in view.items():
            lines.append(
                f"    {control_id:<10} {_STATUS_LABELS[entry['status']]:<24}"
                f" (pass={entry['passed']} fail={entry['failed']}"
                f" skip={entry['skipped']} n/a={entry['not_run']})"
            )
    manifest = ledger.get("manifest")
    if manifest is not None:
        summary = ledger.get("summary", {}).get("manifest", {})
        lines.append(f"Expected-controls manifest - {len(manifest)} control(s):")
        for status in _MANIFEST_STATUS_LABELS:
            lines.append(f"  {_MANIFEST_STATUS_LABELS[status]:<32} {summary.get(status, 0)}")
        for control_id, entry in manifest.items():
            if entry["status"] in ("not_covered", "not_applicable"):
                lines.append(
                    f"    {control_id:<10} {_MANIFEST_STATUS_LABELS[entry['status']]:<32} "
                    f"{entry['note']}"
                )
    asvs4 = ledger.get("asvs4")
    if asvs4 is not None:  # present only when the crosswalk data was loaded
        summary = crosswalk.summarize_asvs4(asvs4)
        lines.append(
            f"ASVS 4.0.3 crosswalk (projected from 5.0) - {len(asvs4)} requirement(s):"
        )
        for status in _STATUS_LABELS:
            lines.append(f"  {_STATUS_LABELS[status]:<24} {summary.get(status, 0)}")
        lines.append(
            f"  dropped supplement (no 5.0 successor): "
            f"{len(ledger.get('asvs4_dropped') or [])}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _sidecar_entry_ok(tags: Any) -> bool:
    """A sidecar entry is well-formed when it is an object whose 'asvs'/'cwe' are
    absent, null, or lists of string ids -- exactly what write_sidecar emits.

    The CLI checks this so a hand-edited or corrupted sidecar fails loudly with
    the exit-3 infra code instead of escaping as a bare exception deeper in the
    rollup (a non-string id is unhashable as an index key).
    """
    if not isinstance(tags, dict):
        return False
    for key in ("asvs", "cwe"):
        value = tags.get(key)
        if value is None:
            continue
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            return False
    return True


def _pytest_test_entry_ok(test: Any) -> bool:
    """A pytest-report test entry is well-formed when it is an object whose
    optional 'nodeid' field is a string.

    main() validates this so a corrupted report fails closed with exit 3 rather
    than silently dropping malformed entries and understating missing coverage.
    """
    return isinstance(test, dict) and (
        "nodeid" not in test or test["nodeid"] is None or isinstance(test["nodeid"], str)
    )


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

    # Shape-validate the parsed JSON before use: a syntactically valid but
    # wrong-shaped artifact (e.g. a top-level list) would otherwise raise
    # AttributeError past these guards and escape the exit-3 infra contract.
    if not isinstance(pytest_data, dict):
        print(
            f"[error] Pytest report {args.pytest_report} is malformed: expected a "
            f"JSON object, got {type(pytest_data).__name__}.",
            file=sys.stderr,
        )
        return 3
    tests = pytest_data.get("tests")
    if tests is not None and not isinstance(tests, list):
        print(
            f"[error] Pytest report {args.pytest_report} is malformed: 'tests' must "
            f"be a list, got {type(tests).__name__}.",
            file=sys.stderr,
        )
        return 3
    for idx, test in enumerate(tests or []):
        if not _pytest_test_entry_ok(test):
            print(
                f"[error] Pytest report {args.pytest_report} is malformed: "
                f"tests[{idx}] must be an object with an optional string 'nodeid'.",
                file=sys.stderr,
            )
            return 3
    if not isinstance(sidecar, dict):
        print(
            f"[error] Marker sidecar {sidecar_path} is malformed: expected a JSON "
            f"object, got {type(sidecar).__name__}.",
            file=sys.stderr,
        )
        return 3
    for node_id, tags in sidecar.items():
        if not _sidecar_entry_ok(tags):
            print(
                f"[error] Marker sidecar {sidecar_path} is malformed: entry "
                f"{node_id!r} must be an object with list-of-string 'asvs'/'cwe' values.",
                file=sys.stderr,
            )
            return 3

    outcomes = outcomes_from_pytest(pytest_data)
    ledger = build_coverage_ledger(sidecar, outcomes)
    # Project the 5.0 view onto ASVS 4.0.3 (+ dropped supplement) for CASA/Tier-2.
    # Absent data warns+skips; malformed data fails loud with the exit-3 infra code.
    try:
        crosswalk.augment_ledger(ledger)
    except crosswalk.CrosswalkError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 3
    ledger["generated_at"] = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Expected-controls manifest view (not_covered / not_applicable by
    # set-difference). Warn-only add-on: a missing/malformed manifest degrades
    # gracefully and never changes this CLI's exit code. Local import keeps the
    # ledger import (and run.sh's `import reports.ledger` probe) light.
    from reports.manifest import attach_manifest_view

    attach_manifest_view(ledger)

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
