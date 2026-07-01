"""Offline unit tests for reports.ledger (ASVS/CWE coverage ledger).

Pure-function tests only — no live target, no pytest collection. Marker
extraction is exercised with duck-typed fake items; the rollup and CLI are fed
synthetic sidecar + pytest-report dicts.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from reports.ledger import (  # noqa: E402
    build_coverage_ledger,
    extract_marker_sidecar,
    load_sidecar,
    main,
    outcomes_from_pytest,
    render_summary,
    sidecar_path_for,
    write_sidecar,
)


# ---------------------------------------------------------------------------
# Fakes for the collection-side extraction
# ---------------------------------------------------------------------------

class _FakeMarker:
    def __init__(self, *args) -> None:
        self.args = args


class _FakeItem:
    """Duck-types the pytest item surface extract_marker_sidecar relies on."""

    def __init__(self, nodeid: str, **markers) -> None:
        self.nodeid = nodeid
        self._markers = markers  # name -> list[_FakeMarker]

    def iter_markers(self, name: str):
        return iter(self._markers.get(name, []))


# ---------------------------------------------------------------------------
# sidecar_path_for
# ---------------------------------------------------------------------------

def test_sidecar_path_for_mirrors_report_suffix():
    assert sidecar_path_for("report.json") == Path("report.asvs-markers.json")
    assert sidecar_path_for(
        "reports/pytest-report-20260626T010203Z.json"
    ) == Path("reports/pytest-report-20260626T010203Z.asvs-markers.json")


# ---------------------------------------------------------------------------
# extract_marker_sidecar
# ---------------------------------------------------------------------------

def test_extract_marker_sidecar_aggregates_stacked_ids_and_filters_untagged():
    items = [
        _FakeItem(
            "tests/test_a.py::test_one",
            asvs=[_FakeMarker("2.3.1")],
            cwe=[_FakeMarker("841")],
        ),
        # Two stacked asvs() markers on one node (cf. test_injection.py:759-760).
        _FakeItem(
            "tests/test_b.py::test_two",
            asvs=[_FakeMarker("1.3.6"), _FakeMarker("15.3.2")],
            cwe=[_FakeMarker("918")],
        ),
        # No coverage tags -> excluded from the sidecar.
        _FakeItem("tests/test_c.py::test_three"),
        # Duplicate id within a node is de-duplicated; asvs-only node has cwe=[].
        _FakeItem(
            "tests/test_d.py::test_four",
            asvs=[_FakeMarker("8.2.3"), _FakeMarker("8.2.3")],
        ),
        # cwe-only node -> kept with asvs=[] (mirror of the asvs-only node above).
        _FakeItem("tests/test_e.py::test_five", cwe=[_FakeMarker("79")]),
    ]

    sidecar = extract_marker_sidecar(items)

    assert sidecar == {
        "tests/test_a.py::test_one": {"asvs": ["2.3.1"], "cwe": ["841"]},
        "tests/test_b.py::test_two": {"asvs": ["1.3.6", "15.3.2"], "cwe": ["918"]},
        "tests/test_d.py::test_four": {"asvs": ["8.2.3"], "cwe": []},
        "tests/test_e.py::test_five": {"asvs": [], "cwe": ["79"]},
    }


# ---------------------------------------------------------------------------
# outcomes_from_pytest
# ---------------------------------------------------------------------------

def test_outcomes_from_pytest_maps_nodeid_to_outcome_ignoring_unnamed():
    data = {
        "tests": [
            {"nodeid": "t::a", "outcome": "passed"},
            {"nodeid": "t::b", "outcome": "skipped"},
            {"outcome": "failed"},  # no nodeid -> dropped
        ]
    }
    assert outcomes_from_pytest(data) == {"t::a": "passed", "t::b": "skipped"}


def test_outcomes_from_pytest_tolerates_null_tests_field():
    # A report whose "tests" key is JSON null must not crash: dict.get(k, [])
    # returns None (key present, value null), and iterating None would raise
    # TypeError past main()'s exit-3 guards -> a bare exit 1 instead of infra-3.
    assert outcomes_from_pytest({"tests": None}) == {}


def test_outcomes_from_pytest_skips_non_dict_entries():
    # A malformed list entry (a bare string, not a test object) is skipped, not
    # crashed on (str has no .get).
    data = {"tests": ["garbage", {"nodeid": "t::a", "outcome": "passed"}]}
    assert outcomes_from_pytest(data) == {"t::a": "passed"}


def test_outcomes_from_pytest_skips_non_string_nodeid():
    # A dict entry whose nodeid is an unhashable non-string (e.g. a list) must be
    # skipped, not used as a dict key (which would raise TypeError).
    data = {"tests": [{"nodeid": [], "outcome": "passed"},
                      {"nodeid": "t::a", "outcome": "passed"}]}
    assert outcomes_from_pytest(data) == {"t::a": "passed"}


# ---------------------------------------------------------------------------
# build_coverage_ledger
# ---------------------------------------------------------------------------

def test_build_coverage_ledger_classifies_each_status():
    sidecar = {
        "t::pass": {"asvs": ["3.4.6"], "cwe": ["1021"]},
        "t::fail": {"asvs": ["2.3.1"], "cwe": ["841"]},
        "t::skip": {"asvs": ["14.2.1"], "cwe": ["598"]},
        "t::gone": {"asvs": ["9.9.9"], "cwe": ["000"]},  # tagged but no outcome
    }
    outcomes = {"t::pass": "passed", "t::fail": "failed", "t::skip": "skipped"}

    ledger = build_coverage_ledger(sidecar, outcomes)

    assert ledger["asvs"]["3.4.6"]["status"] == "covered_passing"
    assert ledger["asvs"]["2.3.1"]["status"] == "covered_failing"
    assert ledger["asvs"]["14.2.1"]["status"] == "skipped"
    assert ledger["asvs"]["9.9.9"]["status"] == "not_run"
    # CWE view mirrors the same nodes.
    assert ledger["cwe"]["841"]["status"] == "covered_failing"
    assert ledger["summary"]["asvs"] == {
        "covered_passing": 1,
        "covered_failing": 1,
        "incomplete": 0,
        "skipped": 1,
        "not_run": 1,
    }


def test_failing_takes_precedence_over_passing_for_a_shared_control():
    sidecar = {
        "t::a": {"asvs": ["8.2.3"], "cwe": []},
        "t::b": {"asvs": ["8.2.3"], "cwe": []},
    }
    outcomes = {"t::a": "passed", "t::b": "failed"}

    entry = build_coverage_ledger(sidecar, outcomes)["asvs"]["8.2.3"]

    assert entry["status"] == "covered_failing"
    assert entry["passed"] == 1 and entry["failed"] == 1
    assert entry["total"] == 2
    assert entry["nodes"] == ["t::a", "t::b"]


def test_control_with_passing_and_skipped_nodes_is_covered_passing():
    # The _rollup docstring's mixed case: one node ran+passed, a sibling skipped
    # (provider absent). Status is covered_passing, but the skip stays visible in
    # the counts rather than being folded into "pass".
    sidecar = {
        "t::pass": {"asvs": ["7.2.4"], "cwe": []},
        "t::skip": {"asvs": ["7.2.4"], "cwe": []},
    }
    outcomes = {"t::pass": "passed", "t::skip": "skipped"}

    entry = build_coverage_ledger(sidecar, outcomes)["asvs"]["7.2.4"]

    assert entry["status"] == "covered_passing"
    assert entry["passed"] == 1 and entry["skipped"] == 1
    assert entry["total"] == 2


def test_control_with_passing_and_not_run_nodes_is_incomplete():
    # Fail closed: a control spread across probes where one passes but a sibling
    # never ran (interrupted run / stale sidecar) must NOT count as covered.
    sidecar = {
        "t::ran": {"asvs": ["8.2.1"], "cwe": []},
        "t::absent": {"asvs": ["8.2.1"], "cwe": []},
    }
    outcomes = {"t::ran": "passed"}  # t::absent has no outcome -> not_run

    entry = build_coverage_ledger(sidecar, outcomes)["asvs"]["8.2.1"]

    assert entry["status"] == "incomplete"
    assert entry["passed"] == 1 and entry["not_run"] == 1
    assert entry["total"] == 2


def test_control_with_failing_and_not_run_nodes_is_incomplete():
    # A failure among the ran probes is still surfaced by reports/aggregate.py;
    # in the coverage ledger the not_run sibling makes the evidence incomplete.
    sidecar = {
        "t::ran": {"asvs": ["8.2.1"], "cwe": []},
        "t::absent": {"asvs": ["8.2.1"], "cwe": []},
    }
    outcomes = {"t::ran": "failed"}

    entry = build_coverage_ledger(sidecar, outcomes)["asvs"]["8.2.1"]

    assert entry["status"] == "incomplete"
    assert entry["failed"] == 1 and entry["not_run"] == 1


def test_control_with_all_nodes_absent_is_not_run_not_incomplete():
    # Distinguish "partially ran" (incomplete) from "nothing ran" (not_run):
    # incomplete requires at least one node to have actually produced an outcome.
    sidecar = {
        "t::a": {"asvs": ["8.2.1"], "cwe": []},
        "t::b": {"asvs": ["8.2.1"], "cwe": []},
    }
    entry = build_coverage_ledger(sidecar, {})["asvs"]["8.2.1"]

    assert entry["status"] == "not_run"
    assert entry["not_run"] == 2


def test_error_outcome_counts_as_failing():
    ledger = build_coverage_ledger(
        {"t::e": {"asvs": ["1.2.5"], "cwe": ["78"]}}, {"t::e": "error"}
    )
    assert ledger["asvs"]["1.2.5"]["status"] == "covered_failing"
    assert ledger["asvs"]["1.2.5"]["failed"] == 1


def test_asvs_view_is_naturally_ordered():
    sidecar = {
        "t::a": {"asvs": ["15.3.2"], "cwe": []},
        "t::b": {"asvs": ["2.4.1"], "cwe": []},
        "t::c": {"asvs": ["2.3.1"], "cwe": []},
    }
    ledger = build_coverage_ledger(sidecar, {})
    assert list(ledger["asvs"].keys()) == ["2.3.1", "2.4.1", "15.3.2"]


def test_cwe_view_is_naturally_ordered():
    # Bare-integer CWE ids sort numerically, not lexically ("799" before "1021").
    sidecar = {
        "t::a": {"asvs": [], "cwe": ["1021"]},
        "t::b": {"asvs": [], "cwe": ["799"]},
        "t::c": {"asvs": [], "cwe": ["78"]},
    }
    ledger = build_coverage_ledger(sidecar, {})
    assert list(ledger["cwe"].keys()) == ["78", "799", "1021"]


def test_natural_key_tolerates_non_ascii_digit_ids():
    # str.isdigit() is True for a superscript "²", but int("²") raises.
    # The isascii() guard must route such a segment to the lexical bucket rather
    # than crash the sort. (Without the guard this call raises ValueError.)
    sidecar = {
        "t::u": {"asvs": ["²"], "cwe": []},  # superscript two
        "t::n": {"asvs": ["2"], "cwe": []},
    }
    ledger = build_coverage_ledger(sidecar, {})  # must not raise
    keys = list(ledger["asvs"].keys())
    assert set(keys) == {"2", "²"}
    # ASCII-numeric segment sorts ahead of the non-ASCII (lexical-bucket) one.
    assert keys.index("2") < keys.index("²")


# ---------------------------------------------------------------------------
# render_summary
# ---------------------------------------------------------------------------

def test_render_summary_contains_axis_titles_and_status_labels():
    ledger = build_coverage_ledger(
        {"t::s": {"asvs": ["2.3.1"], "cwe": ["841"]}}, {"t::s": "skipped"}
    )
    text = render_summary(ledger)
    assert "ASVS 5.0 coverage" in text
    assert "CWE coverage" in text
    assert "skipped (not coverage)" in text
    assert "2.3.1" in text and "841" in text
    # The per-control detail line renders the numeric counts, not just labels.
    assert "pass=0 fail=0 skip=1 n/a=0" in text


def test_render_summary_shows_incomplete_control():
    # A live incomplete control (one probe ran, one absent) renders with the new
    # label and its counts, not just as a zero in the summary block.
    sidecar = {
        "t::ran": {"asvs": ["8.2.1"], "cwe": []},
        "t::absent": {"asvs": ["8.2.1"], "cwe": []},
    }
    text = render_summary(build_coverage_ledger(sidecar, {"t::ran": "passed"}))
    assert "incomplete (partial run)" in text
    assert "8.2.1" in text
    assert "pass=1 fail=0 skip=0 n/a=1" in text


# ---------------------------------------------------------------------------
# write/load + CLI
# ---------------------------------------------------------------------------

def test_write_then_load_sidecar_roundtrip(tmp_path):
    sidecar = {"t::x": {"asvs": ["2.3.1"], "cwe": ["841"]}}
    path = tmp_path / "sub" / "report.asvs-markers.json"
    write_sidecar(sidecar, path)
    assert load_sidecar(path) == sidecar


def test_main_emits_ledger_json_and_derives_sidecar(tmp_path, capsys):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"tests": [{"nodeid": "t::s", "outcome": "skipped"}]}),
        encoding="utf-8",
    )
    # Written at the path main() derives from --pytest-report (no --marker-sidecar).
    write_sidecar({"t::s": {"asvs": ["2.3.1"], "cwe": ["841"]}}, sidecar_path_for(report))
    out = tmp_path / "ledger.json"

    rc = main(["--pytest-report", str(report), "--output", str(out)])

    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["asvs"]["2.3.1"]["status"] == "skipped"
    assert "generated_at" in data
    assert "ASVS 5.0 coverage" in capsys.readouterr().out


def test_main_missing_sidecar_returns_infra_error(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"tests": []}), encoding="utf-8")
    assert main(["--pytest-report", str(report)]) == 3


def test_main_missing_pytest_report_returns_infra_error(tmp_path):
    # Valid sidecar present so exit 3 can only come from the report-load branch
    # (report is loaded before the sidecar), not the missing-sidecar branch.
    report = tmp_path / "nope.json"  # never created
    write_sidecar({"t::s": {"asvs": ["2.3.1"], "cwe": []}}, sidecar_path_for(report))
    assert main(["--pytest-report", str(report)]) == 3


def test_main_corrupt_pytest_report_returns_infra_error(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("{ not json", encoding="utf-8")
    write_sidecar({"t::s": {"asvs": ["2.3.1"], "cwe": []}}, sidecar_path_for(report))
    assert main(["--pytest-report", str(report)]) == 3


def test_main_corrupt_sidecar_returns_infra_error(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"tests": []}), encoding="utf-8")
    sidecar_path_for(report).write_text("{ not json", encoding="utf-8")
    assert main(["--pytest-report", str(report)]) == 3


def test_main_non_dict_pytest_report_returns_infra_error(tmp_path):
    # Valid JSON, wrong shape: a top-level list ([]) would hit .get() and raise
    # AttributeError past the load guards -> must map to exit 3, not a crash.
    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")
    write_sidecar({"t::s": {"asvs": ["2.3.1"], "cwe": []}}, sidecar_path_for(report))
    assert main(["--pytest-report", str(report)]) == 3


def test_main_non_dict_sidecar_returns_infra_error(tmp_path):
    # A top-level list sidecar would hit .items() and raise AttributeError.
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"tests": []}), encoding="utf-8")
    sidecar_path_for(report).write_text("[]", encoding="utf-8")
    assert main(["--pytest-report", str(report)]) == 3


def test_main_non_list_tests_field_returns_infra_error(tmp_path):
    # "tests" present but not a list (a dict) is a malformed report -> exit 3.
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"tests": {"nope": 1}}), encoding="utf-8")
    write_sidecar({"t::s": {"asvs": ["2.3.1"], "cwe": []}}, sidecar_path_for(report))
    assert main(["--pytest-report", str(report)]) == 3


def test_main_non_dict_sidecar_entry_returns_infra_error(tmp_path):
    # A sidecar that is a dict but whose entry value is not an object ([]) would
    # hit tags.get(...) in build_coverage_ledger -> must be caught as exit 3.
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"tests": []}), encoding="utf-8")
    sidecar_path_for(report).write_text(json.dumps({"t::x": []}), encoding="utf-8")
    assert main(["--pytest-report", str(report)]) == 3


def test_main_non_list_tag_values_in_sidecar_returns_infra_error(tmp_path):
    # A sidecar entry whose 'asvs' is a bare string, not a list, is malformed.
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"tests": []}), encoding="utf-8")
    sidecar_path_for(report).write_text(
        json.dumps({"t::x": {"asvs": "2.3.1", "cwe": []}}), encoding="utf-8"
    )
    assert main(["--pytest-report", str(report)]) == 3


def test_main_non_string_tag_element_returns_infra_error(tmp_path):
    # 'asvs' is a list (passes the container check) but holds a non-string,
    # unhashable element; must be caught as exit 3, not crash in the rollup.
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"tests": []}), encoding="utf-8")
    sidecar_path_for(report).write_text(
        json.dumps({"t::x": {"asvs": [[]], "cwe": []}}), encoding="utf-8"
    )
    assert main(["--pytest-report", str(report)]) == 3


def test_build_coverage_ledger_skips_non_string_tag_elements():
    # Direct-caller safety: build itself never raises on a non-string id, it
    # skips it (the CLI rejects the same shape loudly via _sidecar_entry_ok).
    ledger = build_coverage_ledger(
        {"t::x": {"asvs": [[], "2.3.1"], "cwe": []}}, {}
    )
    assert list(ledger["asvs"].keys()) == ["2.3.1"]


def test_main_unwritable_output_returns_infra_error(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"tests": []}), encoding="utf-8")
    write_sidecar({"t::s": {"asvs": ["2.3.1"], "cwe": []}}, sidecar_path_for(report))
    # A file where the output's parent dir should be -> mkdir/write raises OSError.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    out = blocker / "ledger.json"
    assert main(["--pytest-report", str(report), "--output", str(out)]) == 3
