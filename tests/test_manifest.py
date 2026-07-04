"""Offline unit tests for reports.manifest (expected-controls set-difference).

Pure-function + loader tests only -- no live target, no pytest collection. The
manifest is fed as synthetic dicts / tmp_path YAML files, and the set-difference
is exercised against a synthetic ledger ASVS view.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from reports.manifest import (  # noqa: E402
    DEFAULT_MANIFEST_PATH,
    ManifestError,
    attach_manifest_view,
    build_manifest_view,
    load_manifest,
    summarize_manifest_view,
)


# ---------------------------------------------------------------------------
# load_manifest -- happy path + loud rejection of malformed input
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_manifest_parses_valid_entries(tmp_path):
    path = _write(
        tmp_path,
        'controls:\n'
        '  "7.2.4": {status: expected, note: "session token rotation"}\n'
        '  "11": {status: n-a, note: "internal crypto -- not black-box"}\n',
    )
    manifest = load_manifest(path)
    assert manifest == {
        "7.2.4": {"status": "expected", "note": "session token rotation"},
        "11": {"status": "n-a", "note": "internal crypto -- not black-box"},
    }


def test_load_manifest_missing_file_raises_filenotfound(tmp_path):
    # Missing is distinct from malformed: the caller (attach) treats it as
    # graceful degradation, so it must surface as FileNotFoundError, not
    # ManifestError.
    with pytest.raises(FileNotFoundError):
        load_manifest(tmp_path / "nope.yaml")


def test_load_manifest_rejects_invalid_yaml(tmp_path):
    path = _write(tmp_path, "controls: {this is: : broken")
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_load_manifest_rejects_non_mapping_top_level(tmp_path):
    path = _write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_load_manifest_rejects_missing_controls_key(tmp_path):
    path = _write(tmp_path, "something_else: 1\n")
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_load_manifest_rejects_non_mapping_entry(tmp_path):
    path = _write(tmp_path, 'controls:\n  "7.2.4": "just a string"\n')
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_load_manifest_rejects_unknown_status(tmp_path):
    path = _write(
        tmp_path,
        'controls:\n  "7.2.4": {status: maybe, note: "typo in status"}\n',
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_load_manifest_rejects_missing_note(tmp_path):
    # Every entry needs a note; an n-a with no justification is exactly what the
    # loud-rejection guard exists to catch.
    path = _write(tmp_path, 'controls:\n  "11": {status: n-a}\n')
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_load_manifest_rejects_blank_note(tmp_path):
    path = _write(
        tmp_path,
        'controls:\n  "7.2.4": {status: expected, note: "   "}\n',
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_load_manifest_rejects_duplicate_control_ids(tmp_path):
    # PyYAML's default silently keeps the last duplicate key, which could flip a
    # control's status (expected -> n-a) unnoticed in a bad merge. The custom
    # loader must reject it so the "fails loudly" guarantee actually holds.
    path = _write(
        tmp_path,
        'controls:\n'
        '  "7.2.4": {status: expected, note: "first"}\n'
        '  "7.2.4": {status: n-a, note: "second"}\n',
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


# ---------------------------------------------------------------------------
# build_manifest_view -- the set-difference
# ---------------------------------------------------------------------------

def test_expected_but_untagged_control_is_not_covered():
    manifest = {"7.2.4": {"status": "expected", "note": "session rotation"}}
    # asvs_view has no 7.2.4 -> the harness asserts a probe but none is tagged.
    view = build_manifest_view(manifest, asvs_view={})
    assert view["7.2.4"]["status"] == "not_covered"
    assert view["7.2.4"]["manifest_status"] == "expected"
    assert view["7.2.4"]["note"] == "session rotation"


def test_na_control_is_not_applicable_and_carries_justification():
    manifest = {"11": {"status": "n-a", "note": "internal crypto"}}
    view = build_manifest_view(manifest, asvs_view={})
    assert view["11"]["status"] == "not_applicable"
    assert view["11"]["note"] == "internal crypto"


def test_tagged_control_passes_through_its_rollup_status():
    manifest = {
        "7.2.4": {"status": "expected", "note": "session rotation"},
        "8.2.3": {"status": "expected", "note": "BOPLA"},
    }
    asvs_view = {
        "7.2.4": {"status": "covered_passing"},
        "8.2.3": {"status": "covered_failing"},
    }
    view = build_manifest_view(manifest, asvs_view)
    assert view["7.2.4"]["status"] == "covered_passing"
    assert view["8.2.3"]["status"] == "covered_failing"


def test_skip_is_not_coverage_passes_through_as_skipped():
    # A control whose only probes skipped must render skipped, never covered, and
    # must not be credited as satisfying its expected assertion.
    manifest = {"14.2.1": {"status": "expected", "note": "no data in URL"}}
    asvs_view = {"14.2.1": {"status": "skipped"}}
    view = build_manifest_view(manifest, asvs_view)
    assert view["14.2.1"]["status"] == "skipped"


def test_na_control_that_is_actually_tagged_reports_reality():
    # Presence in the ASVS view wins: if something marked n-a nonetheless has a
    # tagged probe, report its real status rather than hiding it as N/A.
    manifest = {"4.3": {"status": "n-a", "note": "GraphQL absent"}}
    asvs_view = {"4.3": {"status": "covered_passing"}}
    view = build_manifest_view(manifest, asvs_view)
    assert view["4.3"]["status"] == "covered_passing"


def test_manifest_view_is_naturally_ordered():
    manifest = {
        "15.3.2": {"status": "expected", "note": "x"},
        "2.3.1": {"status": "expected", "note": "x"},
        "11": {"status": "n-a", "note": "x"},
    }
    view = build_manifest_view(manifest, asvs_view={})
    assert list(view.keys()) == ["2.3.1", "11", "15.3.2"]


def test_summarize_manifest_view_counts_resolved_statuses():
    view = {
        "a": {"status": "not_covered"},
        "b": {"status": "not_applicable"},
        "c": {"status": "covered_passing"},
        "d": {"status": "covered_passing"},
    }
    assert summarize_manifest_view(view) == {
        "not_covered": 1,
        "not_applicable": 1,
        "covered_passing": 2,
    }


# ---------------------------------------------------------------------------
# attach_manifest_view -- graceful degradation + happy wiring
# ---------------------------------------------------------------------------

def test_attach_missing_manifest_degrades_gracefully(tmp_path, capsys):
    ledger = {"asvs": {"7.2.4": {"status": "covered_passing"}}, "summary": {"asvs": {}}}
    attach_manifest_view(ledger, manifest_path=tmp_path / "nope.yaml")
    # No manifest view attached, no crash, and a warning was emitted.
    assert "manifest" not in ledger
    assert "manifest" not in ledger["summary"]
    assert "[warn]" in capsys.readouterr().err


def test_attach_malformed_manifest_is_warn_only(tmp_path, capsys):
    # A malformed (committed) manifest must NOT crash the ledger -- warn + skip.
    path = _write(tmp_path, 'controls:\n  "7.2.4": {status: bogus, note: "x"}\n')
    ledger = {"asvs": {}, "summary": {"asvs": {}}}
    attach_manifest_view(ledger, manifest_path=path)  # must not raise
    assert "manifest" not in ledger
    assert "[warn]" in capsys.readouterr().err


def test_attach_non_utf8_manifest_is_warn_only(tmp_path, capsys):
    # A committed manifest with invalid UTF-8 bytes must degrade gracefully too:
    # read_text raises UnicodeDecodeError (a ValueError, not OSError), which the
    # warn-only catch must still absorb rather than crash the ledger.
    path = tmp_path / "manifest.yaml"
    path.write_bytes(b"controls:\n  \xff\xfe: {status: expected, note: bad}\n")
    ledger = {"asvs": {}, "summary": {"asvs": {}}}
    attach_manifest_view(ledger, manifest_path=path)  # must not raise
    assert "manifest" not in ledger
    assert "[warn]" in capsys.readouterr().err


def test_attach_valid_manifest_adds_view_and_summary(tmp_path):
    path = _write(
        tmp_path,
        'controls:\n'
        '  "7.2.4": {status: expected, note: "rotation"}\n'
        '  "9.9.9": {status: expected, note: "never tagged"}\n'
        '  "11": {status: n-a, note: "internal crypto"}\n',
    )
    ledger = {"asvs": {"7.2.4": {"status": "covered_passing"}}, "summary": {"asvs": {}}}
    attach_manifest_view(ledger, manifest_path=path)
    assert ledger["manifest"]["7.2.4"]["status"] == "covered_passing"
    assert ledger["manifest"]["9.9.9"]["status"] == "not_covered"
    assert ledger["manifest"]["11"]["status"] == "not_applicable"
    assert ledger["summary"]["manifest"] == {
        "covered_passing": 1,
        "not_covered": 1,
        "not_applicable": 1,
    }


# ---------------------------------------------------------------------------
# The committed manifest that ships with the harness must itself be valid.
# ---------------------------------------------------------------------------

def test_ledger_main_attaches_manifest_view_end_to_end(tmp_path):
    # Drive the wired seam in reports.ledger.main(): a real CLI run must emit the
    # manifest view (from the committed DEFAULT_MANIFEST_PATH) into the ledger
    # JSON. 7.2.4 is tagged+passed -> pass-through; a purely-manifest expected id
    # with no probe stays not_covered; an n-a exclusion stays not_applicable.
    import json

    from reports.ledger import main, sidecar_path_for, write_sidecar

    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"tests": [{"nodeid": "t::sess", "outcome": "passed"}]}),
        encoding="utf-8",
    )
    write_sidecar({"t::sess": {"asvs": ["7.2.4"], "cwe": []}}, sidecar_path_for(report))
    out = tmp_path / "ledger.json"

    assert main(["--pytest-report", str(report), "--output", str(out)]) == 0

    ledger = json.loads(out.read_text(encoding="utf-8"))
    manifest = ledger["manifest"]
    assert manifest["7.2.4"]["status"] == "covered_passing"  # tagged + passed
    assert manifest["14.2.1"]["status"] == "not_covered"     # expected, untagged
    assert manifest["11"]["status"] == "not_applicable"      # justified exclusion
    assert "manifest" in ledger["summary"]


def test_ledger_main_summary_surfaces_manifest_states(tmp_path, capsys):
    import json

    from reports.ledger import main, sidecar_path_for, write_sidecar

    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"tests": [{"nodeid": "t::sess", "outcome": "passed"}]}),
        encoding="utf-8",
    )
    write_sidecar({"t::sess": {"asvs": ["7.2.4"], "cwe": []}}, sidecar_path_for(report))

    assert main(["--pytest-report", str(report)]) == 0

    text = capsys.readouterr().out
    assert "Expected-controls manifest" in text
    assert "not covered (no tagged probe)" in text
    assert "14.2.1" in text
    assert "11" in text


def test_committed_manifest_loads_and_is_well_formed():
    manifest = load_manifest(DEFAULT_MANIFEST_PATH)
    assert manifest, "committed manifest must not be empty"
    for control_id, entry in manifest.items():
        assert entry["status"] in ("expected", "n-a")
        assert entry["note"].strip()
        # ids match the @pytest.mark.asvs tag form: dotted, no "V" prefix.
        assert not control_id.upper().startswith("V")


def test_committed_manifest_accounts_for_every_asvs_tag_in_tests():
    # Reconcile asserted vs observed: every @pytest.mark.asvs("id") tagged on a
    # probe must be listed (as `expected`) in the committed manifest. This is the
    # guard that would have caught the 10.4.x / 4.1.5 omissions -- without it the
    # manifest can silently drift out of sync with what the harness actually probes.
    import re

    tag_re = re.compile(r'@pytest\.mark\.asvs\("([^"]+)"\)')
    tagged: set[str] = set()
    for path in (_PKG_ROOT / "tests").glob("test_*.py"):
        if path.name == "test_manifest.py":
            continue  # this file mentions the tag form in a comment, not a real tag
        tagged.update(tag_re.findall(path.read_text(encoding="utf-8")))
    assert tagged, "expected to find some asvs-tagged probes"

    manifest = load_manifest(DEFAULT_MANIFEST_PATH)
    missing = sorted(t for t in tagged if t not in manifest)
    assert not missing, f"tagged ASVS ids absent from the manifest: {missing}"
    for tag in tagged:
        assert manifest[tag]["status"] == "expected", f"{tag} tagged but marked n-a"
