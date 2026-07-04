"""Offline unit tests for reports.crosswalk (ASVS-5.0 -> 4.0.3 crosswalk).

Pure-function tests plus ledger integration. No live target. Synthetic mapping /
dropped YAML is written to tmp_path; a few tests exercise the real vendored data
under reports/data/ to keep the committed artifacts honest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from reports import crosswalk  # noqa: E402
from reports.crosswalk import (  # noqa: E402
    CrosswalkError,
    augment_ledger,
    load_dropped,
    load_mapping,
    project_asvs4,
    summarize_asvs4,
)
from reports.ledger import main, sidecar_path_for, write_sidecar  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


_MAPPING_YAML = """\
---
v5.0.0-6.1.3:
  tag-v4.0.3: MODIFIED, MOVED FROM v4.0.3-1.2.4, COVERS v4.0.3-1.2.3
v5.0.0-6.1.2:
  tag-v4.0.3: ADDED
v5.0.0-8.2.1:
  tag-v4.0.3: MODIFIED, MOVED FROM v4.0.3-1.2.4
"""

_DROPPED_YAML = """\
dropped:
  - id: "1.1.1"
    reason: "not in scope"
  - id: "2.4.2"
    reason: "incorrect"
"""


# ---------------------------------------------------------------------------
# load_mapping
# ---------------------------------------------------------------------------

def test_load_mapping_strips_prefixes_dedups_and_handles_added(tmp_path):
    mapping = load_mapping(_write(tmp_path / "m.yml", _MAPPING_YAML))
    # Prefixes stripped; multiple 4.0.3 ids extracted in order.
    assert mapping["6.1.3"] == ["1.2.4", "1.2.3"]
    # ADDED (no 4.0.3 ancestor) -> empty list, not an error.
    assert mapping["6.1.2"] == []
    assert mapping["8.2.1"] == ["1.2.4"]


def test_load_mapping_rejects_non_mapping_top_level(tmp_path):
    with pytest.raises(CrosswalkError):
        load_mapping(_write(tmp_path / "m.yml", "- just\n- a\n- list\n"))


def test_load_mapping_rejects_entry_without_tag(tmp_path):
    with pytest.raises(CrosswalkError):
        load_mapping(_write(tmp_path / "m.yml", "v5.0.0-6.1.3:\n  note: no tag here\n"))


def test_load_mapping_rejects_invalid_yaml(tmp_path):
    with pytest.raises(CrosswalkError):
        load_mapping(_write(tmp_path / "m.yml", "key: : : not yaml\n  - broken"))


def test_load_mapping_rejects_unreadable_path(tmp_path):
    # A path that exists() reports True but cannot be read as a UTF-8 text file
    # (here: a directory) must fail loud with CrosswalkError, not a bare OSError
    # escaping the exit-3 contract.
    with pytest.raises(CrosswalkError):
        load_mapping(tmp_path)  # a directory -> read_text raises OSError


def test_load_mapping_rejects_non_utf8_bytes(tmp_path):
    # A present-but-undecodable file (git corruption / wrong filters) must map to
    # CrosswalkError, not escape as a bare UnicodeDecodeError past the exit-3 gate.
    bad = tmp_path / "m.yml"
    bad.write_bytes(b"\xff\xfe not utf-8")
    with pytest.raises(CrosswalkError):
        load_mapping(bad)


# ---------------------------------------------------------------------------
# load_dropped
# ---------------------------------------------------------------------------

def test_load_dropped_parses_id_and_reason(tmp_path):
    dropped = load_dropped(_write(tmp_path / "d.yml", _DROPPED_YAML))
    assert dropped == [
        {"id": "1.1.1", "reason": "not in scope"},
        {"id": "2.4.2", "reason": "incorrect"},
    ]


def test_load_dropped_rejects_missing_list(tmp_path):
    with pytest.raises(CrosswalkError):
        load_dropped(_write(tmp_path / "d.yml", "not_dropped: []\n"))


def test_load_dropped_rejects_malformed_entry(tmp_path):
    with pytest.raises(CrosswalkError):
        load_dropped(_write(tmp_path / "d.yml", 'dropped:\n  - id: "1.1.1"\n'))  # no reason


def test_load_dropped_rejects_non_utf8_bytes(tmp_path):
    bad = tmp_path / "d.yml"
    bad.write_bytes(b"\xff\xfe not utf-8")
    with pytest.raises(CrosswalkError):
        load_dropped(bad)


# ---------------------------------------------------------------------------
# project_asvs4
# ---------------------------------------------------------------------------

def test_projection_carries_status_onto_successors():
    asvs5 = {"6.1.3": {"status": "covered_passing"}}
    mapping = {"6.1.3": ["1.2.4", "1.2.3"]}
    view = project_asvs4(asvs5, mapping)
    assert view["1.2.4"]["status"] == "covered_passing"
    assert view["1.2.3"]["status"] == "covered_passing"
    assert view["1.2.4"]["from_asvs5"] == ["6.1.3"]


def test_projection_rolls_up_finding_over_passing_for_shared_req():
    # Two 5.0 controls both map to 4.0.3 1.2.4: one passing, one failing. The 4.0.3
    # requirement takes the higher-precedence (finding) status, and lists both.
    asvs5 = {
        "6.1.3": {"status": "covered_passing"},
        "8.2.1": {"status": "covered_failing"},
    }
    mapping = {"6.1.3": ["1.2.4"], "8.2.1": ["1.2.4"]}
    entry = project_asvs4(asvs5, mapping)["1.2.4"]
    assert entry["status"] == "covered_failing"
    assert entry["from_asvs5"] == ["6.1.3", "8.2.1"]


def test_projection_omits_five_zero_control_with_no_successor():
    # An ADDED 5.0 control (no 4.0.3 ancestor) contributes nothing to the 4.0 view.
    asvs5 = {"6.1.2": {"status": "covered_passing"}}
    mapping = {"6.1.2": []}
    assert project_asvs4(asvs5, mapping) == {}


def test_projection_ignores_untagged_five_zero_controls():
    # Only the ledger's tagged 5.0 universe is projected: a mapping entry whose 5.0
    # control is absent from the ledger view is not invented into the 4.0 view.
    asvs5 = {"6.1.3": {"status": "skipped"}}
    mapping = {"6.1.3": ["1.2.4"], "8.2.1": ["9.9.9"]}
    view = project_asvs4(asvs5, mapping)
    assert set(view) == {"1.2.4"}
    assert view["1.2.4"]["status"] == "skipped"


def test_projection_is_naturally_ordered():
    asvs5 = {"a": {"status": "not_run"}}
    mapping = {"a": ["1.10.1", "1.2.4", "2.1.1"]}
    assert list(project_asvs4(asvs5, mapping)) == ["1.2.4", "1.10.1", "2.1.1"]


def test_summarize_asvs4_counts_by_status():
    view = {
        "1.2.4": {"status": "covered_passing"},
        "1.2.3": {"status": "covered_failing"},
        "2.1.1": {"status": "covered_passing"},
    }
    summary = summarize_asvs4(view)
    assert summary["covered_passing"] == 2
    assert summary["covered_failing"] == 1
    assert summary["not_run"] == 0


# ---------------------------------------------------------------------------
# augment_ledger
# ---------------------------------------------------------------------------

def test_augment_ledger_adds_views_from_explicit_paths(tmp_path):
    ledger = {"asvs": {"6.1.3": {"status": "covered_failing"}}}
    augment_ledger(
        ledger,
        mapping_path=_write(tmp_path / "m.yml", _MAPPING_YAML),
        dropped_path=_write(tmp_path / "d.yml", _DROPPED_YAML),
    )
    assert ledger["asvs4"]["1.2.4"]["status"] == "covered_failing"
    assert ledger["asvs4_dropped"] == [
        {"id": "1.1.1", "reason": "not in scope"},
        {"id": "2.4.2", "reason": "incorrect"},
    ]


def test_augment_ledger_missing_data_warns_and_skips(tmp_path, capsys):
    # One file present, one absent still skips cleanly (the realistic partial case):
    # no keys added, a warning is emitted, no exception, so run.sh is unaffected.
    ledger = {"asvs": {"6.1.3": {"status": "covered_passing"}}}
    augment_ledger(
        ledger,
        mapping_path=_write(tmp_path / "m.yml", _MAPPING_YAML),  # present
        dropped_path=tmp_path / "absent-dropped.yml",  # never created
    )
    assert "asvs4" not in ledger and "asvs4_dropped" not in ledger
    assert "crosswalk data absent" in capsys.readouterr().err


def test_augment_ledger_malformed_data_raises(tmp_path):
    ledger = {"asvs": {"6.1.3": {"status": "covered_passing"}}}
    with pytest.raises(CrosswalkError):
        augment_ledger(
            ledger,
            mapping_path=_write(tmp_path / "m.yml", "- not a mapping\n"),
            dropped_path=_write(tmp_path / "d.yml", _DROPPED_YAML),
        )


# ---------------------------------------------------------------------------
# Vendored data + ledger end-to-end
# ---------------------------------------------------------------------------

def test_vendored_dropped_supplement_has_43_entries():
    dropped = load_dropped(crosswalk.DEFAULT_DROPPED_PATH)
    assert len(dropped) == 43
    reasons = {d["reason"] for d in dropped}
    assert reasons == {"not in scope", "insufficient impact", "incorrect"}


def test_vendored_dropped_excludes_not_practical_requirements():
    # Pin the deliberate exclusion (README / dropped.yaml header): the 7 terminal
    # "DELETED, NOT PRACTICAL" 4.0.3 requirements are NOT in the canonical-43 set,
    # so a regeneration that folded them in would flip this test.
    ids = {d["id"] for d in load_dropped(crosswalk.DEFAULT_DROPPED_PATH)}
    not_practical = {"8.3.6", "10.2.1", "10.2.2", "10.2.3", "10.2.4", "10.2.5", "10.2.6"}
    assert ids.isdisjoint(not_practical)


def test_vendored_dropped_matches_reverse_map_terminal_deletes():
    # Drift guard: the supplement must be EXACTLY the terminal `DELETED, <REASON>`
    # entries of the vendored reverse map for the three canonical reasons — no
    # invented ids, and no leakage of DELETED-but-MERGED/COVERED/DEPRECATED entries
    # (which DO have a 5.0 successor). Keeps a future regeneration honest.
    reverse = yaml.safe_load(
        (_PKG_ROOT / "reports" / "data" / "mapping_v4.0.3_to_v5.0.0.yml").read_text(
            encoding="utf-8"
        )
    )
    terminal = {"NOT IN SCOPE", "INSUFFICIENT IMPACT", "INCORRECT"}
    expected = set()
    for key, entry in reverse.items():
        tag = entry["tag-v5.0.0"].strip()
        if tag.startswith("DELETED,") and tag[len("DELETED,"):].strip() in terminal:
            expected.add(key.split("v4.0.3-", 1)[-1])

    supplement = {d["id"] for d in load_dropped(crosswalk.DEFAULT_DROPPED_PATH)}
    assert supplement == expected


def test_vendored_mapping_projects_a_known_pair():
    mapping = load_mapping(crosswalk.DEFAULT_MAPPING_PATH)
    # OWASP: v5.0.0-6.1.3 MOVED FROM v4.0.3-1.2.4, COVERS v4.0.3-1.2.3.
    assert mapping["6.1.3"] == ["1.2.4", "1.2.3"]


def test_ledger_main_emits_asvs4_from_committed_data(tmp_path, capsys):
    # End-to-end: a probe tagged with a real 5.0 id projects onto its 4.0.3
    # successors using the committed default mapping (no explicit paths).
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"tests": [{"nodeid": "t::a", "outcome": "passed"}]}),
        encoding="utf-8",
    )
    write_sidecar({"t::a": {"asvs": ["6.1.3"], "cwe": []}}, sidecar_path_for(report))
    out = tmp_path / "ledger.json"

    rc = main(["--pytest-report", str(report), "--output", str(out)])

    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["asvs4"]["1.2.4"]["status"] == "covered_passing"
    assert data["asvs4"]["1.2.3"]["status"] == "covered_passing"
    assert len(data["asvs4_dropped"]) == 43
    # The CLI summary renders the crosswalk block.
    assert "ASVS 4.0.3 crosswalk" in capsys.readouterr().out


def test_ledger_main_maps_malformed_crosswalk_to_infra_exit(tmp_path, monkeypatch):
    # The ledger.py seam must map a malformed committed data file to the exit-3
    # infra code (not a crash), exactly like a malformed sidecar/report.
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"tests": [{"nodeid": "t::a", "outcome": "passed"}]}), encoding="utf-8"
    )
    write_sidecar({"t::a": {"asvs": ["6.1.3"], "cwe": []}}, sidecar_path_for(report))
    bad_mapping = tmp_path / "bad-mapping.yml"
    bad_mapping.write_text("- not a mapping\n", encoding="utf-8")
    monkeypatch.setattr(crosswalk, "DEFAULT_MAPPING_PATH", bad_mapping)

    assert main(["--pytest-report", str(report)]) == 3


def test_ledger_main_maps_malformed_dropped_data_to_infra_exit(tmp_path, monkeypatch):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"tests": [{"nodeid": "t::a", "outcome": "passed"}]}), encoding="utf-8"
    )
    write_sidecar({"t::a": {"asvs": ["6.1.3"], "cwe": []}}, sidecar_path_for(report))
    bad_dropped = tmp_path / "bad-dropped.yml"
    bad_dropped.write_bytes(b"\xff\xfe not utf-8")
    monkeypatch.setattr(crosswalk, "DEFAULT_DROPPED_PATH", bad_dropped)

    assert main(["--pytest-report", str(report)]) == 3
