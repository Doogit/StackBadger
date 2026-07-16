"""Offline unit tests for scripts/pip_audit_allowlist.py (the SCA gate wrapper).

Pure-function tests for the allowlist parser plus main()'s exit-code wiring.
No live target and no real pip-audit: main()'s subprocess call is monkeypatched
so the exit-code passthrough is asserted without a network audit. The parser's
expiry logic is the whole point of the wrapper, so its boundary and
malformed-line branches are pinned here to catch a future regression that would
otherwise only surface as a misbehaving CI run.
"""

from __future__ import annotations

import datetime
import importlib.util
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parent.parent
_WRAPPER_PATH = _PKG_ROOT / "scripts" / "pip_audit_allowlist.py"

# scripts/ is not a package; load the module by path.
_spec = importlib.util.spec_from_file_location("pip_audit_allowlist", _WRAPPER_PATH)
assert _spec and _spec.loader
w = importlib.util.module_from_spec(_spec)
sys.modules["pip_audit_allowlist"] = w
_spec.loader.exec_module(w)

TODAY = datetime.date(2026, 7, 15)


# ---------------------------------------------------------------------------
# parse_allowlist — comments / blanks / survivors
# ---------------------------------------------------------------------------

def test_parse_skips_comments_and_blanks():
    text = "# a full-line comment\n\n   \n# expires:2099-01-01 not an entry\n"
    assert w.parse_allowlist(text, TODAY) == []


def test_parse_keeps_future_expiry():
    text = "GHSA-xxxx-yyyy-zzzz  # expires:2099-12-31 — accepted pending upstream fix"
    assert w.parse_allowlist(text, TODAY) == ["GHSA-xxxx-yyyy-zzzz"]


def test_parse_accepts_pysec_and_cve_id_shapes():
    text = "PYSEC-2024-1  # expires:2099-01-01 x\nCVE-2026-0001  # expires:2099-01-01 y"
    assert w.parse_allowlist(text, TODAY) == ["PYSEC-2024-1", "CVE-2026-0001"]


def test_parse_separator_char_is_optional():
    # The documented format uses an em-dash, but the regex tail is `.*`, so a
    # plain-text justification with no separator is still valid.
    text = "GHSA-a  # expires:2099-01-01 accepted, no dash separator"
    assert w.parse_allowlist(text, TODAY) == ["GHSA-a"]


# ---------------------------------------------------------------------------
# parse_allowlist — expiry boundary (the load-bearing behavior)
# ---------------------------------------------------------------------------

def test_parse_drops_past_expiry():
    text = "PYSEC-2024-1  # expires:2026-01-01 — accepted pending upstream fix"
    assert w.parse_allowlist(text, TODAY) == []


def test_parse_drops_entry_expiring_today():
    # expires <= today: an entry expiring today is no longer suppressed.
    text = "CVE-2026-0001  # expires:2026-07-15 — accepted"
    assert w.parse_allowlist(text, TODAY) == []


def test_parse_mixed_keeps_future_drops_past():
    text = (
        "GHSA-keep  # expires:2099-01-01 — accepted\n"
        "GHSA-drop  # expires:2026-01-01 — accepted\n"
    )
    assert w.parse_allowlist(text, TODAY) == ["GHSA-keep"]


# ---------------------------------------------------------------------------
# parse_allowlist — malformed lines fail loud
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad",
    [
        "GHSA-no-comment",                          # no '# expires:' comment
        "GHSA-x  # no expires token here",          # comment without expires:
        "GHSA-x # expires:20991231 no dashes",      # wrong date format
        "GHSA-x # expires:2099-1-1 short fields",   # non-zero-padded date
    ],
)
def test_parse_malformed_line_raises(bad):
    with pytest.raises(w.AllowlistError):
        w.parse_allowlist(bad, TODAY)


def test_parse_regex_valid_but_invalid_calendar_date_raises():
    # Matches the YYYY-MM-DD shape but is not a real date -> fromisoformat trips.
    with pytest.raises(w.AllowlistError):
        w.parse_allowlist("GHSA-x  # expires:2099-13-45 — bad", TODAY)


# ---------------------------------------------------------------------------
# build_args
# ---------------------------------------------------------------------------

def test_build_args_empty_has_no_ignore_flags():
    assert w.build_args([]) == ["pip-audit", "--strict"]


def test_build_args_expands_one_ignore_vuln_per_id():
    assert w.build_args(["A", "B"]) == [
        "pip-audit", "--strict",
        "--ignore-vuln", "A",
        "--ignore-vuln", "B",
    ]


# ---------------------------------------------------------------------------
# main — file handling + exit-code wiring (subprocess monkeypatched)
# ---------------------------------------------------------------------------

class _FakeCompleted:
    def __init__(self, returncode):
        self.returncode = returncode


def test_main_missing_allowlist_returns_2(tmp_path, capsys):
    missing = tmp_path / "nope.txt"
    assert w.main(["--allowlist", str(missing)]) == 2
    assert "not found" in capsys.readouterr().err


def test_main_malformed_allowlist_returns_2(tmp_path, capsys):
    bad = tmp_path / "bad.txt"
    bad.write_text("GHSA-no-comment\n", encoding="utf-8")
    assert w.main(["--allowlist", str(bad)]) == 2


def test_main_propagates_pip_audit_exit_code(tmp_path, monkeypatch):
    empty = tmp_path / "al.txt"
    empty.write_text("# header only\n", encoding="utf-8")

    captured = {}

    def fake_run(cmd, check):
        captured["cmd"] = cmd
        return _FakeCompleted(1)

    monkeypatch.setattr(w.subprocess, "run", fake_run)
    assert w.main(["--allowlist", str(empty)]) == 1
    # Empty allowlist -> no suppression args passed to pip-audit.
    assert captured["cmd"] == ["pip-audit", "--strict"]


def test_main_passes_unexpired_id_to_pip_audit(tmp_path, monkeypatch):
    al = tmp_path / "al.txt"
    al.write_text("GHSA-keep  # expires:2099-01-01 — accepted\n", encoding="utf-8")

    captured = {}

    def fake_run(cmd, check):
        captured["cmd"] = cmd
        return _FakeCompleted(0)

    monkeypatch.setattr(w.subprocess, "run", fake_run)
    assert w.main(["--allowlist", str(al)]) == 0
    assert captured["cmd"] == [
        "pip-audit", "--strict", "--ignore-vuln", "GHSA-keep",
    ]
