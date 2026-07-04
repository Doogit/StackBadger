"""ASVS-4.0 crosswalk view (Tier-2, scope=asvs).

The coverage ledger (``reports/ledger.py``) is authored against **ASVS 5.0** —
probes carry ``@pytest.mark.asvs(<5.0 id>)`` tags. CASA / Tier-2 assessments may
still grade against **ASVS 4.0.3**, so this module projects the ledger's 5.0
coverage onto its 4.0.3 successors using OWASP's own version mapping, and surfaces
the "43-dropped supplement" — the 4.0.3 requirements that have no 5.0 successor and
therefore cannot be covered by any 5.0-authored probe.

Data (committed, offline; see ``reports/data/README.md`` for provenance/licence):
  - ``mapping_v5.0.0_to_v4.0.3.yml`` — OWASP forward map keyed by 5.0 id. Each 5.0
    control lists the 4.0.3 requirement(s) it descends from (``MOVED FROM`` /
    ``MERGED FROM`` / ``SPLIT FROM`` / ``COVERS`` / ``DEPRECATES``). The projection
    reads these to know which 4.0.3 requirement(s) a tagged 5.0 control covers.
  - ``asvs-4.0-dropped.yaml`` — the static 43-dropped checklist (id + drop reason),
    derived from OWASP's reverse map. Emitted as-is; not run-dependent.

This is coverage accounting only: it never touches findings or the run.sh exit
gate. Discipline mirrors the ledger — a *malformed* data file fails LOUDLY (the
caller maps ``CrosswalkError`` to the exit-3 infra code), but a simply *absent*
data file degrades to a warning + skip so run.sh needs no change.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

# Committed default data paths (beside this module, in reports/data/).
_DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_MAPPING_PATH = _DATA_DIR / "mapping_v5.0.0_to_v4.0.3.yml"
DEFAULT_DROPPED_PATH = _DATA_DIR / "asvs-4.0-dropped.yaml"

# Matches a 4.0.3 requirement id embedded in a forward-mapping tag string, e.g.
# "MODIFIED, MOVED FROM v4.0.3-2.1.1" -> "2.1.1".
_V4_ID_RE = re.compile(r"v4\.0\.3-(\d+(?:\.\d+)*)")

# Precedence (highest first) for rolling several 5.0 controls that map to the SAME
# 4.0.3 requirement into one status. A finding is surfaced first; positive coverage
# outranks partial/absent evidence. Any status not listed sorts last (least
# informative), so an unexpected value can never mask a real finding.
_STATUS_PRECEDENCE = (
    "covered_failing",
    "covered_passing",
    "incomplete",
    "skipped",
    "not_run",
)


class CrosswalkError(Exception):
    """A vendored crosswalk data file is present but malformed.

    Raised for shape violations only (not a missing file); the ledger CLI maps it
    to the exit-3 infra code, exactly as it does for a malformed sidecar/report.
    """


# ---------------------------------------------------------------------------
# Loaders (raise CrosswalkError on a present-but-malformed file)
# ---------------------------------------------------------------------------

def load_mapping(path: str | Path) -> dict[str, list[str]]:
    """Load the OWASP forward map into ``{5.0 id -> [4.0.3 id, ...]}``.

    Keys are stripped of the ``v5.0.0-`` prefix to match the ledger's bare tag ids;
    each value is the ordered, de-duplicated set of 4.0.3 ids named in the entry's
    ``tag-v4.0.3`` string. A ``5.0`` control that is ``ADDED`` (no 4.0.3 ancestor)
    maps to ``[]``.
    """
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, ValueError) as exc:
        # ValueError covers UnicodeDecodeError; OSError a path that exists() but is
        # a directory/unreadable. All map to the exit-3 infra contract, not a crash.
        raise CrosswalkError(f"Crosswalk mapping {path} is unreadable/not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise CrosswalkError(
            f"Crosswalk mapping {path} is malformed: expected a mapping, got "
            f"{type(data).__name__}."
        )
    mapping: dict[str, list[str]] = {}
    for key, entry in data.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("tag-v4.0.3"), str):
            raise CrosswalkError(
                f"Crosswalk mapping {path} is malformed: entry {key!r} must be an "
                "object with a string 'tag-v4.0.3' field."
            )
        five_id = str(key).split("v5.0.0-", 1)[-1]
        four_ids: list[str] = []
        for four_id in _V4_ID_RE.findall(entry["tag-v4.0.3"]):
            if four_id not in four_ids:
                four_ids.append(four_id)
        mapping[five_id] = four_ids
    return mapping


def load_dropped(path: str | Path) -> list[dict[str, str]]:
    """Load the static 43-dropped supplement into ``[{'id', 'reason'}, ...]``."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, ValueError) as exc:
        # Mirror load_mapping(): a present but unreadable/non-UTF-8 dropped file
        # is malformed data and must stay on the exit-3 infra-error path.
        raise CrosswalkError(
            f"Dropped supplement {path} is unreadable/not valid YAML: {exc}"
        ) from exc
    if not isinstance(data, dict) or not isinstance(data.get("dropped"), list):
        raise CrosswalkError(
            f"Dropped supplement {path} is malformed: expected a mapping with a "
            "'dropped' list."
        )
    dropped: list[dict[str, str]] = []
    for item in data["dropped"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or not isinstance(item.get("reason"), str)
        ):
            raise CrosswalkError(
                f"Dropped supplement {path} is malformed: every entry must be an "
                "object with string 'id' and 'reason' fields."
            )
        dropped.append({"id": item["id"], "reason": item["reason"]})
    return dropped


# ---------------------------------------------------------------------------
# Projection (pure)
# ---------------------------------------------------------------------------

def _natural_key(control_id: str) -> tuple:
    """Natural order for dotted 4.0.3 ids ("1.2.4" < "1.10.1" < "2.1.1")."""
    return tuple(
        (0, int(seg)) if seg.isascii() and seg.isdigit() else (1, seg)
        for seg in str(control_id).split(".")
    )


def _rollup_status(statuses: list[str]) -> str:
    """Fold the statuses of every 5.0 control mapping to one 4.0.3 req into one."""
    return min(
        statuses,
        key=lambda s: _STATUS_PRECEDENCE.index(s)
        if s in _STATUS_PRECEDENCE
        else len(_STATUS_PRECEDENCE),
    )


def project_asvs4(
    asvs5_view: dict[str, dict[str, Any]],
    mapping: dict[str, list[str]],
) -> dict[str, dict[str, Any]]:
    """Project the ledger's ASVS-5.0 view onto a 4.0.3 view via the forward map.

    For every 5.0 control the ledger actually tagged, credit its rolled-up status
    to each 4.0.3 requirement it descends from. A 4.0.3 requirement touched by
    several 5.0 controls takes the highest-precedence status among them
    (findings first). Only the tagged 5.0 universe is projected — untagged 5.0
    controls and their 4.0.3 ancestors are simply absent, mirroring the ledger,
    which lists only tagged controls (never-covered accounting is the separate
    expected-controls manifest / dropped supplement, not this projection).
    """
    contributions: dict[str, dict[str, str]] = {}  # 4.0.3 id -> {5.0 id: status}
    for five_id, entry in asvs5_view.items():
        status = entry.get("status", "not_run")
        for four_id in mapping.get(five_id, []):
            contributions.setdefault(four_id, {})[five_id] = status

    view: dict[str, dict[str, Any]] = {}
    for four_id in sorted(contributions, key=_natural_key):
        sources = contributions[four_id]
        view[four_id] = {
            "status": _rollup_status(list(sources.values())),
            "from_asvs5": sorted(sources, key=_natural_key),
        }
    return view


def summarize_asvs4(view: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Count 4.0.3 requirements per status (order follows _STATUS_PRECEDENCE)."""
    summary = {status: 0 for status in _STATUS_PRECEDENCE}
    for entry in view.values():
        summary[entry["status"]] = summary.get(entry["status"], 0) + 1
    return summary


# ---------------------------------------------------------------------------
# Ledger integration
# ---------------------------------------------------------------------------

def augment_ledger(
    ledger: dict[str, Any],
    mapping_path: str | Path | None = None,
    dropped_path: str | Path | None = None,
) -> None:
    """Add ``asvs4`` (crosswalk view) and ``asvs4_dropped`` (supplement) to *ledger*.

    Mutates *ledger* in place. Loads the committed data by default. If either data
    file is simply absent, warns to stderr and returns without touching *ledger*
    (so run.sh needs no new artifact). A present-but-malformed file raises
    ``CrosswalkError`` for the caller to map to exit 3.
    """
    mapping_path = Path(mapping_path or DEFAULT_MAPPING_PATH)
    dropped_path = Path(dropped_path or DEFAULT_DROPPED_PATH)

    missing = [str(p) for p in (mapping_path, dropped_path) if not p.exists()]
    if missing:
        print(
            f"[warn] ASVS-4.0 crosswalk data absent ({', '.join(missing)}); "
            "skipping asvs4 view.",
            file=sys.stderr,
        )
        return

    mapping = load_mapping(mapping_path)
    dropped = load_dropped(dropped_path)
    ledger["asvs4"] = project_asvs4(ledger.get("asvs", {}), mapping)
    ledger["asvs4_dropped"] = dropped
