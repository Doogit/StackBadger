"""Expected-controls manifest -> ledger ``not_covered`` / ``not_applicable``.

The marker sidecar (see ``reports/ledger.py``) indexes only the ASVS controls
that ARE tagged on a probe, so the coverage ledger can classify a control only
when it has at least one tagged pytest node. Two of the five §2 ledger states
cannot be expressed from tags alone and are computed here by SET-DIFFERENCE of a
static, committed expected-controls manifest against the ASVS ids the ledger
actually observed:

  - ``not_covered``     -- a control the harness ASSERTS it should probe, but
                           which has zero tagged nodes (a probe was never written
                           or its tag was dropped -- a coverage regression).
  - ``not_applicable``  -- a control deliberately excluded from this black-box
                           harness by written justification (internal crypto,
                           absent stack surface, ...).

Invariant preserved: a skip is NOT coverage. A manifest control whose only probes
skipped carries the ledger's own ``skipped`` status here, never ``covered`` -- an
observed control always reports its real rollup status (presence in the ledger's
ASVS view wins over the manifest's ``expected``/``n-a`` default).

The loader fails LOUDLY (raises :class:`ManifestError`) on a malformed manifest,
mirroring the exit-3 infra-error discipline in ``reports/ledger.py``. The ledger
CLI wires this in as a WARN-ONLY add-on (:func:`attach_manifest_view`): a missing
or malformed manifest degrades gracefully to "no manifest view" -- it never
crashes the ledger and never changes an exit code, so ``run.sh`` needs no change.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml  # PyYAML >=6.0 (declared dep). Safe at module scope: reports.ledger
# imports this module lazily inside main(), so run.sh's `import reports.ledger`
# probe never pays for it.

from reports.ledger import _natural_key  # reuse the shared natural-order sort key

# The committed manifest ships beside this module under reports/data/. Resolved
# from __file__ so it is found regardless of the invocation cwd.
DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent / "data" / "asvs-5.0-manifest.yaml"

_VALID_STATUSES = ("expected", "n-a")


class ManifestError(ValueError):
    """Raised when the expected-controls manifest is present but malformed.

    Distinct from ``FileNotFoundError`` (a missing manifest, handled as graceful
    degradation by :func:`attach_manifest_view`) so a broken *committed* manifest
    surfaces loudly to a direct caller instead of failing silently.
    """


class _NoDuplicateKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of silently keeping
    the last (PyYAML's default). A duplicated control id in a hand-edit or bad
    merge would otherwise collapse two entries into one and could flip a control's
    status (e.g. expected -> n-a) unnoticed -- the exact silent drop the loud
    loader exists to prevent."""


def _construct_mapping_no_dups(loader: yaml.Loader, node: yaml.Node) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in mapping:
            raise ManifestError(f"duplicate control id {key!r} in manifest mapping.")
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


_NoDuplicateKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_dups
)


# ---------------------------------------------------------------------------
# Loader (fails loudly on a malformed manifest)
# ---------------------------------------------------------------------------

def load_manifest(path: str | Path = DEFAULT_MANIFEST_PATH) -> dict[str, dict[str, str]]:
    """Load + validate the expected-controls manifest.

    Returns ``{control_id: {"status": ..., "note": ...}}``. Raises
    ``FileNotFoundError`` if the file is absent and :class:`ManifestError` if it
    is present but not the shape the write-side asserts (bad YAML, duplicate
    keys, wrong shape, unknown status, or a missing justification note).
    """
    raw = Path(path).read_text(encoding="utf-8")  # FileNotFoundError -> caller
    try:
        data = yaml.load(raw, Loader=_NoDuplicateKeyLoader)
    except yaml.YAMLError as exc:
        raise ManifestError(f"manifest {path} is not valid YAML: {exc}") from exc
    return _validate_manifest(data, path)


def _validate_manifest(data: Any, path: str | Path) -> dict[str, dict[str, str]]:
    """Shape-validate the parsed manifest, raising :class:`ManifestError` on any
    deviation so a corrupt committed artifact fails loudly rather than silently
    dropping controls (which would understate excluded/uncovered coverage)."""
    if not isinstance(data, dict):
        raise ManifestError(
            f"manifest {path} must be a mapping, got {type(data).__name__}."
        )
    controls = data.get("controls")
    if not isinstance(controls, dict):
        raise ManifestError(
            f"manifest {path}: top-level 'controls' must be a mapping, "
            f"got {type(controls).__name__}."
        )

    validated: dict[str, dict[str, str]] = {}
    for control_id, entry in controls.items():
        cid = str(control_id)  # YAML may parse a bare numeric-looking key oddly
        if not isinstance(entry, dict):
            raise ManifestError(
                f"manifest {path}: control {cid!r} must be a mapping, "
                f"got {type(entry).__name__}."
            )
        status = entry.get("status")
        if status not in _VALID_STATUSES:
            raise ManifestError(
                f"manifest {path}: control {cid!r} has status {status!r}; "
                f"expected one of {_VALID_STATUSES}."
            )
        note = entry.get("note")
        if not isinstance(note, str) or not note.strip():
            raise ManifestError(
                f"manifest {path}: control {cid!r} needs a non-empty 'note' "
                "(the justification, required for every entry)."
            )
        validated[cid] = {"status": status, "note": note.strip()}
    return validated


# ---------------------------------------------------------------------------
# Set-difference view (pure)
# ---------------------------------------------------------------------------

def build_manifest_view(
    manifest: dict[str, dict[str, str]],
    asvs_view: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Join the manifest against the ledger's ASVS view (both keyed by control id).

    Presence in the observed ASVS view (at least one tagged probe) wins: the
    control carries the ledger's own rollup status (``covered_passing``,
    ``skipped``, ...). A manifest control with no tagged probe becomes
    ``not_covered`` (manifest status ``expected``) or ``not_applicable``
    (manifest status ``n-a``); the justification note is carried through in both.
    """
    view: dict[str, dict[str, Any]] = {}
    for control_id in sorted(manifest, key=_natural_key):
        entry = manifest[control_id]
        observed = asvs_view.get(control_id)
        if observed is not None:
            status = observed["status"]
        elif entry["status"] == "n-a":
            status = "not_applicable"
        else:
            status = "not_covered"
        view[control_id] = {
            "status": status,
            "manifest_status": entry["status"],
            "note": entry["note"],
        }
    return view


def summarize_manifest_view(view: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Count controls per resolved status (mirrors ledger._summarize's intent)."""
    summary: dict[str, int] = {}
    for entry in view.values():
        summary[entry["status"]] = summary.get(entry["status"], 0) + 1
    return summary


# ---------------------------------------------------------------------------
# Ledger wiring (warn-only add-on)
# ---------------------------------------------------------------------------

def attach_manifest_view(
    ledger: dict[str, Any],
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> None:
    """Add ``ledger['manifest']`` + ``ledger['summary']['manifest']`` in place.

    Warn-only: a missing OR malformed manifest prints a single loud warning to
    stderr and leaves the ledger untouched. It never raises and never changes an
    exit code, so the run.sh coverage-ledger step needs no change.
    """
    try:
        manifest = load_manifest(manifest_path)
    except FileNotFoundError:
        print(
            f"[warn] Expected-controls manifest not found at {manifest_path}; "
            "skipping manifest coverage view.",
            file=sys.stderr,
        )
        return
    except (ManifestError, UnicodeDecodeError, OSError) as exc:
        # ManifestError = bad shape/YAML; UnicodeDecodeError = non-UTF-8 bytes
        # (a ValueError, not an OSError); OSError = unreadable file. All three
        # are "malformed manifest" -> degrade gracefully, never crash the ledger.
        print(
            f"[warn] Expected-controls manifest unusable ({exc}); "
            "skipping manifest coverage view.",
            file=sys.stderr,
        )
        return

    view = build_manifest_view(manifest, ledger.get("asvs", {}))
    ledger["manifest"] = view
    ledger.setdefault("summary", {})["manifest"] = summarize_manifest_view(view)
