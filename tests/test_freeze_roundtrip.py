"""Tests that lock the Item 2 (#628) profile-freeze contract.

run.sh now performs a single live discovery crawl, freezes the fully-assembled
profile to a temp YAML via ``yaml.dump(assemble_profile(...).raw())``, then
points ``--profile`` at that artifact with ``PENTEST_PROFILE_FROZEN`` set so the
pytest ``profile`` fixture reloads it instead of crawling a second time. The
whole run therefore depends on two contracts that nothing tested before #628:

1. **Lossless round-trip** — ``assemble_profile(...).raw()`` must survive
   ``yaml.dump`` -> ``load_profile`` without dropping the discovered secrets the
   adapters and ZAP rely on (``stack.auth``, ``target.base_url``,
   ``supabase.anon_key`` / ``clerk.frontend_api`` / ``firebase.api_key``). If a
   key is dropped here, sign-in / ZAP / pytest all break at once.

2. **Freeze path-gate** — the fixture honors the freeze signal ONLY for the
   exact artifact run.sh assembled (``--profile == $PENTEST_PROFILE``). A stale
   ``PENTEST_PROFILE_FROZEN`` left in the shell from a prior run.sh must NOT
   suppress discovery when a developer later runs ``pytest --profile raw.yaml``
   against a different raw profile (the stale-flag bug #628 fixed).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
import yaml

# Ensure the package root is importable regardless of pytest's cwd.
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile  # noqa: E402
from profile_assembler import assemble_profile  # noqa: E402
from providers import ProviderManifest  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A discovered Clerk+Supabase target (no providers manifest -> default stack),
# mirroring the canonical Clerk + Supabase run.
CLERK_DISCOVERED = {
    "supabase_url": "https://abc123.supabase.co",
    "supabase_anon_key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiYzEyMyIsInJvbGUiOiJhbm9uIn0.stub",
    "clerk_publishable_key": "pk_test_Y2xlcmsudGFyaWZmcmVmdW5kZWQuY29tJA==",
    "clerk_fapi_host": "clerk.example.com",
    "api_prefix": "/.netlify/functions",
}

FIREBASE_API_KEY = "AIzaSyAexamplekeyexamplekeyexampleke12"


def _discovered(providers=None, **overrides):
    """Build a discover_live() return dict, optionally carrying a manifest."""
    base = {
        "supabase_url": None,
        "supabase_anon_key": None,
        "clerk_publishable_key": None,
        "clerk_fapi_host": None,
        "api_prefix": None,
    }
    base.update(overrides)
    if providers is not None:
        base["providers"] = providers
    return base


def _freeze_and_reload(profile, tmp_path: Path):
    """Mirror run.sh's freeze step: dump the assembled profile to YAML then
    reload it the way the pytest ``profile`` fixture does."""
    dest = tmp_path / "frozen.yaml"
    dest.write_text(yaml.dump(profile.raw(), sort_keys=False), encoding="utf-8")
    return load_profile(dest)


@pytest.fixture(autouse=True)
def _clear_env_overrides(monkeypatch):
    """Keep a developer's exported credentials from bleeding into assembly."""
    for var in (
        "TARGET_BASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_PROJECT_URL",
        "CLERK_FAPI_HOST", "PENTEST_TARGET_URL",
    ):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# 1. Lossless round-trip
# ---------------------------------------------------------------------------

class TestFreezeRoundTrip:
    """assemble_profile(...).raw() must survive yaml.dump -> load_profile."""

    @mock.patch("profile_assembler.discover_live")
    def test_clerk_stack_round_trips_losslessly(self, mock_discover, tmp_path):
        mock_discover.return_value = dict(CLERK_DISCOVERED)

        assembled = assemble_profile("https://example.com")
        reloaded = _freeze_and_reload(assembled, tmp_path)

        # Discovered secrets the auth adapter / anon client / ZAP depend on.
        assert reloaded.target.base_url == "https://example.com"
        assert reloaded.stack.auth == "clerk"
        assert reloaded.supabase.project_url == CLERK_DISCOVERED["supabase_url"]
        assert reloaded.supabase.anon_key == CLERK_DISCOVERED["supabase_anon_key"]
        assert reloaded.clerk.frontend_api == "clerk.example.com"
        # Strong invariant: nothing at all is lost across the freeze.
        assert reloaded.raw() == assembled.raw()

    @mock.patch("profile_assembler.discover_live")
    def test_firebase_stack_round_trips_losslessly(self, mock_discover, tmp_path):
        mock_discover.return_value = _discovered(
            ProviderManifest(
                auth="firebase",
                database="firestore",
                storage="firebase",
                extracted_config={
                    "firebase_api_key": FIREBASE_API_KEY,
                    "firebase_project_id": "demo-project",
                },
            )
        )

        assembled = assemble_profile("https://fb-demo.web.app")
        reloaded = _freeze_and_reload(assembled, tmp_path)

        assert reloaded.target.base_url == "https://fb-demo.web.app"
        assert reloaded.stack.auth == "firebase"
        # Non-Clerk auth derives a pure manifest stack: no Clerk-stack leakage.
        assert reloaded.stack.payments is None
        assert reloaded.firebase.api_key == FIREBASE_API_KEY
        assert reloaded.firebase.project_id == "demo-project"
        assert reloaded.raw() == assembled.raw()


# ---------------------------------------------------------------------------
# 2. Freeze path-gate (conftest `profile` fixture)
# ---------------------------------------------------------------------------

FROZEN_YAML = (
    "target:\n"
    "  base_url: https://frozen.example.com\n"
    "stack:\n"
    "  auth: clerk\n"
    "  database: supabase\n"
    "supabase:\n"
    "  anon_key: frozen-anon-key\n"
)

RAW_YAML = (
    "target:\n"
    "  base_url: https://raw.example.com\n"
    "stack:\n"
    "  auth: clerk\n"
)

# A frozen artifact run.sh produced incompletely: a target block with no
# base_url. The freeze path must reject it loudly rather than load a partial.
INCOMPLETE_FROZEN_YAML = (
    "target:\n"
    "  api_prefix: /.netlify/functions\n"
    "stack:\n"
    "  auth: clerk\n"
)


def _request_with_profile(path: str | None):
    """Minimal stand-in for pytest's request object: only --profile is read."""
    config = SimpleNamespace(
        getoption=lambda name: path if name == "--profile" else None
    )
    return SimpleNamespace(config=config)


def _profile_fixture():
    """The undecorated body of the session-scoped `profile` fixture."""
    import conftest
    return conftest.profile.__wrapped__


class TestFrozenProfilePathGate:
    """The fixture trusts the freeze flag only for the exact frozen artifact."""

    def test_frozen_flag_with_matching_path_skips_assembly(
        self, tmp_path, monkeypatch
    ):
        import conftest

        frozen = tmp_path / "frozen.yaml"
        frozen.write_text(FROZEN_YAML, encoding="utf-8")
        monkeypatch.setenv("PENTEST_PROFILE_FROZEN", "1")
        monkeypatch.setenv("PENTEST_PROFILE", str(frozen))

        with mock.patch.object(conftest, "assemble_profile") as m_assemble:
            prof = _profile_fixture()(_request_with_profile(str(frozen)))

        # Frozen artifact is loaded verbatim — no second discovery crawl.
        m_assemble.assert_not_called()
        assert prof.target.base_url == "https://frozen.example.com"
        assert prof.stack.auth == "clerk"
        assert prof.supabase.anon_key == "frozen-anon-key"

    def test_stale_frozen_flag_with_mismatched_path_falls_through(
        self, tmp_path, monkeypatch
    ):
        """Regression pin for #628: a stale PENTEST_PROFILE_FROZEN must NOT
        suppress discovery when --profile points at a different raw YAML."""
        import conftest

        frozen = tmp_path / "frozen.yaml"
        frozen.write_text(FROZEN_YAML, encoding="utf-8")
        raw = tmp_path / "raw.yaml"
        raw.write_text(RAW_YAML, encoding="utf-8")
        # Flag + PENTEST_PROFILE point at the OLD frozen artifact...
        monkeypatch.setenv("PENTEST_PROFILE_FROZEN", "1")
        monkeypatch.setenv("PENTEST_PROFILE", str(frozen))

        sentinel = object()
        with mock.patch.object(
            conftest, "assemble_profile", return_value=sentinel
        ) as m_assemble:
            # ...but the developer passes a DIFFERENT raw profile.
            result = _profile_fixture()(_request_with_profile(str(raw)))

        # Must fall through to live assembly against the raw profile's target.
        m_assemble.assert_called_once()
        args, kwargs = m_assemble.call_args
        assert args[0] == "https://raw.example.com"
        assert kwargs.get("yaml_path") == str(raw)
        assert result is sentinel

    def test_no_frozen_flag_falls_through_to_assembly(self, tmp_path, monkeypatch):
        """Without the freeze flag, a direct `pytest --profile` always assembles."""
        import conftest

        raw = tmp_path / "raw.yaml"
        raw.write_text(RAW_YAML, encoding="utf-8")
        monkeypatch.delenv("PENTEST_PROFILE_FROZEN", raising=False)
        monkeypatch.delenv("PENTEST_PROFILE", raising=False)

        sentinel = object()
        with mock.patch.object(
            conftest, "assemble_profile", return_value=sentinel
        ) as m_assemble:
            result = _profile_fixture()(_request_with_profile(str(raw)))

        m_assemble.assert_called_once()
        assert result is sentinel

    def test_frozen_artifact_missing_base_url_is_rejected(self, tmp_path, monkeypatch):
        """The freeze path must fail loudly on an incomplete frozen artifact
        (no target.base_url) rather than hand the run a silent partial profile.
        Enforced by load_profile's required-field check on the frozen path."""
        frozen = tmp_path / "frozen.yaml"
        frozen.write_text(INCOMPLETE_FROZEN_YAML, encoding="utf-8")
        monkeypatch.setenv("PENTEST_PROFILE_FROZEN", "1")
        monkeypatch.setenv("PENTEST_PROFILE", str(frozen))

        with pytest.raises(ValueError, match="base_url"):
            _profile_fixture()(_request_with_profile(str(frozen)))

    def test_missing_profile_option_raises(self, monkeypatch):
        """No --profile at all is a hard error, regardless of the freeze flag."""
        monkeypatch.delenv("PENTEST_PROFILE_FROZEN", raising=False)
        with pytest.raises(ValueError, match="profile is required"):
            _profile_fixture()(_request_with_profile(None))
