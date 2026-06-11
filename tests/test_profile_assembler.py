"""Tests for profile_assembler.assemble_profile."""

from __future__ import annotations

import sys
import warnings
from pathlib import Path
from unittest import mock

import pytest

# Ensure the package root is importable.
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile
from profile_assembler import assemble_profile, _deep_merge, _manifest_has_signal
from providers import ProviderManifest


def _discovered(providers=None, **overrides):
    """Build a discover_live() return dict, optionally carrying a manifest.

    Defaults to all-None discovered values (no supabase/clerk) so manifest-only
    cases are isolated; pass overrides to add specific discovered fields.
    """
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MOCK_DISCOVERED = {
    "supabase_url": "https://abc123.supabase.co",
    "supabase_anon_key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiYzEyMyIsInJvbGUiOiJhbm9uIn0.stub",
    "clerk_publishable_key": "pk_test_Y2xlcmsuZXhhbXBsZS5jb20k",
    "clerk_fapi_host": "clerk.example.com",
    "api_prefix": "/.netlify/functions",
}

YAML_PROFILE_PATH = str(_PKG_ROOT / "profiles" / "clerk-supabase-example.yaml")


# ---------------------------------------------------------------------------
# Tests: _deep_merge
# ---------------------------------------------------------------------------


class TestDeepMerge:
    def test_simple_override(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        assert _deep_merge(base, override) == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"supabase": {"project_url": "https://old.supabase.co", "tables": ["t1"]}}
        override = {"supabase": {"project_url": "https://new.supabase.co"}}
        result = _deep_merge(base, override)
        assert result["supabase"]["project_url"] == "https://new.supabase.co"
        assert result["supabase"]["tables"] == ["t1"]

    def test_list_replaced_not_merged(self):
        base = {"items": [1, 2, 3]}
        override = {"items": [4, 5]}
        assert _deep_merge(base, override) == {"items": [4, 5]}

    def test_null_override_skipped(self):
        """YAML sections with only comments parse as None; must not clobber base."""
        base = {"clerk": {"frontend_api": "https://discovered.clerk.com"}, "other": "val"}
        override = {"clerk": None, "other": "new"}
        result = _deep_merge(base, override)
        # None override must not wipe the discovered clerk dict.
        assert result["clerk"] == {"frontend_api": "https://discovered.clerk.com"}
        # Non-None overrides still work.
        assert result["other"] == "new"


# ---------------------------------------------------------------------------
# Tests: assemble_profile
# ---------------------------------------------------------------------------


class TestAssembleProfileDiscoveryOnly:
    """No YAML, no env vars — pure discovery."""

    @pytest.fixture(autouse=True)
    def _clear_env_overrides(self, monkeypatch):
        """Ensure no env vars leak into discovery-only tests."""
        for var in ("TARGET_BASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_PROJECT_URL", "CLERK_FAPI_HOST"):
            monkeypatch.delenv(var, raising=False)

    @mock.patch("profile_assembler.discover_live")
    def test_happy_path_discovery_only(self, mock_discover, monkeypatch):
        for var in ("SUPABASE_PROJECT_URL", "SUPABASE_ANON_KEY", "TARGET_BASE_URL", "CLERK_FAPI_HOST", "PENTEST_TARGET_URL"):
            monkeypatch.delenv(var, raising=False)
        mock_discover.return_value = MOCK_DISCOVERED

        profile = assemble_profile("https://example.com")

        assert profile.target.base_url == "https://example.com"
        assert profile.supabase.project_url == "https://abc123.supabase.co"
        assert profile.supabase.anon_key == MOCK_DISCOVERED["supabase_anon_key"]
        assert profile.clerk.frontend_api == "clerk.example.com"
        assert profile.target.api_prefix == "/.netlify/functions"

    @mock.patch("profile_assembler.discover_live")
    def test_discovery_returns_none_values(self, mock_discover, monkeypatch, capsys):
        """When discovery finds nothing, profile has None values and warnings."""
        for var in ("SUPABASE_PROJECT_URL", "SUPABASE_ANON_KEY", "TARGET_BASE_URL", "CLERK_FAPI_HOST", "PENTEST_TARGET_URL"):
            monkeypatch.delenv(var, raising=False)
        mock_discover.return_value = {
            "supabase_url": None,
            "supabase_anon_key": None,
            "clerk_publishable_key": None,
            "clerk_fapi_host": None,
            "api_prefix": None,
        }

        profile = assemble_profile("https://example.com")

        assert profile.target.base_url == "https://example.com"
        assert profile.supabase is None or profile.supabase.project_url is None
        captured = capsys.readouterr()
        assert "supabase.project_url not discovered" in captured.err


class TestAssembleProfileWithYaml:
    """YAML profile provides structural data + optional overrides."""

    @pytest.fixture(autouse=True)
    def _clear_env_overrides(self, monkeypatch):
        """Ensure no env vars leak into discovery-only tests."""
        for var in ("TARGET_BASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_PROJECT_URL", "CLERK_FAPI_HOST"):
            monkeypatch.delenv(var, raising=False)

    @mock.patch("profile_assembler.discover_live")
    def test_yaml_overrides_discovered_value(self, mock_discover):
        """YAML supabase.project_url overrides discovered value (staging scenario)."""
        mock_discover.return_value = MOCK_DISCOVERED

        profile = assemble_profile(
            "https://example.com",
            yaml_path=YAML_PROFILE_PATH,
        )

        # YAML has "https://xxx.supabase.co" placeholder which overrides discovery.
        # This tests the precedence: YAML > discovered.
        assert profile.target.base_url == "https://example.com"
        # YAML structural data (endpoints) should be present.
        assert profile.endpoints is not None
        assert profile.endpoints.authenticated is not None

    @mock.patch("profile_assembler.discover_live")
    def test_yaml_structural_data_merged(self, mock_discover):
        """YAML endpoints, tables, RPCs are merged with discovered config."""
        mock_discover.return_value = MOCK_DISCOVERED

        profile = assemble_profile(
            "https://example.com",
            yaml_path=YAML_PROFILE_PATH,
        )

        # Structural data from YAML must be present.
        assert profile.supabase_rpcs is not None
        assert profile.stack is not None
        assert profile.stack.auth == "clerk"


class TestAssembleProfileWithEnvVars:
    """Env vars have highest precedence."""

    @mock.patch("profile_assembler.discover_live")
    def test_env_var_overrides_both(self, mock_discover, monkeypatch):
        """TARGET_BASE_URL env var overrides both discovered and YAML base_url."""
        mock_discover.return_value = MOCK_DISCOVERED
        monkeypatch.setenv("TARGET_BASE_URL", "https://staging.example.com")

        profile = assemble_profile(
            "https://example.com",
            yaml_path=YAML_PROFILE_PATH,
        )

        assert profile.target.base_url == "https://staging.example.com"

    @mock.patch("profile_assembler.discover_live")
    def test_supabase_env_vars_override(self, mock_discover, monkeypatch):
        """SUPABASE_ANON_KEY and SUPABASE_PROJECT_URL env vars override discovery."""
        mock_discover.return_value = MOCK_DISCOVERED
        monkeypatch.setenv("SUPABASE_ANON_KEY", "env-key-override")
        monkeypatch.setenv("SUPABASE_PROJECT_URL", "https://env.supabase.co")

        profile = assemble_profile("https://example.com")

        assert profile.supabase.anon_key == "env-key-override"
        assert profile.supabase.project_url == "https://env.supabase.co"


class TestAssembleProfileErrors:
    """Error paths."""

    @mock.patch("profile_assembler.discover_live")
    def test_missing_supabase_warns(self, mock_discover, monkeypatch, capsys):
        """Discovery finds no Supabase URL — warning emitted."""
        for var in ("SUPABASE_PROJECT_URL", "SUPABASE_ANON_KEY", "TARGET_BASE_URL", "CLERK_FAPI_HOST", "PENTEST_TARGET_URL"):
            monkeypatch.delenv(var, raising=False)
        mock_discover.return_value = {
            "supabase_url": None,
            "supabase_anon_key": None,
            "clerk_publishable_key": "pk_test_abc",
            "clerk_fapi_host": "clerk.example.com",
            "api_prefix": None,
        }

        profile = assemble_profile("https://example.com")
        captured = capsys.readouterr()
        assert "supabase.project_url not discovered" in captured.err
        assert "supabase.anon_key not discovered" in captured.err


class TestAssembleProfileManifest:
    """Multi-stack: stack + provider config derived from the ProviderManifest."""

    @pytest.fixture(autouse=True)
    def _clear_env_overrides(self, monkeypatch):
        for var in (
            "TARGET_BASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_PROJECT_URL",
            "CLERK_FAPI_HOST", "PENTEST_TARGET_URL",
        ):
            monkeypatch.delenv(var, raising=False)

    @mock.patch("profile_assembler.discover_live")
    def test_firebase_manifest_sets_stack_and_config(self, mock_discover):
        mock_discover.return_value = _discovered(
            ProviderManifest(
                auth="firebase",
                database="firestore",
                storage="firebase",
                extracted_config={
                    "firebase_api_key": "AIzaSyAexamplekeyexamplekeyexampleke12",
                    "firebase_project_id": "demo-project",
                },
            )
        )

        profile = assemble_profile("https://fb-demo.web.app")

        assert profile.stack.auth == "firebase"
        assert profile.stack.database == "firestore"
        assert profile.stack.storage == "firebase"
        # Non-Clerk auth => Clerk-stack defaults must NOT leak (no Stripe).
        assert profile.stack.payments is None
        assert profile.firebase.api_key == "AIzaSyAexamplekeyexamplekeyexampleke12"
        assert profile.firebase.project_id == "demo-project"

    @mock.patch("profile_assembler.discover_live")
    def test_nextauth_manifest_sets_auth_only(self, mock_discover):
        mock_discover.return_value = _discovered(ProviderManifest(auth="nextauth"))

        profile = assemble_profile("https://nextauth-demo.example.com")

        assert profile.stack.auth == "nextauth"
        # Nothing else fingerprinted => pure manifest, no Clerk-stack defaults.
        assert profile.stack.database is None
        assert profile.stack.payments is None
        assert profile.firebase is None

    @mock.patch("profile_assembler.discover_live")
    def test_clerk_manifest_preserves_default_stack(self, mock_discover):
        """No-regression: a Clerk fingerprint keeps Stripe/Supabase gating.

        Stripe is never fingerprinted by detect_providers, so it must survive
        as the default payments value for the canonical Clerk+Supabase target.
        """
        mock_discover.return_value = _discovered(
            ProviderManifest(auth="clerk", database="supabase", storage="supabase")
        )

        profile = assemble_profile("https://example.com")

        assert profile.stack.auth == "clerk"
        assert profile.stack.database == "supabase"
        assert profile.stack.storage == "supabase"
        assert profile.stack.payments == "stripe"
        assert profile.stack.hosting == "netlify"

    @mock.patch("profile_assembler.discover_live")
    def test_empty_manifest_falls_back_to_default(self, mock_discover):
        mock_discover.return_value = _discovered(ProviderManifest())

        profile = assemble_profile("https://unknown.example.com")

        assert profile.stack.auth == "clerk"
        assert profile.stack.database == "supabase"
        assert profile.stack.payments == "stripe"

    @mock.patch("profile_assembler.discover_live")
    def test_missing_providers_key_falls_back_to_default(self, mock_discover):
        """Legacy discover_live dicts (no 'providers' key) must not crash."""
        mock_discover.return_value = _discovered()  # no providers key

        profile = assemble_profile("https://legacy.example.com")

        assert profile.stack.auth == "clerk"
        assert profile.stack.payments == "stripe"

    @mock.patch("profile_assembler.discover_live")
    def test_incidental_firebase_key_on_clerk_stack_no_block(self, mock_discover):
        """A stray Google API key on a Clerk target must not graft a firebase block."""
        mock_discover.return_value = _discovered(
            ProviderManifest(
                auth="clerk",
                database="supabase",
                storage="supabase",
                extracted_config={
                    "firebase_api_key": "AIzaSyAexamplekeyexamplekeyexampleke12",
                },
            )
        )

        profile = assemble_profile("https://example.com")

        assert profile.stack.auth == "clerk"
        assert profile.firebase is None

    @mock.patch("profile_assembler.discover_live")
    def test_yaml_stack_overrides_manifest(self, mock_discover):
        """YAML stack.auth wins over a discovered manifest (precedence: YAML > discovered)."""
        mock_discover.return_value = _discovered(ProviderManifest(auth="firebase"))

        profile = assemble_profile(
            "https://example.com",
            yaml_path=YAML_PROFILE_PATH,
        )

        # clerk-supabase-example.yaml declares stack.auth: clerk — must override firebase.
        assert profile.stack.auth == "clerk"

    @mock.patch("profile_assembler.discover_live")
    def test_firebase_config_applied_on_storage_leg(self, mock_discover):
        """firebase config block is grafted when stack.storage == 'firebase'
        even if auth is a different (non-firebase) provider — the storage leg of
        the _apply_manifest_config guard, independent of the auth leg."""
        mock_discover.return_value = _discovered(
            ProviderManifest(
                auth="nextauth",
                storage="firebase",
                extracted_config={"firebase_api_key": "AIzaSyAexamplekeyexamplekeyexampleke12"},
            )
        )

        profile = assemble_profile("https://mixed.example.com")

        assert profile.stack.auth == "nextauth"
        assert profile.stack.storage == "firebase"
        assert profile.firebase.api_key == "AIzaSyAexamplekeyexamplekeyexampleke12"

    @mock.patch("profile_assembler.discover_live")
    def test_firebase_config_applied_on_firestore_leg(self, mock_discover):
        """firebase config block is grafted when stack.database == 'firestore'
        even if auth/storage are non-firebase — the database leg of the
        _apply_manifest_config guard, isolated from the auth and storage legs."""
        mock_discover.return_value = _discovered(
            ProviderManifest(
                auth="nextauth",
                database="firestore",
                extracted_config={"firebase_api_key": "AIzaSyAexamplekeyexamplekeyexampleke12"},
            )
        )

        profile = assemble_profile("https://firestore-only.example.com")

        assert profile.stack.auth == "nextauth"
        assert profile.stack.database == "firestore"
        assert profile.stack.storage is None
        assert profile.firebase.api_key == "AIzaSyAexamplekeyexamplekeyexampleke12"

    @mock.patch("profile_assembler.discover_live")
    def test_multi_payments_manifest_yields_list(self, mock_discover):
        """Two payment providers stay a list (conftest marker gating depends on it)."""
        mock_discover.return_value = _discovered(
            ProviderManifest(auth="nextauth", payments=["paddle", "lemonsqueezy"])
        )

        profile = assemble_profile("https://multipay.example.com")

        assert profile.stack.payments == ["paddle", "lemonsqueezy"]

    @mock.patch("profile_assembler.discover_live")
    def test_single_payment_manifest_yields_string(self, mock_discover):
        """A single payment provider collapses to a bare string."""
        mock_discover.return_value = _discovered(
            ProviderManifest(auth="nextauth", payments=["paddle"])
        )

        profile = assemble_profile("https://onepay.example.com")

        assert profile.stack.payments == "paddle"

    @mock.patch("profile_assembler.discover_live")
    def test_auth_none_with_db_signal_inherits_clerk_default(self, mock_discover):
        """INTENTIONAL contract: a manifest with a Supabase signal but no auth
        fingerprint (auth=None) inherits the full Clerk default stack — including
        auth='clerk' and payments='stripe'. This protects the canonical no-profile
        run from a flaky Clerk-key miss; Supabase Auth targets must be named via
        --profile (they share Supabase's fingerprint and aren't auto-detected)."""
        mock_discover.return_value = _discovered(
            ProviderManifest(database="supabase", storage="supabase")  # auth is None
        )

        profile = assemble_profile("https://supabase-only.example.com")

        assert profile.stack.auth == "clerk"
        assert profile.stack.database == "supabase"
        assert profile.stack.payments == "stripe"


class TestManifestHasSignal:
    """Direct coverage of the _manifest_has_signal service_role_key_found carve-out."""

    def test_none_manifest_has_no_signal(self):
        assert _manifest_has_signal(None) is False

    def test_empty_manifest_has_no_signal(self):
        assert _manifest_has_signal(ProviderManifest()) is False

    def test_service_role_false_alone_is_not_a_signal(self):
        # A bool that is legitimately False must not, by itself, count as a signal.
        assert _manifest_has_signal(
            ProviderManifest(extracted_config={"service_role_key_found": False})
        ) is False

    def test_service_role_true_alone_is_a_signal(self):
        assert _manifest_has_signal(
            ProviderManifest(extracted_config={"service_role_key_found": True})
        ) is True

    def test_other_config_value_is_a_signal(self):
        assert _manifest_has_signal(
            ProviderManifest(extracted_config={"firebase_api_key": "AIza..."})
        ) is True

    def test_auth_signal_is_a_signal(self):
        assert _manifest_has_signal(ProviderManifest(auth="firebase")) is True


class TestLoadProfileWarnings:
    def _write_profile(self, tmp_path, *extra_lines):
        profile_path = tmp_path / "profile.yaml"
        profile_path.write_text(
            "\n".join([
                "target:",
                "  base_url: https://example.com",
                "stack:",
                "  payments:",
                "    - lemonsqueezy",
                *extra_lines,
            ]),
            encoding="utf-8",
        )
        return profile_path

    @staticmethod
    def _load_and_capture(profile_path):
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            profile = load_profile(profile_path)
        return profile, [w for w in recorded if "lemonsqueezy_webhook_path" in str(w.message)]

    @pytest.mark.parametrize("alias_block", ["payments_config", "payments_cfg", "payments"])
    def test_alias_block_supplies_path_does_not_warn(self, tmp_path, alias_block):
        profile_path = self._write_profile(
            tmp_path,
            f"{alias_block}:",
            "  lemonsqueezy_webhook_path: /api/webhooks/lemonsqueezy",
        )

        profile, lemon_warnings = self._load_and_capture(profile_path)

        assert profile.target.base_url == "https://example.com"
        assert lemon_warnings == []

    def test_second_alias_supplies_path_when_first_block_lacks_key(self, tmp_path):
        # Regression: payments_config is a non-empty dict missing the webhook key;
        # the path lives in payments_cfg. A short-circuiting `or` chain would have
        # masked the second block and warned spuriously.
        profile_path = self._write_profile(
            tmp_path,
            "payments_config:",
            "  stripe_key: sk_test_unrelated",
            "payments_cfg:",
            "  lemonsqueezy_webhook_path: /api/webhooks/lemonsqueezy",
        )

        profile, lemon_warnings = self._load_and_capture(profile_path)

        assert profile is not None
        assert lemon_warnings == []

    def test_warns_when_path_absent_everywhere(self, tmp_path):
        profile_path = self._write_profile(tmp_path)

        _profile, lemon_warnings = self._load_and_capture(profile_path)

        assert len(lemon_warnings) == 1
