"""Unit tests for detect_providers() in discover.py.

All tests use simple string fixtures — no network calls required.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure the package root is on the path so ``import discover`` works when
# pytest is invoked from any working directory.
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent       # tests/
_PKG_ROOT = _HERE.parent                      # StackBadger/
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from discover import (  # noqa: E402
    detect_providers,
    _merge_manifests,
    _priority_winner,
    _AUTH_PRIORITY,
)
from providers import ProviderManifest  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jwt(role: str = "anon") -> str:
    """Craft a minimal syntactically-valid JWT with the given role in payload."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload_bytes = json.dumps({"role": role, "iss": "supabase"}).encode()
    payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"fakesignature1234").rstrip(b"=").decode()
    return f"eyJhbGci{header}.{payload}.{sig}"


def _make_firebase_key() -> str:
    """Return a valid-looking Firebase API key (AIza + 35 chars)."""
    return "AIzaSyA1234567890abcdefghijklmnopqrstuv"


def _make_supabase_url() -> str:
    """Return a valid Supabase project URL with 20-char ref."""
    return "https://abcdefghijklmnopqrst.supabase.co"


def _encode_clerk_pk(hostname: str) -> str:
    """Encode a hostname into a Clerk publishable key."""
    encoded = base64.b64encode(hostname.encode()).rstrip(b"=").decode()
    return f"pk_test_{encoded}$"


def _supabase_js_gotrue_blob() -> str:
    """Verbatim GoTrue/auth-js string literals shipped inside ``supabase-js``.

    These tokens were lifted (2026-06-10) from the canonical Clerk + Supabase
    production bundle ``vendor-supabase-*.js`` — a target that uses **Clerk**
    for auth and Supabase only as a **database**. ``supabase-js`` statically
    bundles the GoTrue auth client, so every one of these strings is present
    regardless of whether the app ever calls Supabase Auth. They are therefore
    NOT a usable fingerprint for Supabase Auth (an inherent limit of static bundle analysis).
    The full
    request paths (``/auth/v1/token`` etc.) never appear as contiguous literals
    because they are constructed at runtime from ``new URL("auth/v1", base)``
    joined with ``/token`` — that join is reproduced here.
    """
    return (
        'this.authUrl=new URL(`auth/v1`,r);'
        'async signInWithPassword(e){let t;if(`email`in e){'
        'this._request(`POST`,`/token?grant_type=password`)}}'
        'let $t=`supabase.auth.token`;'
        '// Use supabase.auth.getUser() instead;'
        'name:`@supabase/auth-js`,GoTrueClient,gotrue-js,'
    )


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------

class TestDetectProvidersHappyPath:
    """Verify provider detection for common single-provider bundles."""

    def test_firebase_aiza_key_sets_auth_and_database(self):
        """Firebase AIza key -> auth=firebase, database=firestore."""
        bundle = f'var config = {{apiKey: "{_make_firebase_key()}"}};'
        m = detect_providers(bundle)

        assert m.auth == "firebase"
        assert m.database == "firestore"
        assert m.storage == "firebase"
        assert "firebase_api_key" in m.extracted_config

    def test_supabase_and_clerk(self):
        """Supabase URL + Clerk PK -> database=supabase, auth=clerk."""
        clerk_pk = _encode_clerk_pk("happy-dog.clerk.accounts.dev")
        bundle = (
            f'var SUPABASE_URL = "{_make_supabase_url()}";'
            f'var CLERK_PK = "{clerk_pk}";'
        )
        m = detect_providers(bundle)

        assert m.auth == "clerk"
        assert m.database == "supabase"
        assert "supabase_project_ref" in m.extracted_config

    def test_nextauth_csrf_path(self):
        """NextAuth CSRF path string -> auth=nextauth."""
        bundle = 'fetch("/api/auth/csrf").then(r => r.json());'
        m = detect_providers(bundle)

        assert m.auth == "nextauth"

    def test_nextauth_callback_path(self):
        """NextAuth callback credentials path -> auth=nextauth."""
        bundle = 'const url = "/api/auth/callback/credentials";'
        m = detect_providers(bundle)

        assert m.auth == "nextauth"

    def test_paddle_and_r2(self):
        """Paddle CDN + R2 -> payments=["paddle"], s3_compatible=True."""
        bundle = (
            'const s = document.createElement("script");'
            's.src = "https://cdn.paddle.com/paddle/v2/paddle.js";'
            'const storageUrl = "https://bucket.r2.cloudflarestorage.com/img";'
        )
        m = detect_providers(bundle)

        assert "paddle" in m.payments
        assert m.storage == "r2"
        assert m.s3_compatible is True

    def test_lemonsqueezy_detected(self):
        """LemonSqueezy domain in bundle -> payments includes lemonsqueezy."""
        bundle = 'window.createLemonSqueezy(); fetch("https://api.lemonsqueezy.com/v1");'
        m = detect_providers(bundle)

        assert "lemonsqueezy" in m.payments

    def test_s3_amazonaws(self):
        """S3 URL -> storage=s3, s3_compatible=True."""
        bundle = 'const uploadUrl = "https://my-bucket.s3.amazonaws.com/uploads";'
        m = detect_providers(bundle)

        assert m.storage == "s3"
        assert m.s3_compatible is True

    def test_cognito_user_pool(self):
        """Cognito user pool ID extracted into config."""
        pool_id = "us-east-1_AbCdEfGhI"
        bundle = f'var userPoolId = "{pool_id}";'
        m = detect_providers(bundle)

        assert m.extracted_config.get("cognito_user_pool_id") == pool_id


# ---------------------------------------------------------------------------
# Edge-case tests
# ---------------------------------------------------------------------------

class TestDetectProvidersEdgeCases:
    """Edge cases and priority conflict resolution."""

    def test_firebase_and_supabase_resolves_to_supabase(self):
        """Both Firebase key and Supabase URL -> database=supabase (warning logged)."""
        bundle = (
            f'var apiKey = "{_make_firebase_key()}";'
            f'var sbUrl = "{_make_supabase_url()}";'
        )

        with pytest.warns(UserWarning, match="Ambiguous"):
            m = detect_providers(bundle)

        # Supabase takes priority for database
        assert m.database == "supabase"
        # Firebase key still sets auth when Clerk is absent
        assert m.auth == "firebase"
        assert "firebase_api_key" in m.extracted_config
        assert "supabase_project_ref" in m.extracted_config

    def test_empty_bundle_returns_all_none(self):
        """Empty bundle text -> all fields None/empty."""
        m = detect_providers("")

        assert m.auth is None
        assert m.database is None
        assert m.storage is None
        assert m.payments == []
        assert m.s3_compatible is False
        assert m.extracted_config.get("service_role_key_found") is False

    def test_service_role_jwt_found(self):
        """Service role JWT -> extracted_config["service_role_key_found"]=True."""
        bundle = '{"role": "service_role", "iss": "supabase"}'
        m = detect_providers(bundle)

        assert m.extracted_config["service_role_key_found"] is True

    def test_service_role_prefix_found(self):
        """sb_secret_ prefix -> service_role_key_found=True."""
        bundle = 'const key = "sb_secret_abc123def456";'
        m = detect_providers(bundle)

        assert m.extracted_config["service_role_key_found"] is True

    def test_clerk_pk_with_aiza_keeps_clerk_auth(self):
        """Clerk PK present alongside Firebase AIza key -> auth stays 'clerk'."""
        clerk_pk = _encode_clerk_pk("my-app.clerk.accounts.dev")
        bundle = (
            f'var apiKey = "{_make_firebase_key()}";'
            f'var clerkPk = "{clerk_pk}";'
        )
        m = detect_providers(bundle)

        assert m.auth == "clerk"
        # Firebase key is still extracted but does not override auth
        assert "firebase_api_key" in m.extracted_config

    def test_firebase_and_nextauth_coexist_firebase_wins(self):
        """Single bundle with both Firebase key and NextAuth routes -> auth=firebase.

        Regression for the round-2 Codex P1: detect_providers must apply the
        same precedence as _merge_manifests (firebase outranks nextauth).
        Previously an earlier NextAuth signal blocked the Firebase upgrade
        because the Firebase branch only ran when auth was still None.
        """
        bundle = (
            f'var config = {{apiKey: "{_make_firebase_key()}"}};'
            'fetch("/api/auth/csrf");'
            'const cb = "/api/auth/callback/credentials";'
        )
        m = detect_providers(bundle)

        assert m.auth == "firebase"  # not "nextauth"
        assert m.database == "firestore"
        # And the merged path must agree with the single-bundle path.
        assert _merge_manifests([detect_providers(bundle)]).auth == "firebase"

    def test_paddle_setup_variant(self):
        """paddle.Setup() call detected as Paddle provider."""
        bundle = 'Paddle.Setup({ vendor: 12345 });'
        m = detect_providers(bundle)

        assert "paddle" in m.payments

    def test_x_amz_algorithm_detects_s3(self):
        """X-Amz-Algorithm string in presigned URL logic -> s3 storage."""
        bundle = 'url += "&X-Amz-Algorithm=AWS4-HMAC-SHA256";'
        m = detect_providers(bundle)

        assert m.storage == "s3"
        assert m.s3_compatible is True

    def test_lmsqueezy_short_domain(self):
        """lmsqueezy.com (short alias) also detected."""
        bundle = 'const api = "https://api.lmsqueezy.com/v1";'
        m = detect_providers(bundle)

        assert "lemonsqueezy" in m.payments


# ---------------------------------------------------------------------------
# Merge tests
# ---------------------------------------------------------------------------

class TestMergeManifests:
    """Verify _merge_manifests combines multiple bundle results correctly."""

    def test_merge_clerk_beats_firebase_regardless_of_order(self):
        """Clerk PK is higher priority than Firebase for auth, regardless of bundle order."""
        # Bundle 1 = firebase, Bundle 2 = clerk (clerk arrives second — old code would have missed it)
        m1 = ProviderManifest(auth="firebase", database="firestore")
        m2 = ProviderManifest(auth="clerk", database="supabase")
        merged = _merge_manifests([m1, m2])

        assert merged.auth == "clerk"
        assert merged.database == "supabase"

    def test_merge_clerk_beats_firebase_early_position(self):
        """Clerk PK is higher priority than Firebase even when clerk arrives first."""
        m1 = ProviderManifest(auth="clerk", database=None)
        m2 = ProviderManifest(auth="firebase", database="firestore")
        merged = _merge_manifests([m1, m2])

        assert merged.auth == "clerk"

    def test_merge_supabase_beats_firestore_regardless_of_order(self):
        """Supabase wins over firestore for database regardless of bundle order."""
        m1 = ProviderManifest(database="firestore")
        m2 = ProviderManifest(database="supabase")
        merged = _merge_manifests([m1, m2])

        assert merged.database == "supabase"

        # Reversed order must produce the same result.
        merged_rev = _merge_manifests([m2, m1])
        assert merged_rev.database == "supabase"

    def test_merge_none_does_not_override_set_value(self):
        """None in a later bundle does not erase an already-detected auth value."""
        m1 = ProviderManifest(auth="clerk")
        m2 = ProviderManifest(auth=None)
        merged = _merge_manifests([m1, m2])

        assert merged.auth == "clerk"

    def test_merge_supabase_storage_beats_s3(self):
        """Supabase storage wins over s3 regardless of order."""
        m1 = ProviderManifest(storage="s3", s3_compatible=True)
        m2 = ProviderManifest(storage="supabase")
        merged = _merge_manifests([m1, m2])

        assert merged.storage == "supabase"
        # s3_compatible still reflects that S3 was detected in one bundle
        assert merged.s3_compatible is True

        merged_rev = _merge_manifests([m2, m1])
        assert merged_rev.storage == "supabase"

    def test_merge_order_independence(self):
        """Reversing the manifest list produces the same auth/database/storage result."""
        manifests = [
            ProviderManifest(auth="firebase", database="firestore", storage="firebase"),
            ProviderManifest(auth="nextauth", database=None, storage="s3"),
            ProviderManifest(auth="clerk", database="supabase", storage="supabase"),
        ]
        merged_fwd = _merge_manifests(manifests)
        merged_rev = _merge_manifests(list(reversed(manifests)))

        assert merged_fwd.auth == merged_rev.auth == "clerk"
        assert merged_fwd.database == merged_rev.database == "supabase"
        assert merged_fwd.storage == merged_rev.storage == "supabase"

    def test_merge_nextauth_wins_over_none(self):
        """nextauth is chosen when it is the only non-None auth value."""
        m1 = ProviderManifest(auth=None)
        m2 = ProviderManifest(auth="nextauth")
        merged = _merge_manifests([m1, m2])

        assert merged.auth == "nextauth"

    def test_merge_clerk_beats_nextauth(self):
        """Clerk has higher priority than nextauth."""
        m1 = ProviderManifest(auth="nextauth")
        m2 = ProviderManifest(auth="clerk")
        merged = _merge_manifests([m1, m2])

        assert merged.auth == "clerk"

        merged_rev = _merge_manifests([m2, m1])
        assert merged_rev.auth == "clerk"

    def test_merge_unions_payments(self):
        """Payments lists are unioned without duplicates."""
        m1 = ProviderManifest(payments=["paddle"])
        m2 = ProviderManifest(payments=["paddle", "lemonsqueezy"])
        merged = _merge_manifests([m1, m2])

        assert sorted(merged.payments) == ["lemonsqueezy", "paddle"]

    def test_merge_s3_compatible_any_true(self):
        """s3_compatible is True if any manifest set it."""
        m1 = ProviderManifest(s3_compatible=False)
        m2 = ProviderManifest(s3_compatible=True)
        merged = _merge_manifests([m1, m2])

        assert merged.s3_compatible is True

    def test_merge_extracted_config_first_writer_wins(self):
        """First writer wins for extracted_config keys."""
        m1 = ProviderManifest(extracted_config={"firebase_api_key": "key1"})
        m2 = ProviderManifest(extracted_config={"firebase_api_key": "key2", "supabase_project_ref": "ref1"})
        merged = _merge_manifests([m1, m2])

        assert merged.extracted_config["firebase_api_key"] == "key1"
        assert merged.extracted_config["supabase_project_ref"] == "ref1"

    def test_merge_service_role_true_wins(self):
        """service_role_key_found True wins over False."""
        m1 = ProviderManifest(extracted_config={"service_role_key_found": False})
        m2 = ProviderManifest(extracted_config={"service_role_key_found": True})
        merged = _merge_manifests([m1, m2])

        assert merged.extracted_config["service_role_key_found"] is True

    def test_merge_empty_list_returns_empty_manifest(self):
        """Empty input list returns a fresh empty manifest."""
        merged = _merge_manifests([])

        assert merged.auth is None
        assert merged.database is None
        assert merged.payments == []


# ---------------------------------------------------------------------------
# _priority_winner unit tests
# ---------------------------------------------------------------------------

class TestPriorityWinner:
    """Direct tests of the shared precedence helper."""

    def test_returns_none_for_all_none(self):
        assert _priority_winner([None, None], ["a", "b"]) is None

    def test_known_value_beats_none(self):
        assert _priority_winner([None, "a"], ["a", "b"]) == "a"

    def test_higher_index_beats_lower(self):
        assert _priority_winner(["a", "b"], ["a", "b"]) == "b"

    def test_order_independence(self):
        result_fwd = _priority_winner(["a", "b"], ["a", "b"])
        result_rev = _priority_winner(["b", "a"], ["a", "b"])
        assert result_fwd == result_rev == "b"

    def test_unknown_value_beats_none(self):
        """Values not in the priority list still win over None."""
        assert _priority_winner([None, "unknown-provider"], ["a", "b"]) == "unknown-provider"

    def test_known_value_beats_unknown(self):
        """A value in the priority list beats one not in it."""
        assert _priority_winner(["unknown-provider", "a"], ["a", "b"]) == "a"

    def test_clerk_beats_supabase_auth_in_auth_priority(self):
        """clerk outranks supabase-auth in the real _AUTH_PRIORITY table.

        ``supabase-auth`` is reachable only via an explicit ``--profile``
        (``detect_providers`` never emits it — see
        TestSupabaseAuthNotAutoDetected). This pins the dormant priority entry
        so that if a --profile target ever surfaces both auth values, clerk
        still wins, matching the canonical-target protection.
        """
        assert _priority_winner(["supabase-auth", "clerk"], _AUTH_PRIORITY) == "clerk"
        assert _priority_winner(["clerk", "supabase-auth"], _AUTH_PRIORITY) == "clerk"


# ---------------------------------------------------------------------------
# Supabase Auth is deliberately NOT auto-detected (Item 3 investigation)
# ---------------------------------------------------------------------------

class TestSupabaseAuthNotAutoDetected:
    """Pin the correct-by-design contract that ``detect_providers`` never emits
    ``supabase-auth`` from a static bundle scan.

    Background (Item 3 / handover 2026-06-10): we investigated fingerprinting
    Supabase Auth (GoTrue) so a no-profile run could target it. The conclusion
    was that NO reliable positive signal exists: ``supabase-js`` statically
    bundles the GoTrue auth client, so the canonical Clerk + Supabase target
    (Clerk auth + Supabase DB) already carries every candidate token
    (``gotrue``, ``signInWithPassword``, ``supabase.auth``, ``auth/v1``).
    Emitting ``supabase-auth`` from any of those would misclassify the
    canonical target as Supabase Auth whenever the Clerk PK match is momentarily
    flaky. Supabase Auth therefore stays a ``--profile``-only stack. These tests
    fail loudly if a future change re-introduces a library-string fingerprint.
    """

    def test_gotrue_library_strings_do_not_emit_supabase_auth(self):
        """A bundle full of GoTrue library strings + a Supabase URL but NO Clerk
        PK must resolve ``auth=None`` (NOT ``supabase-auth``).

        This is the core regression guard: it reproduces the "clerk_pk
        momentarily unmatched" scenario from acceptance criterion #2. The
        resulting ``auth=None`` is what lets ``_resolve_stack`` inherit the
        Clerk default, protecting the canonical no-profile run.
        """
        bundle = f'var u="{_make_supabase_url()}";{_supabase_js_gotrue_blob()}'
        m = detect_providers(bundle)

        assert m.auth is None
        assert m.database == "supabase"

    def test_gotrue_library_strings_with_clerk_pk_resolve_clerk(self):
        """The canonical Clerk + Supabase shape — Clerk auth + Supabase DB with
        ``supabase-js`` (hence GoTrue strings) bundled — resolves ``auth=clerk``.

        GoTrue library tokens must never outrank a present Clerk PK.
        """
        clerk_pk = _encode_clerk_pk("happy-dog.clerk.accounts.dev")
        bundle = (
            f'var u="{_make_supabase_url()}";'
            f'var pk="{clerk_pk}";'
            f"{_supabase_js_gotrue_blob()}"
        )
        m = detect_providers(bundle)

        assert m.auth == "clerk"
        assert m.database == "supabase"

    def test_clerk_only_resolves_clerk(self):
        """A clerk-only bundle (no GoTrue/Supabase signal) resolves ``auth=clerk``."""
        clerk_pk = _encode_clerk_pk("solo.clerk.accounts.dev")
        m = detect_providers(f'var pk="{clerk_pk}";')

        assert m.auth == "clerk"

    def test_gotrue_strings_in_isolation_emit_no_auth(self):
        """The purest statement of the contract: GoTrue library strings ALONE —
        with NO Supabase URL and NO Clerk PK — produce ``auth=None``.

        Isolates the "GoTrue tokens are never an auth signal" claim from the
        Supabase-URL confound present in the other suppression tests, so the
        guard can't pass merely because the URL drove the database leg.
        """
        m = detect_providers(_supabase_js_gotrue_blob())

        assert m.auth is None
        assert m.database is None

    def test_merge_preserves_no_supabase_auth_emission(self):
        """Cross-bundle merge of per-bundle GoTrue-library scans still yields no
        ``supabase-auth`` — the deliberate non-detection holds end-to-end."""
        gotrue_bundle = f'var u="{_make_supabase_url()}";{_supabase_js_gotrue_blob()}'
        merged = _merge_manifests([
            detect_providers(gotrue_bundle),
            detect_providers("// unrelated chunk"),
        ])

        assert merged.auth is None
        assert merged.database == "supabase"
