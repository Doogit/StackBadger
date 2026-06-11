"""Information disclosure tests.

Validates that the production deployment does not leak:
  - JavaScript source maps (should be excluded from production builds).
  - Secret key material in client-side bundles.
  - Sensitive filesystem paths via directory listing.
  - Supabase metadata that exceeds what anonymous users should see.

These tests are stack-agnostic — no special marker required.
"""

from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from typing import Optional

import httpx
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_url(profile) -> str:
    return ((profile.target and profile.target.base_url) or "").rstrip("/")


class _ScriptSrcParser(HTMLParser):
    """Minimal HTML parser that collects <script src="..."> URLs."""

    def __init__(self) -> None:
        super().__init__()
        self.script_srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag == "script":
            for attr_name, attr_value in attrs:
                if attr_name == "src" and attr_value:
                    self.script_srcs.append(attr_value)


def _absolute_url(base: str, src: str) -> str:
    """Make a script src absolute if it is root-relative."""
    if src.startswith("http://") or src.startswith("https://"):
        return src
    if src.startswith("//"):
        return "https:" + src
    return base + "/" + src.lstrip("/")


# ---------------------------------------------------------------------------
# Source map probing
# ---------------------------------------------------------------------------

_COMMON_MAP_PATHS = [
    "/assets/index.js.map",
    "/assets/main.js.map",
    "/assets/vendor.js.map",
    # Vite/Rollup typical hashed filename patterns (static probes)
    "/assets/index-abc123.js.map",
    "/assets/index-[hash].js.map",
]


class TestSourceMapExposure:
    """Source maps must not be accessible in production.

    Source maps expose the full original TypeScript/JSX source code, comments,
    and variable names — effectively handing attackers a readable copy of the
    application logic.

    Vite excludes source maps from production builds by default.  This test
    confirms that default is not overridden.
    """

    @pytest.mark.parametrize("path", _COMMON_MAP_PATHS)
    def test_static_map_path_returns_404(self, profile, path, evidence):
        """GET known source map paths — expect 404, not 200."""
        url = _base_url(profile) + path
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url)

        if resp.status_code == 200:
            # SPA catch-all (e.g., _redirects /* -> /index.html 200) returns
            # HTML for any unknown path. Only flag as exposed if the response
            # looks like an actual source map (JSON content, not HTML).
            content_type = resp.headers.get("content-type", "")
            body_prefix = resp.text[:50].strip()
            is_html = "text/html" in content_type or body_prefix.startswith(("<!DOCTYPE", "<html", "<!doctype"))
            if is_html:
                # SPA fallback — not a real source map, treat as 404-equivalent.
                pass
            else:
                evidence.capture(resp, label="source_map_exposed_" + path.replace("/", "_"))
                assert False, (
                    f"Source map accessible at {url} (HTTP {resp.status_code}, "
                    f"Content-Type: {content_type}). "
                    "Source maps must not be deployed to production. "
                    "Set sourcemap: false in vite.config.js for production builds."
                )
        elif resp.status_code != 404:
            # Unexpected status (3xx, 5xx) — capture for review but don't hard-fail.
            evidence.capture(resp, label="source_map_unexpected_" + path.replace("/", "_"))

    def test_js_bundle_has_no_inline_sourcemappingurl(self, profile, evidence):
        """JS bundles must not contain //# sourceMappingURL= pointing to .map files.

        Inline sourceMappingURL comments in production bundles instruct browsers
        to fetch the source map.  Even if the map file returns 404, the URL
        itself reveals the asset naming convention.
        """
        base = _base_url(profile)
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            # Fetch the main page to discover actual bundle URLs.
            index_resp = client.get(base + "/")
            if index_resp.status_code != 200:
                pytest.skip(
                    f"Main page returned {index_resp.status_code}; "
                    "cannot discover JS bundles."
                )

            parser = _ScriptSrcParser()
            parser.feed(index_resp.text)
            script_urls = [
                _absolute_url(base, src) for src in parser.script_srcs
                if src and not src.startswith("data:")
            ]

        if not script_urls:
            pytest.skip("No <script src=...> tags found on main page.")

        violations: list[str] = []
        with httpx.Client(timeout=15.0) as client:
            for url in script_urls[:10]:  # cap at 10 bundles
                try:
                    resp = client.get(url)
                except httpx.TransportError:
                    continue
                if resp.status_code != 200:
                    continue
                if "//# sourceMappingURL=" in resp.text:
                    # Check if it points to a .map file (not a data URI).
                    matches = re.findall(
                        r"//# sourceMappingURL=([^\s]+)", resp.text
                    )
                    for target in matches:
                        if target.endswith(".map"):
                            violations.append(f"{url} -> {target}")

        assert not violations, (
            "Production JS bundles contain sourceMappingURL references:\n"
            + "\n".join(f"  {v}" for v in violations)
            + "\nSet sourcemap: false in vite.config.js build options."
        )


# ---------------------------------------------------------------------------
# Secret key scanning in client bundles
# ---------------------------------------------------------------------------

# Patterns that must never appear in client-side JavaScript.
_SECRET_PATTERNS: list[tuple[str, str]] = [
    ("SUPABASE_SERVICE_ROLE_KEY", "Supabase service role key name"),
    ("CLERK_SECRET_KEY", "Clerk secret key name"),
    ("STRIPE_SECRET_KEY", "Stripe secret key name"),
    ("INTERNAL_API_SECRET", "Internal API secret name"),
    ("OPENAI_API_KEY", "OpenAI API key name"),
    ("sk_live_", "Stripe live secret key prefix"),
    ("sk_test_", "Stripe test secret key prefix"),
    # Supabase service-role JWTs start with eyJ and encode role:service_role
    # The anon key is safe client-side; the service key is not.
    # We check for the literal string to avoid false positives on the anon key.
    ('"role":"service_role"', "Supabase service_role JWT payload fragment"),
]


class TestSecretKeyScanning:
    """Client-side JS bundles must not contain secret key material."""

    def test_bundles_contain_no_secret_keys(self, profile, evidence):
        """Fetch all JS bundles from the main page and scan for secret patterns.

        The Vite build pipeline is configured to inject only VITE_-prefixed
        environment variables into the client bundle.  This test confirms that
        no server-side secret variable names or values leaked into the build.

        Finding: Any match is a critical severity finding — immediate rotation
        of the exposed key is required.
        """
        base = _base_url(profile)
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            index_resp = client.get(base + "/")
            if index_resp.status_code != 200:
                pytest.skip(
                    f"Main page returned {index_resp.status_code}; "
                    "cannot discover JS bundles."
                )

            parser = _ScriptSrcParser()
            parser.feed(index_resp.text)
            script_urls = [
                _absolute_url(base, src) for src in parser.script_srcs
                if src and not src.startswith("data:")
            ]

        if not script_urls:
            pytest.skip("No <script src=...> tags found on main page.")

        violations: list[str] = []
        with httpx.Client(timeout=15.0) as client:
            for url in script_urls[:10]:
                try:
                    resp = client.get(url)
                except httpx.TransportError:
                    continue
                if resp.status_code != 200:
                    continue

                bundle_text = resp.text
                for pattern, description in _SECRET_PATTERNS:
                    if pattern in bundle_text:
                        # Find surrounding context (up to 80 chars).
                        idx = bundle_text.index(pattern)
                        ctx = bundle_text[max(0, idx - 20): idx + len(pattern) + 20]
                        violations.append(
                            f"Bundle {url}: found {description} ({pattern!r}). "
                            f"Context: ...{ctx!r}..."
                        )

        assert not violations, (
            "CRITICAL: Secret key material found in client-side bundles:\n"
            + "\n".join(f"  {v}" for v in violations)
            + "\nRotate any exposed keys immediately."
        )


# ---------------------------------------------------------------------------
# Directory listing / sensitive path exposure
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS = [
    "/.git",
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.netlify",
    "/.clerk",
    "/node_modules",
    "/node_modules/.package-lock.json",
]


class TestDirectoryListing:
    """Sensitive paths and directories must return 404, not directory listings."""

    @pytest.mark.parametrize("path", _SENSITIVE_PATHS)
    def test_sensitive_path_returns_404(self, profile, path, evidence):
        """GET a sensitive path; expect 404 (not 200 with directory listing).

        Netlify's static hosting returns 404 for paths that are not in the
        publish directory.  The .git directory and .env files are never in the
        publish dir, so this should always be 404.

        A 200 response would indicate either:
          - A misconfigured _redirects rule serving the filesystem root, or
          - A server-side function handling /* and reading arbitrary files.

        Finding: 200 on /.git/config exposes branch names, remote URLs, and
        potentially embedded credentials in the git config.
        """
        url = _base_url(profile) + path
        with httpx.Client(timeout=10.0, follow_redirects=False) as client:
            resp = client.get(url)

        if resp.status_code == 200:
            # SPA catch-all (e.g., _redirects /* -> /index.html 200) returns
            # HTML for any unknown path. Only flag as exposed if the response
            # is NOT an HTML page (actual file content, JSON, etc.).
            content_type = resp.headers.get("content-type", "")
            body_prefix = resp.text[:100].strip()
            is_html = "text/html" in content_type or body_prefix.startswith(("<!DOCTYPE", "<html", "<!doctype"))
            if is_html:
                # SPA fallback — not real sensitive file exposure.
                pass
            else:
                evidence.capture(resp, label="sensitive_path_exposed_" + path.replace("/", "_").lstrip("_"))
                assert False, (
                    f"Sensitive path accessible: GET {url} returned HTTP 200 "
                    f"(Content-Type: {content_type}). "
                    f"Body excerpt: {resp.text[:300]!r}"
                )


# ---------------------------------------------------------------------------
# Supabase metadata probing
# ---------------------------------------------------------------------------

class TestSupabaseMetadataExposure:
    """Document what Supabase metadata is accessible to anonymous clients.

    These tests are primarily informational (INFO-level findings).  They do
    not assert hard pass/fail on all endpoints — instead they capture what
    is exposed so the security team can review.

    A test FAILs only if clearly sensitive configuration data is returned.
    """

    @pytest.mark.supabase
    def test_postgrest_root_schema_exposure(self, profile, evidence):
        """GET /rest/v1/ — document what the PostgREST root returns.

        PostgREST returns an OpenAPI schema at the root.  With the anon key,
        it should only expose tables that have RLS policies allowing anon reads
        (currently: kb_chunks, edge_case_guidance).

        FAIL: If user_facing tables (uploads, entry_lines, etc.) appear in the
        schema as publicly readable — that indicates missing or misconfigured RLS.
        """
        project_url = profile.supabase and profile.supabase.project_url
        if not project_url or "xxx" in project_url:
            pytest.skip("Supabase project_url not configured in profile")

        anon_key = (profile.supabase and profile.supabase.anon_key) or ""
        url = project_url.rstrip("/") + "/rest/v1/"

        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                url,
                headers={
                    "apikey": anon_key,
                    "Authorization": f"Bearer {anon_key}",
                },
            )

        evidence.capture(resp, label="supabase_postgrest_root")

        # INFO: Log what's accessible.
        # FAIL: User-facing sensitive tables should not be in anon schema.
        user_facing_tables = [
            t for t in (profile.supabase.tables.user_facing or [])
        ] if profile.supabase and profile.supabase.tables else []

        if resp.status_code == 200:
            body = resp.text
            exposed_sensitive = [
                table for table in user_facing_tables
                if f'"{table}"' in body or f"/{table}" in body
            ]
            assert not exposed_sensitive, (
                "User-facing tables appear in the anonymous PostgREST schema: "
                + str(exposed_sensitive)
                + ". Verify RLS policies restrict anon reads on these tables."
            )

    @pytest.mark.supabase
    def test_auth_settings_does_not_expose_sensitive_config(self, profile, evidence):
        """GET /auth/v1/settings — check for sensitive configuration exposure.

        Supabase Auth exposes a /settings endpoint that can reveal:
          - Enabled auth providers (acceptable)
          - SMTP credentials or OAuth secrets (NOT acceptable)
          - Disable signup flag (acceptable)

        FAIL: If SMTP passwords, OAuth secrets, or service role keys appear.
        """
        project_url = profile.supabase and profile.supabase.project_url
        if not project_url or "xxx" in project_url:
            pytest.skip("Supabase project_url not configured in profile")

        url = project_url.rstrip("/") + "/auth/v1/settings"

        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url)

        evidence.capture(resp, label="supabase_auth_settings")

        if resp.status_code != 200:
            # 401/404 means the endpoint is not publicly accessible — acceptable.
            return

        body = resp.text
        sensitive_indicators = [
            "smtp_password",
            "smtp_admin_email",
            "secret",
            "private_key",
            "service_role",
        ]
        found = [s for s in sensitive_indicators if s in body.lower()]
        assert not found, (
            f"Supabase /auth/v1/settings exposes potentially sensitive fields: "
            + str(found)
            + f". Body excerpt: {body[:500]!r}"
        )

    @pytest.mark.supabase
    def test_supabase_storage_bucket_not_public(self, profile, evidence):
        """GET /storage/v1/bucket — verify the user-files bucket is not public.

        A public storage bucket allows unauthenticated download of any object
        if the URL is known.  The user-files bucket must be private (RLS-gated).

        Finding: Public bucket + predictable object paths = data exfiltration risk.
        """
        project_url = profile.supabase and profile.supabase.project_url
        if not project_url or "xxx" in project_url:
            pytest.skip("Supabase project_url not configured in profile")

        anon_key = (profile.supabase and profile.supabase.anon_key) or ""
        url = project_url.rstrip("/") + "/storage/v1/bucket"

        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                url,
                headers={
                    "apikey": anon_key,
                    "Authorization": f"Bearer {anon_key}",
                },
            )

        evidence.capture(resp, label="supabase_storage_bucket_list")

        if resp.status_code != 200:
            # Not accessible anonymously — acceptable.
            return

        try:
            buckets = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"[warn] test_info_disclosure.test_supabase_storage_no_public_buckets: JSON parse failed: {exc}", file=sys.stderr)
            return

        if not isinstance(buckets, list):
            return

        public_user_buckets = [
            b for b in buckets
            if isinstance(b, dict)
            and b.get("public") is True
            and b.get("name") in (
                profile.supabase.storage_buckets or []
            )
        ]

        assert not public_user_buckets, (
            "User storage buckets are configured as public: "
            + str([b.get("name") for b in public_user_buckets])
            + ". Set public: false on all user-data buckets and enforce "
            "storage RLS policies."
        )
