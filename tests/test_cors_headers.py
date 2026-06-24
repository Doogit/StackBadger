"""CORS policy and security headers tests.

Validates:
  - CORS origin reflection: no endpoint reflects arbitrary origins or returns
    Access-Control-Allow-Origin: *.
  - Security headers on the main page (CSP, X-Frame-Options, HSTS, etc.).
    NOTE: These are KNOWN gaps — tests are expected to fail in the current
    deployment. Failures document the missing controls.
  - Clerk session cookie flags: Secure, HttpOnly, SameSite.

These tests are stack-agnostic — no special marker required.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path

import httpx
import pytest

# ---------------------------------------------------------------------------
# Collection-time profile loading
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile, resolve_profile_path  # noqa: E402
from helpers import FakeResponse, cache_control_is_safe, netlify_url  # noqa: E402
from conftest import first_endpoint, probe_body_for  # noqa: E402


def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_acao(response: httpx.Response) -> str | None:
    """Return the Access-Control-Allow-Origin header value, or None."""
    return response.headers.get("access-control-allow-origin")


# ---------------------------------------------------------------------------
# CORS origin reflection
# ---------------------------------------------------------------------------

# Netlify function endpoints to probe for CORS misconfig.
# Built from the active profile's browser-facing endpoints (authenticated,
# anonymous, payment).  Webhooks and internal endpoints are server-to-server
# and not CORS-relevant.

def _build_cors_paths(profile) -> list[str]:
    """Return browser-facing endpoint paths from the profile.

    Returns empty list when profile is None — tests will not be collected.
    """
    if profile is None or not profile.endpoints:
        return []
    paths: list[str] = []
    for group in ("authenticated", "anonymous", "payment"):
        eps = getattr(profile.endpoints, group, None)
        if not eps:
            continue
        for ep in eps:
            path = getattr(ep, "path", "")
            if path:
                paths.append(path.lstrip("/"))
    return paths


_NETLIFY_CORS_PATHS = _build_cors_paths(_PROFILE)

_EVIL_ORIGIN = "https://evil.com"

# The allowed origin — derived from profile.target.base_url at collection time.
_ALLOWED_ORIGIN: str = (
    _PROFILE.target.base_url.rstrip("/")
    if _PROFILE and _PROFILE.target and _PROFILE.target.base_url
    else ""
)


class TestCORSOriginReflection:
    """No endpoint should reflect arbitrary origins or use wildcard ACAO."""

    @pytest.mark.parametrize("path", _NETLIFY_CORS_PATHS)
    def test_netlify_function_does_not_reflect_evil_origin(
        self, profile, path, evidence
    ):
        """Send a POST with Origin: https://evil.com to each Netlify function.

        A correct CORS implementation will:
          - Return ACAO absent, or
          - Return ACAO matching the site's configured allowed origin only.

        FAIL conditions:
          - ACAO: * (wildcard — allows any browser to read the response)
          - ACAO: https://evil.com (origin reflection — attacker controls the header)

        Finding: CORS misconfiguration can allow cross-origin credential theft
        when combined with Clerk session cookies.
        """
        url = netlify_url(profile, path)
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                url,
                json={},
                headers={
                    "Origin": _EVIL_ORIGIN,
                    "Content-Type": "application/json",
                },
            )

        acao = _get_acao(resp)

        if acao in ("*", _EVIL_ORIGIN):
            evidence.capture(resp, label=f"{path}_cors_reflection")

        assert acao not in ("*", _EVIL_ORIGIN), (
            f"CORS misconfiguration on /.netlify/functions/{path}: "
            f"Access-Control-Allow-Origin: {acao!r}. "
            "Endpoint reflects the attacker-controlled origin or uses wildcard."
        )

    def test_supabase_postgrest_does_not_reflect_evil_origin(self, profile, evidence):
        """Send a request with Origin: evil.com to the Supabase PostgREST root.

        Supabase by default restricts CORS to configured allowed origins.
        This test verifies that the project-level CORS setting is not set to *.

        NOTE: The anon-key header is included so the server can parse the
        request — without it PostgREST returns 401 before evaluating CORS.
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
                    "Origin": _EVIL_ORIGIN,
                    "apikey": anon_key,
                    "Authorization": f"Bearer {anon_key}",
                },
            )

        acao = _get_acao(resp)

        if acao in ("*", _EVIL_ORIGIN):
            evidence.capture(resp, label="supabase_cors_reflection")

        assert acao not in ("*", _EVIL_ORIGIN), (
            f"Supabase CORS misconfiguration: "
            f"Access-Control-Allow-Origin: {acao!r}. "
            "PostgREST reflects attacker origin or uses wildcard."
        )

    @pytest.mark.parametrize("path", _NETLIFY_CORS_PATHS)
    def test_no_wildcard_on_options_preflight(self, profile, path, evidence):
        """OPTIONS preflight must not return ACAO: *.

        A wildcard on a preflight bypasses the browser's CORS restriction
        entirely for simple cross-origin requests.
        """
        url = netlify_url(profile, path)
        with httpx.Client(timeout=10.0) as client:
            resp = client.options(
                url,
                headers={
                    "Origin": _EVIL_ORIGIN,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type,authorization",
                },
            )

        acao = _get_acao(resp)

        if acao == "*":
            evidence.capture(resp, label=f"{path}_preflight_wildcard")

        assert acao != "*", (
            f"OPTIONS preflight for /.netlify/functions/{path} returns ACAO: *. "
            "Wildcard on preflight allows cross-origin reads from any domain."
        )


# ---------------------------------------------------------------------------
# Security headers on the main page
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    """Main page must include standard security response headers.

    NOTE: These tests are EXPECTED TO FAIL in the current deployment.
    Netlify does not inject these headers by default; they must be configured
    in netlify.toml [[headers]] blocks.  Failures here document the gap and
    provide the evidence artefacts for the remediation ticket.
    """

    @pytest.fixture(scope="class")
    def main_page_response(self, profile):
        """Fetch the main page once and share across tests in this class."""
        base_url = (profile.target and profile.target.base_url) or ""
        with httpx.Client(
            timeout=15.0,
            follow_redirects=True,
        ) as client:
            return client.get(base_url + "/")

    def test_content_security_policy_present(self, main_page_response, evidence):
        """Content-Security-Policy header must be present.

        CSP prevents XSS attacks from loading external scripts and exfiltrating
        data via unauthorized fetch() calls.

        KNOWN GAP: Not currently configured in netlify.toml.
        """
        resp = main_page_response
        csp = resp.headers.get("content-security-policy")
        if not csp:
            evidence.capture(resp, label="missing_csp")
        assert csp, (
            "Content-Security-Policy header is absent on the main page. "
            "Add a CSP directive in netlify.toml [[headers]] for /*."
        )

    def test_x_frame_options_present(self, main_page_response, evidence):
        """X-Frame-Options must be DENY or SAMEORIGIN.

        Prevents clickjacking — embedding the app in an attacker-controlled
        iframe to intercept user interactions.

        KNOWN GAP: Not currently configured in netlify.toml.
        """
        resp = main_page_response
        xfo = resp.headers.get("x-frame-options", "").upper()
        if xfo not in ("DENY", "SAMEORIGIN"):
            evidence.capture(resp, label="missing_xfo")
        assert xfo in ("DENY", "SAMEORIGIN"), (
            f"X-Frame-Options is {xfo!r}. Expected DENY or SAMEORIGIN. "
            "Add X-Frame-Options: DENY in netlify.toml [[headers]] for /*."
        )

    def test_strict_transport_security_present(self, main_page_response, evidence):
        """Strict-Transport-Security must be present with a meaningful max-age.

        HSTS prevents protocol downgrade attacks.  Netlify serves all custom
        domains over HTTPS, so this header should always be emitted.

        KNOWN GAP: Not currently configured in netlify.toml (Netlify may inject
        it automatically on Pro/Enterprise plans — this test verifies the actual
        behaviour).
        """
        resp = main_page_response
        hsts = resp.headers.get("strict-transport-security", "")
        if not hsts:
            evidence.capture(resp, label="missing_hsts")
        assert hsts, (
            "Strict-Transport-Security header is absent. "
            "Add HSTS with max-age >= 31536000 in netlify.toml [[headers]]."
        )
        # If present, verify max-age is set and not trivially small.
        match = re.search(r"max-age=(\d+)", hsts)
        if match:
            max_age = int(match.group(1))
            assert max_age >= 86400, (
                f"HSTS max-age={max_age} is less than 1 day. "
                "Use max-age=31536000 (1 year) minimum."
            )

    def test_x_content_type_options_nosniff(self, main_page_response, evidence):
        """X-Content-Type-Options must be 'nosniff'.

        Prevents browsers from MIME-sniffing responses — particularly
        important for JSON APIs that might be interpreted as HTML or JS.

        KNOWN GAP: Not currently configured in netlify.toml.
        """
        resp = main_page_response
        xcto = resp.headers.get("x-content-type-options", "").lower()
        if xcto != "nosniff":
            evidence.capture(resp, label="missing_xcto")
        assert xcto == "nosniff", (
            f"X-Content-Type-Options is {xcto!r}. Expected 'nosniff'. "
            "Add X-Content-Type-Options: nosniff in netlify.toml [[headers]] for /*."
        )

    def test_referrer_policy_present(self, main_page_response, evidence):
        """Referrer-Policy must be present.

        Without Referrer-Policy, the browser sends the full URL (including
        any query parameters containing upload IDs or tokens) to third-party
        origins referenced in the page.

        KNOWN GAP: Not currently configured in netlify.toml.
        """
        resp = main_page_response
        rp = resp.headers.get("referrer-policy", "")
        if not rp:
            evidence.capture(resp, label="missing_referrer_policy")
        assert rp, (
            "Referrer-Policy header is absent. "
            "Add Referrer-Policy: strict-origin-when-cross-origin in "
            "netlify.toml [[headers]] for /*."
        )


# ---------------------------------------------------------------------------
# Clerk cookie flags
# ---------------------------------------------------------------------------

class TestClerkCookieFlags:
    """Clerk session cookies must have Secure, HttpOnly, and SameSite flags."""

    @pytest.mark.clerk
    def test_clerk_cookies_have_secure_httponly_samesite(self, profile, evidence):
        """Fetch the main app page and inspect Set-Cookie headers.

        Clerk emits __clerk_db_jwt and __session cookies.  Both must have:
          - Secure: cookie only sent over HTTPS (prevents network sniffing)
          - HttpOnly: inaccessible to JavaScript (prevents XSS cookie theft)
          - SameSite=Lax or SameSite=Strict (CSRF mitigation)

        NOTE: Cookies are only set after the user authenticates.  This test
        checks the /sign-in page redirect response, which may carry the initial
        Clerk cookie.  If no cookies are present, the test is skipped rather
        than failed — absence on the unauthenticated landing page is expected.
        """
        base_url = (profile.target and profile.target.base_url) or ""
        with httpx.Client(
            timeout=15.0,
            follow_redirects=False,
        ) as client:
            resp = client.get(base_url + "/sign-in")

        # Collect all Set-Cookie headers.
        set_cookie_headers = resp.headers.get_list("set-cookie")
        clerk_cookies = [
            h for h in set_cookie_headers
            if "__clerk_db_jwt" in h or "__session" in h
        ]

        if not clerk_cookies:
            pytest.skip(
                "No Clerk cookies present on unauthenticated /sign-in request. "
                "Run this test with a full authenticated session to validate flags."
            )

        failures: list[str] = []
        for cookie_header in clerk_cookies:
            header_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0].strip()

            if "secure" not in header_lower:
                failures.append(f"{cookie_name}: missing Secure flag")

            if "httponly" not in header_lower:
                failures.append(f"{cookie_name}: missing HttpOnly flag")

            samesite_match = re.search(r"samesite=(\w+)", header_lower)
            if not samesite_match:
                failures.append(f"{cookie_name}: missing SameSite attribute")
            else:
                samesite_val = samesite_match.group(1)
                if samesite_val not in ("lax", "strict"):
                    failures.append(
                        f"{cookie_name}: SameSite={samesite_val!r} "
                        "(expected Lax or Strict)"
                    )

        if failures:
            evidence.capture(resp, label="clerk_cookie_flag_issues")

        assert not failures, (
            "Clerk cookie flag issues detected:\n"
            + "\n".join(f"  - {f}" for f in failures)
        )


# ---------------------------------------------------------------------------
# Cache-Control on authenticated responses (ASVS V14.3.2, CWE-524)
# ---------------------------------------------------------------------------

class TestAuthenticatedResponseCaching:
    """Authenticated responses must not be cacheable (no-store / no-cache / private).

    A sensitive, per-user response that lacks a restrictive Cache-Control may be
    written to a shared proxy or the browser disk cache and read back by a later
    user of the same machine or network (CWE-524). ASVS V14.3.2 requires
    sensitive responses carry Cache-Control: no-store (no-cache / private are
    accepted as adequate).
    """

    @pytest.mark.asvs("14.3.2")
    @pytest.mark.cwe("524")
    def test_authenticated_response_is_not_cacheable(
        self, profile, user_a_client, evidence
    ):
        """The first authenticated endpoint must return a non-cacheable response.

        The authenticated endpoint is derived from the profile
        (``first_endpoint(profile, "authenticated")``); skips cleanly when the
        profile declares none. Uses the signed-in user_a client so the response
        is genuinely sensitive/per-user.
        """
        endpoint = first_endpoint(profile, "authenticated")
        path = endpoint["path"]
        method = (endpoint.get("method") or "POST").upper()
        body = probe_body_for(endpoint)
        url = netlify_url(profile, path)

        try:
            resp = user_a_client.request(method, url, json=body, timeout=15)
        except httpx.HTTPError as exc:
            pytest.skip(
                f"Authenticated endpoint {path} unreachable "
                f"({type(exc).__name__}) — cannot check cache hygiene"
            )

        cache_control = resp.headers.get("cache-control", "")
        safe = cache_control_is_safe(cache_control)

        if not safe:
            # Capture headers only — the body may carry per-user PII we must not
            # persist. Mirror test_session's sanitized FakeResponse pattern.
            evidence.capture(
                FakeResponse(
                    resp.status_code, url,
                    f"[body omitted] Cache-Control: {cache_control or '(absent)'}",
                    method,
                ),
                label=f"{path.lstrip('/')}_cacheable_authenticated_response",
            )

        assert safe, (
            f"Authenticated response at {path} returned "
            f"Cache-Control: {cache_control or '(absent)'!r}. Sensitive per-user "
            "responses must set no-store (or no-cache / private) so credentials "
            "and PII are not written to shared or browser caches "
            "(ASVS V14.3.2, CWE-524)."
        )
