"""API surface hardening tests.

Validates:
  - Rate limiting exists on the first anonymous endpoint declared by the profile.
  - HTTP method enforcement: POST-only endpoints reject other verbs with 405.
  - Error responses do not disclose internal details (stack traces, paths,
    Postgres error codes, node_modules references).
  - Missing Content-Type is handled gracefully (400, not 500).
  - HTTP TRACE is disabled (ASVS V13.4.4, CWE-650; Cross-Site Tracing).
  - Cookie-authenticated state changes require an anti-CSRF defense (ASVS
    V3.5.1, CWE-352).

Most tests here are stack-agnostic and need no special marker. The anti-CSRF
probe is the exception: it MUTATES (sends a state-changing request) so it carries
``@pytest.mark.write_probe`` (runs only under ``--full``/``--branch``) and
``@pytest.mark.asvs_extended`` (deselected unless ``SCAN_SCOPE=asvs``). Probes
that exercise a specific ASVS requirement are dual-tagged ``asvs``+``cwe`` for the
coverage ledger.
"""

from __future__ import annotations

import sys as _sys
import time
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
from helpers import EVIL_ORIGIN, FakeResponse, netlify_url, safe_text, send_request  # noqa: E402
from conftest import first_endpoint, probe_body_for  # noqa: E402


def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()

# ---------------------------------------------------------------------------
# Sensitive patterns — loaded from profile.sensitive_patterns when available,
# supplemented by universal infrastructure patterns that apply to any stack.
# ---------------------------------------------------------------------------

_UNIVERSAL_SENSITIVE_PATTERNS = (
    "node_modules",
    "at Object.",
    "at Function.",
    "at Module.",
    "Error: ENOENT",
    "SyntaxError",
    "UnhandledPromiseRejection",
    # Postgres error classes
    "42703",  # undefined_column
    "42P01",  # undefined_table
    "23503",  # foreign_key_violation
    "23505",  # unique_violation
    "ERROR:  ",  # Postgres verbose error prefix
    # File path indicators
    "/var/task/",
    "/opt/nodejs/",
    "/home/",
    "netlify/functions/",
)

_PROFILE_SENSITIVE_PATTERNS: tuple[str, ...] = (
    tuple(_PROFILE.sensitive_patterns)
    if _PROFILE and _PROFILE.sensitive_patterns
    else ()
)

_SENSITIVE_PATTERNS: tuple[str, ...] = _UNIVERSAL_SENSITIVE_PATTERNS + _PROFILE_SENSITIVE_PATTERNS


def _check_no_sensitive_content(body: str, context: str) -> None:
    """Assert that the response body contains no sensitive internal details."""
    body_lower = body.lower()
    for pattern in _SENSITIVE_PATTERNS:
        assert pattern.lower() not in body_lower, (
            f"[{context}] Response body contains sensitive pattern {pattern!r}. "
            f"Body excerpt: {body[:500]!r}"
        )


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def _first_anonymous_path(profile) -> str:
    """Return the first anonymous endpoint path, or skip if none are declared."""
    return first_endpoint(profile, "anonymous")["path"].lstrip("/")


class TestRateLimiting:
    """Verify that a rate-limiting mechanism exists on a public endpoint."""

    @pytest.mark.write_probe
    def test_anonymous_endpoint_rate_limited_under_burst(self, profile, evidence):
        """Send 100 rapid POST requests to the first anonymous endpoint.

        At least one response must be 429 (Too Many Requests) or contain a
        rate-limit indicator.  The test does not assert the exact threshold —
        only that the mechanism is present.

        Finding: PASS means rate limiting is active.
                 FAIL means 100 requests all succeeded, implying no rate limit.
        """
        url = netlify_url(profile, _first_anonymous_path(profile))
        payload = {"message": "ping", "session_id": "pentest-rate-limit-probe"}
        headers = {"Content-Type": "application/json"}

        statuses: list[int] = []
        with httpx.Client(timeout=10.0) as client:
            for _ in range(100):
                try:
                    resp = client.post(url, json=payload, headers=headers)
                    statuses.append(resp.status_code)
                    if resp.status_code == 429:
                        break
                except httpx.TransportError as exc:
                    # Transport failures (DNS, TLS, connectivity) are NOT rate-limit
                    # signals. Record the error and stop the burst — the endpoint is
                    # unreachable, not rate-limited.
                    pytest.fail(
                        f"Transport error after {len(statuses)} requests "
                        f"(endpoint unreachable, not rate-limited): {exc}"
                    )

        rate_limited = any(s == 429 for s in statuses)
        # Capture evidence before asserting so artifacts are written on failure.
        if not rate_limited:
            # Build a minimal synthetic response for the evidence logger.
            evidence.capture(
                FakeResponse(
                    status_code=200,
                    url=url,
                    body=f"All {len(statuses)} requests returned non-429. Statuses: {statuses}",
                ),
                label="rate_limit_miss",
            )
        assert rate_limited, (
            f"No 429 received after {len(statuses)} requests to {url}. "
            "Rate limiting appears absent. All statuses: "
            + str(statuses[:20])
            + ("..." if len(statuses) > 20 else "")
        )


# ---------------------------------------------------------------------------
# HTTP method enforcement
# ---------------------------------------------------------------------------

def _build_post_only_paths(profile) -> list[str]:
    """Return POST-only endpoint paths from the profile.

    Collects all endpoints with method=POST across authenticated, anonymous,
    payment, and internal categories.  Returns empty list when profile is None.
    """
    if profile is None or not profile.endpoints:
        return []
    paths: list[str] = []
    for group in ("authenticated", "anonymous", "payment", "internal"):
        eps = getattr(profile.endpoints, group, None)
        if not eps:
            continue
        for ep in eps:
            method = getattr(ep, "method", "POST")
            path = getattr(ep, "path", "")
            if method == "POST" and path:
                paths.append(path.lstrip("/"))
    return paths


# Collection-time resolution.
_POST_ONLY_PATHS = _build_post_only_paths(_PROFILE)

_DISALLOWED_METHODS = ["GET", "PUT", "DELETE"]


class TestMethodEnforcement:
    """POST-only endpoints must reject non-POST verbs with 405."""

    @pytest.mark.parametrize("path", _POST_ONLY_PATHS)
    @pytest.mark.parametrize("method", _DISALLOWED_METHODS)
    def test_wrong_method_returns_405(self, profile, path, method, evidence):
        """Send {method} to a POST-only endpoint; expect 405, not 200 or 500.

        A 200 indicates the endpoint accepts unexpected methods (logic gap).
        A 500 indicates an unhandled dispatch error (information leak risk).
        Both are failures.
        """
        url = netlify_url(profile, path)
        with httpx.Client(timeout=10.0) as client:
            resp = client.request(method, url)

        if resp.status_code in (200, 500):
            evidence.capture(resp, label=f"{path}_{method}_method_abuse")

        assert resp.status_code not in (200, 500), (
            f"{method} {url} returned {resp.status_code}. "
            "Expected 405 Method Not Allowed (or 401/403/404). "
            f"Body: {resp.text[:300]!r}"
        )

    @pytest.mark.parametrize("path", _POST_ONLY_PATHS)
    def test_options_does_not_return_500(self, profile, path, evidence):
        """OPTIONS preflight must not return 500 (should be 200/204 or 405)."""
        url = netlify_url(profile, path)
        with httpx.Client(timeout=10.0) as client:
            resp = client.options(
                url,
                headers={
                    "Origin": (profile.target and profile.target.base_url) or "",
                    "Access-Control-Request-Method": "POST",
                },
            )

        if resp.status_code == 500:
            evidence.capture(resp, label=f"{path}_options_500")

        assert resp.status_code != 500, (
            f"OPTIONS {url} returned 500. "
            f"Body: {resp.text[:300]!r}"
        )


# ---------------------------------------------------------------------------
# HTTP TRACE / method hardening (ASVS V13.4.4, CWE-650)
# ---------------------------------------------------------------------------

class TestTraceMethod:
    """The HTTP TRACE method must be disabled (Cross-Site Tracing defense).

    TRACE echoes the inbound request (headers included) back in the response
    body. Historically this enabled Cross-Site Tracing (XST): script on another
    origin coaxes the browser into a TRACE request and reads back HttpOnly
    cookies the browser would otherwise hide from JavaScript. Modern browsers
    block TRACE from fetch/XHR, but an enabled TRACE still signals a permissive
    server/method configuration and can leak request data through other vectors,
    so ASVS V13.4.4 requires it be disabled.

    Host-derived: TRACE handling is a server/CDN/function-gateway concern, not a
    per-route one, so this probes the application origin once rather than every
    endpoint. Skips cleanly on placeholder-host example profiles via the
    ``profile`` fixture.
    """

    @pytest.mark.asvs("13.4.4")
    @pytest.mark.cwe("650")
    def test_trace_method_is_rejected(self, profile, evidence):
        """Send TRACE to the application origin; a 200 means TRACE is honored.

        A correctly configured server rejects TRACE (405 Method Not Allowed, 501
        Not Implemented, or 403). A 200, especially one that echoes the request
        line/headers, is the finding.
        """
        base_url = (profile.target and profile.target.base_url) or ""
        if not base_url:
            pytest.skip("Profile declares no target.base_url for the TRACE probe")
        url = base_url.rstrip("/") + "/"

        try:
            resp = send_request("TRACE", url, timeout=10.0)
        except httpx.TransportError as exc:
            pytest.skip(
                f"Application origin unreachable for TRACE probe "
                f"({type(exc).__name__}: {exc})"
            )

        # A reflected request line is the unmistakable XST signature; check only
        # a short prefix so a large echoed body is not scanned in full.
        body_head = safe_text(resp)[:200].upper()
        echoed = "TRACE " in body_head

        if resp.status_code == 200:
            # Headers/status only: an echoed TRACE body can carry request
            # headers we must not persist. Mirror the sanitized-FakeResponse
            # pattern used elsewhere in the suite.
            evidence.capture(
                FakeResponse(
                    resp.status_code, url,
                    f"[body omitted] TRACE returned 200 (request echoed: {echoed})",
                    "TRACE",
                ),
                label="trace_method_enabled",
            )

        assert resp.status_code != 200, (
            f"TRACE {url} returned 200 (request echoed: {echoed}). HTTP TRACE is "
            "enabled, exposing the app to Cross-Site Tracing. Disable TRACE/TRACK "
            "at the web server, CDN, or function gateway and return 405 for it "
            "(ASVS V13.4.4, CWE-650)."
        )


# ---------------------------------------------------------------------------
# Anti-CSRF on cookie-authenticated state changes (ASVS V3.5.1, CWE-352)
# ---------------------------------------------------------------------------

def _strip_csrf_cookies(cookie_header: str) -> str:
    """Return *cookie_header* with any CSRF/XSRF token cookie removed.

    Models a cross-site attacker: a real browser still attaches the ambient
    session cookie to a forged request, but the attacker cannot read or replay
    the application's double-submit anti-CSRF token cookie. Cookie pairs whose
    name contains ``csrf`` or ``xsrf`` (case-insensitive) are dropped; the rest
    (notably the session cookie) are kept.
    """
    kept: list[str] = []
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        name = pair.split("=", 1)[0].lower()
        if "csrf" in name or "xsrf" in name:
            continue
        kept.append(pair)
    return "; ".join(kept)


# Status codes that indicate the server DELIBERATELY refused the cross-site,
# tokenless forgery (a CSRF defense is present: origin/Referer check or a
# validated token). A transient rejection (429 rate limit, 5xx, a 3xx redirect)
# proves nothing, so those skip-inconclusive rather than pass.
_CSRF_DEFENSE_REJECTION_CODES = frozenset({400, 401, 403, 419})
# Codes on the cookieless control that prove the endpoint required the ambient
# session, so the cookie was the differentiator in a genuine CSRF.
_SESSION_REQUIRED_CODES = frozenset({401, 403})


def _csrf_forgery_outcome(
    forged_status: int, cookieless_status: int | None = None
) -> str:
    """Classify the CSRF probe legs into a single outcome (pure, for unit tests).

    ``cookieless_status`` is only consulted once the forgery was accepted (2xx);
    callers pass ``None`` first to learn whether the cookieless leg is needed.

    Returns one of:
      - ``"defended"``: forgery deliberately rejected (CSRF defense present; pass).
      - ``"inconclusive_forgery"``: forgery got a transient/ambiguous non-2xx.
      - ``"need_cookieless"``: forgery accepted; send the cookieless control next.
      - ``"auth_gap"``: cookieless control also accepted (not CSRF, an auth gap).
      - ``"csrf"``: forgery accepted, cookieless cleanly auth-rejected (the finding).
      - ``"inconclusive_cookieless"``: cookieless control was an ambiguous non-2xx.
    """
    if forged_status in _CSRF_DEFENSE_REJECTION_CODES:
        return "defended"
    if forged_status // 100 != 2:
        return "inconclusive_forgery"
    if cookieless_status is None:
        return "need_cookieless"
    if cookieless_status // 100 == 2:
        return "auth_gap"
    if cookieless_status in _SESSION_REQUIRED_CODES:
        return "csrf"
    return "inconclusive_cookieless"


class TestCSRFProtection:
    """A cookie-authenticated state change must reject a cross-site forgery.

    CSRF only applies when the credential is *ambient*: the browser attaches it
    automatically to any request to the origin. That is true for cookie-session
    auth, and structurally false for Bearer-token auth (a cross-site page cannot
    make the browser add an ``Authorization`` header), so this probe dispatches on
    ``auth_adapter.auth_type`` and skips Bearer stacks with a reason rather than
    a green pass.

    Method (cookie auth only):
      1. Positive control: send the legitimate authenticated request through the
         shared cookie session. If it is not accepted (non-2xx) the baseline is
         unusable (e.g. the endpoint needs a body the profile does not supply), so
         the negative result would be meaningless and the test skips inconclusive.
      2. Forgery: replay the same request from a bare client carrying ONLY the
         session cookie (CSRF token cookies stripped) plus a cross-site
         ``Origin``/``Referer`` and no anti-CSRF token. A deliberate rejection
         (400/401/403/419) means a CSRF defense refused it (pass). A transient
         non-2xx (429 rate limit, 5xx, redirect) proves nothing, so the test skips
         inconclusive rather than passing.
      3. Cookieless control: if the forgery was accepted (2xx), replay it once more
         with NO cookie. If the cookieless request is also accepted, the endpoint
         does not depend on the ambient session, so this is an authentication gap,
         not CSRF, and the test skips. The finding (CWE-352) requires the
         cookie-bearing forgery to succeed while the cookieless one is rejected with
         a clean auth status (401/403); any other cookieless status is treated as
         inconclusive (skip), not a finding. A transport error on either leg also
         skips inconclusive rather than erroring.

    Known limitations (documented, not bugs):
      - SameSite: httpx does not honor a cookie's ``SameSite`` attribute, so this
        probe always sends the session cookie. An app whose ONLY CSRF defense is
        ``SameSite=Strict``/``Lax`` on the session cookie (a valid browser-enforced
        defense) could therefore report a finding a real browser would not reach.
        The failure message says so; confirm the session cookie's ``SameSite`` flag
        before treating a finding as exploitable. The probe targets the
        server-side origin/token check specifically.
      - Read endpoints: the first ``authenticated`` endpoint may be a read declared
        POST. CSRF on a pure read is not a vulnerability, but black-box the probe
        cannot tell a 2xx read from a 2xx state change, so an operator should
        confirm the endpoint actually mutates before acting on a finding.

    Safety: this MUTATES. It sends up to three real requests to the endpoint (the
    legitimate control, the cookie-bearing forgery, and the cookieless control), so
    a vulnerable target may apply the state change more than once. It carries
    ``write_probe``/``asvs_extended`` and runs only under
    ``--full``/``--branch`` + ``SCAN_SCOPE=asvs``. Like the rate-limit burst
    probe, the mutations are not torn down, so run it against a branch/staging
    target.
    """

    @pytest.mark.write_probe
    @pytest.mark.asvs_extended
    @pytest.mark.asvs("3.5.1")
    @pytest.mark.cwe("352")
    def test_state_change_requires_anti_csrf_token(
        self, profile, auth_adapter, user_a_client, evidence
    ):
        """Forge a cross-site state change; the server must reject it."""
        if getattr(auth_adapter, "auth_type", "bearer") != "cookie":
            pytest.skip(
                "Auth uses Bearer tokens in the Authorization header (a "
                "non-ambient credential). A cross-site page cannot make the "
                "browser attach an Authorization header, so request forgery "
                "cannot carry the victim's credential; the anti-CSRF token "
                "control (ASVS V3.5.1, CWE-352) is structurally not applicable to "
                "this stack. Re-run against a cookie-session target (e.g. "
                "NextAuth) to exercise it."
            )

        endpoint = first_endpoint(profile, "authenticated")
        path = endpoint["path"]
        method = (endpoint.get("method") or "POST").upper()
        body = probe_body_for(endpoint)
        url = netlify_url(profile, path)

        # --- Positive control: a legitimate authenticated request is accepted ---
        try:
            control = user_a_client.request(method, url, json=body, timeout=15)
        except httpx.HTTPError as exc:
            pytest.skip(
                f"Authenticated endpoint {path} unreachable "
                f"({type(exc).__name__}), so a CSRF baseline cannot be established"
            )
        if control.status_code // 100 != 2:
            pytest.skip(
                f"Positive control failed: a legitimate authenticated {method} "
                f"{path} returned {control.status_code}, not 2xx. Without an "
                "accepted baseline the cross-site rejection test is "
                "inconclusive (the endpoint may require a body the profile does "
                "not supply)."
            )

        # --- Forgery: session cookie only, cross-site origin, no CSRF token ---
        session_cookie = _strip_csrf_cookies(
            auth_adapter.get_headers("user_a").get("Cookie", "")
        )
        if not session_cookie:
            pytest.skip(
                "Could not isolate a session cookie from the auth adapter "
                "(no Cookie header, or only CSRF-token cookies present), so a "
                "cross-site forgery cannot be modeled"
            )

        # Content-Type is set by send_request via json_body, so it is not passed
        # in forged_headers (passing both would duplicate the header).
        forged_headers = {
            "Cookie": session_cookie,
            "Origin": EVIL_ORIGIN,
            "Referer": EVIL_ORIGIN + "/",
        }
        try:
            forged = send_request(method, url, headers=forged_headers, json_body=body)
        except httpx.HTTPError as exc:
            pytest.skip(
                f"Forged cross-site {method} {path} could not be sent "
                f"({type(exc).__name__}); the CSRF result is inconclusive"
            )

        outcome = _csrf_forgery_outcome(forged.status_code)
        if outcome == "defended":
            return  # server deliberately refused the forgery: a CSRF defense exists
        if outcome == "inconclusive_forgery":
            pytest.skip(
                f"Forged cross-site {method} {path} returned {forged.status_code}, "
                "which is neither an accept (2xx) nor a deliberate CSRF rejection "
                "(400/401/403/419); the result is inconclusive (likely rate "
                "limiting or a transient error)."
            )

        # The cookie-bearing forgery was accepted. Distinguish a genuine CSRF (the
        # session cookie is what let it through) from an endpoint that accepts
        # unauthenticated requests anyway (a missing-auth issue, not CWE-352):
        # replay the same cross-site request with NO cookie.
        anon_headers = {"Origin": EVIL_ORIGIN, "Referer": EVIL_ORIGIN + "/"}
        try:
            cookieless = send_request(method, url, headers=anon_headers, json_body=body)
        except httpx.HTTPError as exc:
            pytest.skip(
                f"Cookieless control for {path} could not be sent "
                f"({type(exc).__name__}); the CSRF result is inconclusive"
            )

        outcome = _csrf_forgery_outcome(forged.status_code, cookieless.status_code)
        if outcome == "auth_gap":
            pytest.skip(
                f"Endpoint {path} accepted the same cross-site {method} with NO "
                f"session cookie (status {cookieless.status_code}), so it does not "
                "depend on the ambient session. That is an authentication gap, not "
                "CSRF (CWE-352); investigate it via the auth-bypass probes instead."
            )
        if outcome == "inconclusive_cookieless":
            pytest.skip(
                f"Cookieless control for {path} returned {cookieless.status_code}, "
                "not a clean auth rejection (401/403), so it cannot be confirmed "
                "the session cookie was the differentiator; the CSRF result is "
                "inconclusive (likely rate limiting or a transient error)."
            )

        # outcome == "csrf": forgery accepted with the cookie, cleanly rejected
        # without it.
        evidence.capture(
            FakeResponse(
                forged.status_code, url,
                f"[body omitted] Forged cross-site {method} accepted "
                f"(status {forged.status_code}); cookieless control rejected "
                f"({cookieless.status_code}); legitimate control was "
                f"{control.status_code}.",
                method,
            ),
            label=f"{path.lstrip('/')}_csrf_forgery_accepted",
        )
        pytest.fail(
            f"HIGH: forged cross-site {method} {path} was accepted "
            f"(status {forged.status_code}) carrying only the session cookie with "
            f"a cross-site Origin and no anti-CSRF token, while the same request "
            f"with no cookie was rejected ({cookieless.status_code}). The endpoint "
            "performs a state change authenticated solely by the ambient session "
            "cookie, with no request-origin check and no synchronizer/double-submit "
            "token, so an attacker's page can act as the logged-in victim (ASVS "
            "V3.5.1, CWE-352). Confirm the session cookie is not SameSite=Lax or "
            "Strict (which a real browser would not send cross-site) before "
            "treating this as exploitable."
        )


# ---------------------------------------------------------------------------
# Error message disclosure
# ---------------------------------------------------------------------------

# Malformed payloads sent to every POST endpoint. Each is designed to trip a
# different parsing/validation path so a brittle handler surfaces a stack trace,
# a database driver error, or a filesystem path instead of a clean 4xx.
#   - empty object: missing every required field
#   - traversal string: filesystem path handling
#   - SQLi marker: database layer error handling
# Bytes payloads are sent as a raw body (content=...); dict payloads as JSON.
# The empty-body case exercises the parse-before-validate path where a handler
# that calls JSON.parse() before a null-check leaks a SyntaxError/stack trace.
_MALFORMED_PAYLOADS = [
    ("empty_object", {}),
    ("path_traversal", {"id": "../../etc/passwd"}),
    ("sqli_marker", {"id": "' OR 1=1 --"}),
    ("empty_body", b""),
]

# Status codes that represent a clean, handled rejection (no internal leak).
_CLEAN_ERROR_STATUSES = (400, 401, 403, 404, 405, 409, 415, 422, 429, 500)


class TestErrorDisclosure:
    """Error responses must not leak internal implementation details.

    Profile-driven: every POST endpoint declared by the active profile
    (authenticated, anonymous, payment, internal) is probed with each malformed
    payload. The endpoint set comes from the profile, so this covers any stack
    without naming a single application endpoint.
    """

    @pytest.mark.parametrize(
        "payload_id,payload",
        _MALFORMED_PAYLOADS,
        ids=[p[0] for p in _MALFORMED_PAYLOADS],
    )
    @pytest.mark.parametrize("path", _POST_ONLY_PATHS, ids=_POST_ONLY_PATHS or None)
    def test_malformed_payload_no_disclosure(
        self, profile, path, payload_id, payload, evidence
    ):
        """POST a malformed payload; response must not disclose internals.

        A clean handler returns a 4xx (or a generic 500) with no stack trace,
        Postgres error code, filesystem path, or node_modules reference in the
        body.
        """
        url = netlify_url(profile, path)
        post_kwargs = (
            {"content": payload} if isinstance(payload, (bytes, bytearray)) else {"json": payload}
        )
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                url,
                headers={"Content-Type": "application/json"},
                **post_kwargs,
            )

        context = f"{path}/{payload_id}"
        if resp.status_code not in _CLEAN_ERROR_STATUSES:
            evidence.capture(resp, label=f"{path}_{payload_id}_unexpected_status")
        assert resp.status_code in _CLEAN_ERROR_STATUSES, (
            f"[{context}] unexpected status {resp.status_code}"
        )
        _check_no_sensitive_content(resp.text, context)


# ---------------------------------------------------------------------------
# Missing Content-Type handling
# ---------------------------------------------------------------------------

# Reuse the profile-driven POST endpoint list for content-type tests.
_POST_ENDPOINTS_FOR_CONTENT_TYPE = _POST_ONLY_PATHS


class TestMissingContentType:
    """POST requests without Content-Type must get 400, not 500."""

    @pytest.mark.parametrize("path", _POST_ENDPOINTS_FOR_CONTENT_TYPE)
    def test_missing_content_type_returns_400_not_500(self, profile, path, evidence):
        """Send a POST with a JSON-shaped body but no Content-Type header.

        The server should validate the request envelope before attempting to
        parse the body. A 500 here indicates the parser crashes on unexpected
        input before validation runs — an internal error surfaced to the client.

        Expected: 400 Bad Request (or 401/403/415 Unsupported Media Type).
        Failure: 500 Internal Server Error.
        """
        url = netlify_url(profile, path)
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                url,
                content=b'{"test": true}',
                # Deliberately omit Content-Type header.
            )

        if resp.status_code == 500:
            evidence.capture(resp, label=f"{path}_no_content_type_500")

        assert resp.status_code != 500, (
            f"POST {url} without Content-Type returned 500. "
            "Server crashed on malformed request instead of returning 400. "
            f"Body: {resp.text[:300]!r}"
        )


# ---------------------------------------------------------------------------
# Offline unit tests: pure helpers (no profile, no network)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "cookie_header,expected",
    [
        # Session cookie kept, csrf-token cookie dropped.
        (
            "next-auth.csrf-token=abc; next-auth.session-token=xyz",
            "next-auth.session-token=xyz",
        ),
        # __Host-/__Secure- prefixes and an authjs variant.
        (
            "__Host-next-auth.csrf-token=v; __Secure-authjs.session-token=s",
            "__Secure-authjs.session-token=s",
        ),
        # XSRF naming is also stripped.
        ("XSRF-TOKEN=t; sid=1", "sid=1"),
        # A base64url-padded value containing '=' must not break name extraction
        # (split('=', 1) is load-bearing here).
        (
            "next-auth.csrf-token=abc==|sig; next-auth.session-token=xyz==",
            "next-auth.session-token=xyz==",
        ),
        # Nothing to strip.
        ("session=s", "session=s"),
        # Only a CSRF cookie present -> empty (caller then skips inconclusive).
        ("csrf-token=x", ""),
        # Empty input.
        ("", ""),
        # Extra whitespace is normalised.
        (" a=1 ;  csrfToken=2 ; b=3 ", "a=1; b=3"),
    ],
)
def test_strip_csrf_cookies(cookie_header, expected):
    assert _strip_csrf_cookies(cookie_header) == expected


@pytest.mark.parametrize(
    "forged,cookieless,expected",
    [
        # Forgery deliberately rejected -> a CSRF defense exists (pass).
        (403, None, "defended"),
        (401, None, "defended"),
        (400, None, "defended"),
        (419, None, "defended"),
        # Forgery got a transient/ambiguous non-2xx -> inconclusive, never a pass.
        (429, None, "inconclusive_forgery"),
        (503, None, "inconclusive_forgery"),
        (302, None, "inconclusive_forgery"),
        # Forgery accepted -> the cookieless control is needed next.
        (200, None, "need_cookieless"),
        (204, None, "need_cookieless"),
        # Cookieless also accepted -> auth gap, not CSRF.
        (200, 200, "auth_gap"),
        (200, 204, "auth_gap"),
        # Cookieless cleanly auth-rejected -> the session was the differentiator.
        (200, 401, "csrf"),
        (200, 403, "csrf"),
        # Cookieless ambiguous (rate limit / transient / validation) -> inconclusive,
        # never escalated to a finding.
        (200, 429, "inconclusive_cookieless"),
        (200, 500, "inconclusive_cookieless"),
        (200, 400, "inconclusive_cookieless"),
    ],
)
def test_csrf_forgery_outcome(forged, cookieless, expected):
    assert _csrf_forgery_outcome(forged, cookieless) == expected


def test_send_request_dispatches_nonstandard_verb_trace(monkeypatch):
    """send_request must build a TRACE request without AttributeError.

    Regression: dispatch via getattr(client, method.lower()) had no attribute for
    'trace' (httpx.Client exposes only the standard verbs as methods), so the
    TRACE probe raised AttributeError before any request was built and could never
    reach a live target. A MockTransport keeps this offline (no socket).
    """
    import helpers

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        return httpx.Response(405)

    real_client = httpx.Client

    def _client_with_mock(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(helpers.httpx, "Client", _client_with_mock)

    resp = helpers.send_request("TRACE", "https://example.com/")

    assert captured["method"] == "TRACE"
    assert resp.status_code == 405
