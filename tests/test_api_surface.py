"""API surface hardening tests.

Validates:
  - Rate limiting exists on the first anonymous endpoint declared by the profile.
  - HTTP method enforcement: POST-only endpoints reject other verbs with 405.
  - Error responses do not disclose internal details (stack traces, paths,
    Postgres error codes, node_modules references).
  - Missing Content-Type is handled gracefully (400, not 500).

These tests are stack-agnostic — no special marker required.
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
from helpers import netlify_url  # noqa: E402
from conftest import first_endpoint  # noqa: E402


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
            # Create a synthetic response-like object for evidence.
            evidence.capture(
                # Build a minimal fake response for the evidence logger.
                _FakeResponse(
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
# Internal helper — minimal fake response for evidence capture
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal duck-type of httpx.Response for use with EvidenceCapture."""

    def __init__(self, status_code: int, url: str, body: str) -> None:
        import httpx as _httpx

        self.status_code = status_code
        self.text = body
        self.content = body.encode()
        self.headers = {}
        self.request = _httpx.Request("GET", url)
