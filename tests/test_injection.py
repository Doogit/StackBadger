"""Injection tests: SQL injection, CSV formula injection, JSON injection,
CRLF header injection, and RPC parameter injection.

Test categories:
- SQL injection via API parameters (all authenticated and anonymous endpoints)
- CSV formula injection via file upload endpoints
- JSON structural injection (deeply nested, prototype pollution payloads)
- CRLF header injection
- Supabase RPC parameter injection (all client-callable RPCs)
"""

from __future__ import annotations

import json
import sys as _sys
import uuid
from pathlib import Path
from pathlib import Path as _Path

import httpx
import pytest

# ---------------------------------------------------------------------------
# Fixture path
# ---------------------------------------------------------------------------

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# ---------------------------------------------------------------------------
# Ensure the StackBadger package root is importable at collection time.
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from helpers import send_request  # noqa: E402


# ---------------------------------------------------------------------------
# Collection-time profile loading for parametrize decorators
# ---------------------------------------------------------------------------

def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        from profile import load_profile, resolve_profile_path  # type: ignore[import]
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()


def _collection_endpoints(category: str) -> list[dict]:
    """Get endpoints for parametrize — returns empty list if profile unavailable."""
    if _PROFILE is None:
        return []
    from conftest import endpoints_for_category
    return endpoints_for_category(_PROFILE, category)


def _collection_rpcs(tier: str) -> list[dict]:
    """Get RPCs for parametrize — returns empty list if profile unavailable."""
    if _PROFILE is None:
        return []
    from conftest import all_rpcs
    return all_rpcs(_PROFILE, tier)


# Endpoints with probe bodies (suitable for injection via body fields).
_ALL_ENDPOINTS_WITH_PROBE = [
    ep for ep in (
        _collection_endpoints("authenticated") + _collection_endpoints("anonymous")
    )
    if ep.get("probe_body")
]

# Paths of all authenticated + anonymous endpoints (for path-only parametrize).
_ALL_ENDPOINT_PATHS = [
    ep.get("path", "")
    for ep in (
        _collection_endpoints("authenticated") + _collection_endpoints("anonymous")
    )
    if ep.get("path")
]

# Client-callable RPCs for RPC injection tests.
_CLIENT_CALLABLE_RPCS = _collection_rpcs("client_callable")


# ---------------------------------------------------------------------------
# SQL injection payloads
# ---------------------------------------------------------------------------

_SQLI_PAYLOADS: list[str] = [
    "' OR 1=1 --",
    "'; DROP TABLE uploads --",
    "1 UNION SELECT null, null, null --",
    "' OR '1'='1",
    "1; SELECT pg_sleep(5) --",
    "' AND 1=CAST((SELECT version()) AS INT) --",
    "\\'; DROP TABLE users; --",
]

# ---------------------------------------------------------------------------
# CSV formula injection payloads (spreadsheet injection)
# ---------------------------------------------------------------------------

_FORMULA_PATTERNS: list[str] = [
    "=cmd|' /C calc'!A0",
    "+cmd|' /C calc'!A0",
    "-cmd|' /C calc'!A0",
    "@SUM(1+1)*cmd|' /C calc'!A0",
    '=HYPERLINK("http://evil.example.com")',
    "=1+1",
    "=IMPORTDATA(\"http://evil.example.com\")",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _endpoint_url(profile, path: str) -> str:
    base = (profile.target.base_url or "").rstrip("/")
    prefix = (profile.target.api_prefix or "/.netlify/functions").rstrip("/")
    return f"{base}{prefix}{path}"


def _assert_no_data_leak(resp: httpx.Response, payloads: list[str], context: str) -> None:
    """Assert that none of the injection payloads are echoed back in the response body."""
    body = resp.text
    for payload in payloads:
        assert payload not in body, (
            f"{context}: response body echoed back injection payload: {payload!r}"
        )


def _assert_safe_status(resp: httpx.Response, context: str) -> None:
    """Assert that the response is not a 500 (unhandled server error)."""
    assert resp.status_code != 500, (
        f"{context}: returned 500 (unhandled server error) — "
        "injection payload may have caused an unhandled exception"
    )


def _endpoint_id(ep: dict) -> str:
    """Human-readable pytest ID for an endpoint."""
    method = ep.get("method", "POST")
    path = ep.get("path", "unknown")
    return f"{method}:{path}"


def _rpc_id(rpc: dict) -> str:
    return rpc.get("name", "unknown")


# ---------------------------------------------------------------------------
# SQL injection via all endpoints with probe bodies
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "endpoint",
    _ALL_ENDPOINTS_WITH_PROBE,
    ids=[_endpoint_id(e) for e in _ALL_ENDPOINTS_WITH_PROBE],
)
@pytest.mark.parametrize("payload", _SQLI_PAYLOADS, ids=[f"sqli:{p[:20]!r}" for p in _SQLI_PAYLOADS])
def test_sqli_endpoint_probe_fields(payload, endpoint, profile, evidence):
    """Inject SQL payloads into all probe_body fields of each endpoint.

    Each field in the probe_body is replaced with the SQL payload in turn.
    The endpoint must return 4xx or 2xx (never 500) and must not reflect
    raw SQL in the response body.
    """
    from conftest import probe_body_for
    path = endpoint.get("path", "")
    method = endpoint.get("method", "POST")
    url = _endpoint_url(profile, path)
    base_body = probe_body_for(endpoint)

    # Inject the payload into every field of the probe body.
    for field in list(base_body.keys()):
        injected_body = dict(base_body)
        injected_body[field] = payload
        resp = send_request(method, url, json_body=injected_body)
        context = f"{method} {path} {field}={payload!r}"
        _assert_safe_status(resp, context)
        assert resp.status_code in range(200, 500), (
            f"{context}: returned {resp.status_code}; expected 2xx or 4xx, not 5xx"
        )
        _assert_no_data_leak(resp, _SQLI_PAYLOADS, context)
        if resp.status_code not in (400, 401, 403, 422):
            evidence.capture(resp, f"sqli_{path.lstrip('/')}_{field}_status_{resp.status_code}")


# ---------------------------------------------------------------------------
# CSV formula injection via file upload endpoints
# ---------------------------------------------------------------------------

def test_csv_formula_injection_upload(profile, evidence):
    """Upload the injection fixture to the upload endpoint; response must not echo formula payloads."""
    # The profile's upload endpoint is the single source of truth — skip when absent.
    upload_path = profile.uploads and profile.uploads.endpoint
    if not upload_path:
        pytest.skip("No upload endpoint defined in profile (profile.uploads.endpoint)")
    path = upload_path
    url = _endpoint_url(profile, path)
    fixture_path = _FIXTURES / "records_injection.csv"
    if not fixture_path.exists():
        pytest.skip(f"Fixture not found: {fixture_path}")
    content = fixture_path.read_bytes()
    files = {"file": ("records_injection.csv", content, "text/csv")}
    resp = send_request("POST", url, files=files)
    context = f"POST {path} (records_injection.csv)"
    _assert_safe_status(resp, context)
    # The response must not reflect raw formula strings that could be injected
    # into a downstream spreadsheet via the API response.
    _assert_no_data_leak(resp, _FORMULA_PATTERNS, context)
    if resp.status_code not in (200, 400, 401, 403, 422):
        evidence.capture(resp, f"csv_formula_injection_status_{resp.status_code}")


# ---------------------------------------------------------------------------
# JSON injection — deeply nested object (100 levels)
# ---------------------------------------------------------------------------

def _make_nested(depth: int) -> dict:
    """Build a JSON object nested to the given depth."""
    obj: dict = {"leaf": "value"}
    for _ in range(depth):
        obj = {"nested": obj}
    return obj


@pytest.mark.parametrize("path", _ALL_ENDPOINT_PATHS, ids=_ALL_ENDPOINT_PATHS)
def test_json_deep_nesting(path, profile, evidence):
    """Endpoints must not crash (500) when sent a 100-level nested JSON object."""
    url = _endpoint_url(profile, path)
    body = _make_nested(100)
    resp = send_request("POST", url, json_body=body)
    context = f"POST {path} (100-level nested JSON)"
    _assert_safe_status(resp, context)
    assert resp.status_code in range(200, 500), (
        f"{context}: returned {resp.status_code}; expected 2xx or 4xx"
    )
    if resp.status_code not in (400, 401, 403, 413, 422):
        evidence.capture(resp, f"json_deep_nesting_status_{resp.status_code}")


# ---------------------------------------------------------------------------
# JSON injection — prototype pollution via __proto__
# ---------------------------------------------------------------------------

_PROTOTYPE_PAYLOADS: list[dict] = [
    {"__proto__": {"admin": True}},
    {"constructor": {"prototype": {"admin": True}}},
    {"__proto__": {"isAdmin": True, "role": "superuser"}},
]


@pytest.mark.parametrize("path", _ALL_ENDPOINT_PATHS, ids=_ALL_ENDPOINT_PATHS)
@pytest.mark.parametrize(
    "proto_payload",
    _PROTOTYPE_PAYLOADS,
    ids=[f"proto:{list(p.keys())[0]}" for p in _PROTOTYPE_PAYLOADS],
)
def test_json_prototype_pollution(path, proto_payload, profile, evidence):
    """Endpoints must not crash or grant elevated access via prototype pollution payloads."""
    url = _endpoint_url(profile, path)
    resp = send_request("POST", url, json_body=proto_payload)
    context = f"POST {path} (prototype pollution: {proto_payload!r})"
    _assert_safe_status(resp, context)
    assert resp.status_code in range(200, 500), (
        f"{context}: returned {resp.status_code}; expected 2xx or 4xx"
    )
    # A 200 with no body change is acceptable only if this represents an auth rejection
    # wrapped as 200 — in practice we expect 400/401.
    if resp.status_code == 200:
        evidence.capture(resp, "json_prototype_pollution_200_review")
    if resp.status_code not in (400, 401, 403, 422):
        evidence.capture(resp, f"json_prototype_pollution_status_{resp.status_code}")


# ---------------------------------------------------------------------------
# CRLF header injection
# ---------------------------------------------------------------------------

_CRLF_PAYLOADS: list[str] = [
    "value\r\nX-Injected: true",
    "value\r\nSet-Cookie: session=injected",
    "value\r\n\r\n<html>injected</html>",
    "value%0d%0aX-Injected: true",
    "value%0aX-Injected: true",
]


@pytest.mark.parametrize("path", _ALL_ENDPOINT_PATHS, ids=_ALL_ENDPOINT_PATHS)
@pytest.mark.parametrize(
    "crlf_value",
    _CRLF_PAYLOADS,
    ids=[f"crlf:{v[:20]!r}" for v in _CRLF_PAYLOADS],
)
def test_crlf_header_injection(path, crlf_value, profile, evidence):
    """Endpoints must not crash or reflect injected headers for CRLF payloads in custom headers.

    httpx will raise on literal CRLF in header values (RFC 7230 compliance).
    Percent-encoded variants are passed through to test server-side decoding.
    """
    url = _endpoint_url(profile, path)
    try:
        headers = {"X-Custom-Header": crlf_value}
        resp = send_request("POST", url, headers=headers, json_body={"test": "crlf"})
        context = f"POST {path} (CRLF header: {crlf_value!r})"
        _assert_safe_status(resp, context)
        # Injected header must not appear in the response headers.
        response_header_names = [k.lower() for k in resp.headers.keys()]
        assert "x-injected" not in response_header_names, (
            f"{context}: response contained injected 'X-Injected' header — CRLF injection succeeded"
        )
        if resp.status_code not in (200, 400, 401, 403, 422):
            evidence.capture(resp, f"crlf_injection_status_{resp.status_code}")
    except (httpx.LocalProtocolError, ValueError):
        # httpx refuses to send literal CRLF in headers — this is correct client-side
        # enforcement. The test passes because the payload cannot even be transmitted.
        pass


# ---------------------------------------------------------------------------
# RPC parameter injection — all client-callable RPCs
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
@pytest.mark.supabase
@pytest.mark.parametrize(
    "rpc",
    _CLIENT_CALLABLE_RPCS,
    ids=[_rpc_id(r) for r in _CLIENT_CALLABLE_RPCS],
)
@pytest.mark.parametrize("payload", _SQLI_PAYLOADS, ids=[f"sqli:{p[:20]!r}" for p in _SQLI_PAYLOADS])
def test_rpc_sqli(payload, rpc, profile, anon_client, evidence):
    """Client-callable RPCs must not accept SQLi payloads in their parameters.

    Supabase PostgREST parameterises RPC arguments; this test verifies the
    endpoint does not expose raw SQL concatenation errors or data leaks.
    """
    supabase_url = (profile.supabase and profile.supabase.project_url) or ""
    if not supabase_url:
        pytest.skip("profile.supabase.project_url not set")
    rpc_name = rpc.get("name", "")
    rpc_url = supabase_url.rstrip("/") + f"/rest/v1/rpc/{rpc_name}"
    params = rpc.get("params") or []

    # Inject the SQLi payload into the first string-typed param; fill others with safe values.
    body: dict = {}
    first_injected = False
    for param in params:
        param_name = param if isinstance(param, str) else (param.get("name", "") if hasattr(param, "get") else str(param))
        if not first_injected:
            body[param_name] = payload
            first_injected = True
        elif "action" in param_name:
            body[param_name] = "include"
        elif "attestation" in param_name:
            body[param_name] = False
        else:
            body[param_name] = str(uuid.uuid4())

    if not body:
        body = {str(params[0]) if params else "anon_id": payload}

    resp = anon_client.post(rpc_url, json=body)
    context = f"RPC {rpc_name} sqli payload={payload!r}"
    _assert_safe_status(resp, context)
    _assert_no_data_leak(resp, _SQLI_PAYLOADS, context)
    if resp.status_code not in (200, 400, 401, 403, 404, 422):
        evidence.capture(resp, f"rpc_{rpc_name}_sqli_status_{resp.status_code}")
