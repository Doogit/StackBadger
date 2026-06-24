"""OAuth / delegated-send probes — client-observable flow integrity + token storage.

ASVS 5.0: V10.2.1 (CSRF state), V10.2.3 (scope minimisation), V10.4.6
(PKCE / code_challenge), V10.5.1 (OIDC nonce), V10.1.1 (token storage).
CWE-352 (CSRF), CWE-347 (improper signature/claim validation), CWE-522
(insufficiently protected credentials).

Trust boundary (plan §P1-B, the load-bearing partition)
-------------------------------------------------------
The app under test is an OAuth **client** of Google / Microsoft. Only the
controls the *client* owns are probed here:

  - it generates a ``state`` and validates it on the callback (V10.2.1)
  - it sends a PKCE ``code_challenge`` with method ``S256`` (V10.4.6, emission)
  - it requests only the scopes it needs (V10.2.3)
  - for an OIDC flow it sends a ``nonce`` (V10.5.1)
  - delegated-send access/refresh tokens never reach the browser (V10.1.1)

The authorization-server-owned controls — redirect-URI exact-match (V10.4.1),
auth-code single-use + revocation (V10.4.2), PKCE *enforcement* (V10.4.6) — are
Google's / Microsoft's responsibility. Probing them would test the AS (out of
scope, no authorization) or pass regardless of the app, so they are recorded as
a **Track-C attestation** (skip-with-reason). Phase-1 exit must NOT go green on
AS-enforced behaviour — these render as skips, never passes.

Everything is derived from ``profile.oauth.delegated_send`` (no hardcoded app
names). Each probe skips with a reason when the field it needs is absent, so a
profile without a delegated-send BFF produces clean skips. All probes are
``asvs_extended`` (heavy pre-audit scope) and dual-tagged ``asvs`` + ``cwe``.

Safety
------
The token-storage read probes (status / token endpoints) are read-only. The
delegated-send probe actually triggers a server-side send, so it carries
``@pytest.mark.write_probe`` (read-only mode skips it) and only fires when the
profile supplies a ``probe_body`` for the send endpoint. Evidence bodies are
additionally scrubbed for tokens / Gmail-Drive content by ``reports.scrub``.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from conftest import endpoints_for_category, probe_body_for  # noqa: E402,F401
from helpers import FakeResponse, auth_provider as _auth_provider, safe_text as _safe_text  # noqa: E402

# OIDC / framework scopes that are benign regardless of the declared API scopes:
# they grant identity/login or offline refresh, not restricted data access, so a
# request for them is not a scope-minimisation finding.
_BENIGN_SCOPES = frozenset(
    {
        "openid",
        "email",
        "profile",
        "offline_access",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    }
)

# Token-material markers used by the V10.1.1 leakage probes. ya29. = Google
# access token, 1// = Google refresh token; the JSON field names cover Google +
# Microsoft Graph token responses.
_TOKEN_BODY_MARKERS = (
    "ya29.",
    "access_token",
    "refresh_token",
    "id_token",
)
_GOOGLE_TOKEN_SHAPE_RE = re.compile(r"ya29\.[A-Za-z0-9_.\-]{10,}|1//[0-9A-Za-z_\-]{10,}")


# ---------------------------------------------------------------------------
# Profile accessors / helpers
# ---------------------------------------------------------------------------

def _delegated_send(profile):
    """Return the ``oauth.delegated_send`` block, or skip when absent."""
    oauth = profile.oauth
    ds = oauth.delegated_send if oauth else None
    if ds is None:
        pytest.skip(
            "Profile declares no oauth.delegated_send block; OAuth client probes "
            "require authorize_url / scopes / send endpoints to be profile-derived."
        )
    return ds


def _abs_url(profile, path_or_url: str) -> str:
    """Resolve an app-relative path against the target origin; pass URLs through."""
    if path_or_url.startswith(("http://", "https://")):
        return path_or_url
    base = (profile.target and profile.target.base_url) or ""
    return base.rstrip("/") + "/" + path_or_url.lstrip("/")


def _request_or_skip(fn, what: str):
    """Run a live request thunk, converting a transport error into a clean skip."""
    try:
        return fn()
    except httpx.HTTPError as exc:
        pytest.skip(f"OAuth probe: {what} failed (network error: {type(exc).__name__})")


_URL_RE = re.compile(r'https?://[^\s"\'<>\\)]+')


def _looks_like_authorize_url(url: str) -> bool:
    """An authorization request carries client_id plus a redirect/response param."""
    return "client_id=" in url and ("redirect_uri=" in url or "response_type=" in url)


def _extract_authorize_url(resp) -> str | None:
    """Find the AS authorization URL the app sends the user to.

    Handles the two common shapes: a 3xx ``Location`` redirect to the AS, or a
    2xx JSON/HTML body that embeds the authorize URL (client builds the redirect).
    """
    loc = resp.headers.get("location", "")
    if loc and _looks_like_authorize_url(loc):
        return loc
    for cand in _URL_RE.findall(_safe_text(resp)):
        if _looks_like_authorize_url(cand):
            return cand
    return loc or None


def _authorize_params(profile, client, evidence, label: str) -> dict[str, list[str]]:
    """Observe the app's authorize request and return its query params.

    Fetches ``authorize_url`` without following redirects and parses the AS
    authorization URL's query. Skips (never fails) when the flow cannot be
    observed — a black-box prober that cannot see the authorize request must not
    assert anything about it.
    """
    ds = _delegated_send(profile)
    authorize_url = ds.authorize_url
    if not authorize_url:
        pytest.skip("oauth.delegated_send.authorize_url not set; cannot observe the flow.")
    url = _abs_url(profile, authorize_url)

    resp = _request_or_skip(
        lambda: client.get(url, follow_redirects=False, timeout=15),
        f"authorize request to {authorize_url}",
    )
    target = _extract_authorize_url(resp)
    # The authorize URL carries no secrets (state/code_challenge/scope are public
    # anti-CSRF / scope values), but capture only a param-name summary to keep the
    # full redirect target out of evidence by default.
    if not target:
        evidence.capture(
            FakeResponse(resp.status_code, url, "[no authorize redirect observed]", "GET"),
            label,
        )
        pytest.skip(
            f"Could not observe an OAuth authorize request from {authorize_url} "
            f"(HTTP {resp.status_code}, no AS redirect/URL in the response). The "
            "route may require an interactive session or build the redirect "
            "client-side beyond black-box reach."
        )
    params = parse_qs(urlparse(target).query)
    evidence.capture(
        FakeResponse(resp.status_code, url,
                     f"[authorize params present: {sorted(params)}]", "GET"),
        label,
    )
    if "client_id" not in params:
        pytest.skip(
            "Observed redirect is not an OAuth authorize request (no client_id); "
            "cannot evaluate state/PKCE/scope."
        )
    return params


def _requested_scopes(params: dict[str, list[str]]) -> list[str]:
    """Flatten the ``scope`` param (space- or plus-delimited) into a scope list."""
    raw = " ".join(params.get("scope", []))
    return [s for s in raw.replace("+", " ").split() if s]


# ---------------------------------------------------------------------------
# §P1-B — client-observable OAuth controls
# ---------------------------------------------------------------------------

@pytest.mark.asvs_extended
@pytest.mark.asvs("10.2.1")
@pytest.mark.cwe("352")
def test_oauth_authorize_emits_state(profile, user_a_client, evidence):
    """The app must send an unguessable ``state`` on the authorization request.

    ``state`` is the OAuth client's CSRF defence (V10.2.1, CWE-352): without it,
    an attacker can splice their own authorization code into a victim's session.
    Emission is client-observable; full validation (rejecting a mismatched state
    on the callback) also belongs to the client but needs a completed flow, so we
    assert the client at least emits a non-trivial state here.
    """
    params = _authorize_params(profile, user_a_client, evidence, "authorize_state")
    state_values = params.get("state", [])
    state = state_values[0] if state_values else ""
    assert state and len(state) >= 8, (
        f"OAuth authorize request omitted a usable 'state' parameter "
        f"(got {state!r}). The client must generate and later validate an "
        "unguessable state to prevent login CSRF (ASVS V10.2.1, CWE-352)."
    )


@pytest.mark.asvs_extended
@pytest.mark.asvs("10.4.6")
@pytest.mark.cwe("352")
def test_oauth_authorize_uses_pkce_s256(profile, user_a_client, evidence):
    """The app must send a PKCE ``code_challenge`` using method ``S256``.

    PKCE binds the authorization code to the client that started the flow,
    defeating code-interception attacks. Emission of ``code_challenge`` +
    ``code_challenge_method=S256`` is client-observable (V10.4.6). The AS-side
    *enforcement* of PKCE is attested separately (see the Track-C test).
    """
    params = _authorize_params(profile, user_a_client, evidence, "authorize_pkce")
    challenge = (params.get("code_challenge") or [""])[0]
    method = (params.get("code_challenge_method") or [""])[0].upper()
    assert challenge, (
        "OAuth authorize request omitted a PKCE 'code_challenge'. A public/SPA "
        "OAuth client must use PKCE so an intercepted authorization code cannot "
        "be redeemed by an attacker (ASVS V10.4.6)."
    )
    assert method == "S256", (
        f"OAuth authorize request used PKCE method {method!r}, not 'S256'. The "
        "'plain' method offers no protection if the challenge is intercepted; "
        "use S256 (ASVS V10.4.6)."
    )


@pytest.mark.asvs_extended
@pytest.mark.asvs("10.2.3")
@pytest.mark.cwe("352")
def test_oauth_requests_minimal_scopes(profile, user_a_client, evidence):
    """The app must request only the delegated scopes it declares it needs.

    Over-broad scope requests (e.g. asking for ``gmail.modify`` or full Drive
    when only ``gmail.send`` is needed) violate least privilege (V10.2.3) and
    enlarge the blast radius of a token compromise. Compares the requested scopes
    against ``required_scopes`` (benign OIDC/login scopes are allowed).
    """
    ds = _delegated_send(profile)
    required = list(ds.required_scopes or [])
    if not required:
        pytest.skip(
            "oauth.delegated_send.required_scopes not set; cannot evaluate scope "
            "minimisation without the app's declared scope baseline."
        )
    params = _authorize_params(profile, user_a_client, evidence, "authorize_scopes")
    requested = _requested_scopes(params)
    if not requested:
        pytest.skip("Authorize request exposed no 'scope' parameter to evaluate.")

    allowed = set(required) | _BENIGN_SCOPES
    extra = [s for s in requested if s not in allowed]
    assert not extra, (
        f"OAuth authorize request asks for scopes beyond the declared minimum: "
        f"{extra}. The app requests {requested} but declares it needs {required}. "
        "Request only the scopes required for delegated send (ASVS V10.2.3) — "
        "broader scopes expand the damage from a leaked token."
    )


@pytest.mark.asvs_extended
@pytest.mark.asvs("10.5.1")
@pytest.mark.cwe("347")
def test_oauth_oidc_emits_nonce(profile, user_a_client, evidence):
    """For an OIDC flow, the app must send a ``nonce`` to bind the ID token.

    ``nonce`` ties the returned ID token to this specific authorization request,
    defeating ID-token replay (V10.5.1, CWE-347). Only meaningful for an OIDC
    flow (``openid`` scope present); a pure OAuth delegated-send flow returns no
    ID token, so the probe records that as a skip rather than a finding. Full
    ID-token ``aud``/``iss``/``nonce`` *validation* requires forging a signed
    token (needs the AS key) and is AS-co-owned — see the Track-C attestation.
    """
    params = _authorize_params(profile, user_a_client, evidence, "authorize_nonce")
    requested = _requested_scopes(params)
    if "openid" not in requested:
        pytest.skip(
            "Not an OIDC flow (no 'openid' scope / no ID token issued); a nonce "
            "is not applicable to a pure OAuth delegated-send flow."
        )
    nonce = (params.get("nonce") or [""])[0]
    assert nonce and len(nonce) >= 8, (
        f"OIDC authorize request omitted a usable 'nonce' (got {nonce!r}). The "
        "client must send a nonce so a stolen ID token cannot be replayed into "
        "this session (ASVS V10.5.1, CWE-347)."
    )


@pytest.mark.asvs_extended
@pytest.mark.asvs("10.4.1")
@pytest.mark.cwe("347")
def test_oauth_as_owned_controls_are_attested(profile):
    """Track-C attestation: AS-owned OAuth controls are not StackBadger probes.

    Redirect-URI exact-match (V10.4.1), authorization-code single-use +
    revocation (V10.4.2) and PKCE *enforcement* (V10.4.6) are enforced by the
    authorization server (Google / Microsoft), not the app. Probing them would
    exercise the AS (out of scope, no authorization) or pass regardless of the
    app's posture. They are verified by provider attestation in Track C; this
    test exists so the control ids appear in the ledger as an explicit,
    auditable skip — never a green pass that would overstate Phase-1 coverage.
    """
    _delegated_send(profile)  # only relevant when a delegated-send flow exists
    pytest.skip(
        "Track-C attestation: redirect-URI exact-match (V10.4.1), auth-code "
        "single-use/revocation (V10.4.2) and PKCE enforcement (V10.4.6) are "
        "authorization-server-owned (Google/Microsoft). Verified by provider "
        "attestation, not by a black-box probe. Phase-1 exit must not go green "
        "on AS-enforced behaviour."
    )


# ---------------------------------------------------------------------------
# §P1-D — delegated-send token storage (V10.1.1 / CWE-522)
# ---------------------------------------------------------------------------

def _assert_no_token_in_body(body: str, where: str) -> None:
    """Fail when a response body carries OAuth token material."""
    lowered = body.lower()
    marker_hit = any(m in lowered for m in _TOKEN_BODY_MARKERS)
    shape_hit = bool(_GOOGLE_TOKEN_SHAPE_RE.search(body))
    assert not (marker_hit or shape_hit), (
        f"{where} returned OAuth token material to the browser. Delegated-send "
        "access/refresh tokens must be held server-side (e.g. a secrets vault) "
        "and never serialised to a client response (ASVS V10.1.1, CWE-522)."
    )


@pytest.mark.asvs_extended
@pytest.mark.asvs("10.1.1")
@pytest.mark.cwe("522")
def test_oauth_status_endpoint_does_not_leak_tokens(profile, user_a_client, evidence):
    """An OAuth connection-status endpoint must not echo stored tokens.

    A status/"is Gmail connected?" endpoint is a common place a poorly built BFF
    serialises the stored access/refresh token back to the SPA. Read-only:
    GETs each declared status endpoint as an authenticated user and asserts no
    token material appears (V10.1.1, CWE-522).
    """
    ds = _delegated_send(profile)
    status_eps = list(ds.status_endpoints or [])
    if not status_eps:
        pytest.skip("oauth.delegated_send.status_endpoints not set; nothing to check.")

    for ep in status_eps:
        path = ep["path"] if isinstance(ep, dict) else ep.path
        method = ((ep.get("method") if isinstance(ep, dict) else ep.method) or "GET").upper()
        url = _abs_url(profile, path)
        resp = _request_or_skip(
            lambda: user_a_client.request(method, url, timeout=15),
            f"status request to {path}",
        )
        body = _safe_text(resp)
        # Scrub before evidence; the body may legitimately contain a token we are
        # flagging, which must not be persisted verbatim.
        evidence.capture(
            FakeResponse(resp.status_code, url, "[status body omitted]", method),
            f"oauth_status_{path.strip('/').replace('/', '_')}",
        )
        if resp.status_code >= 400:
            continue  # endpoint not reachable as this user; nothing leaked
        _assert_no_token_in_body(body, f"OAuth status endpoint {path}")


@pytest.mark.asvs_extended
@pytest.mark.asvs("10.1.1")
@pytest.mark.cwe("522")
def test_oauth_token_endpoint_rejects_unprivileged_access(profile, anon_client, evidence):
    """A BFF token endpoint must not hand stored tokens to an unprivileged caller.

    If the app exposes a token-exchange / token-vault route, an anonymous (or
    ordinary browser) caller must not be able to read token material from it: it
    should reject (401/403/404) or, at most, return a non-token response. A 200
    carrying access/refresh-token material is a credential-exposure finding
    (V10.1.1, CWE-522). Sends a GET only (read-only); a write exchange route
    answering 405 counts as "did not leak".
    """
    ds = _delegated_send(profile)
    token_endpoint = ds.token_endpoint
    if not token_endpoint:
        pytest.skip("oauth.delegated_send.token_endpoint not set; nothing to check.")
    url = _abs_url(profile, token_endpoint)
    resp = _request_or_skip(
        lambda: anon_client.get(url, timeout=15, follow_redirects=False),
        f"anonymous token-endpoint request to {token_endpoint}",
    )
    body = _safe_text(resp)
    evidence.capture(
        FakeResponse(resp.status_code, url, "[token endpoint body omitted]", "GET"),
        "oauth_token_endpoint_anon",
    )
    if resp.status_code >= 400:
        return  # rejected — correct
    _assert_no_token_in_body(body, f"OAuth token endpoint {token_endpoint} (anonymous)")


@pytest.mark.asvs_extended
@pytest.mark.asvs("10.1.1")
@pytest.mark.cwe("522")
@pytest.mark.write_probe
def test_delegated_send_response_does_not_leak_tokens(profile, user_a_client, evidence):
    """Triggering a delegated send must not return token material to the browser.

    Mutating (it triggers a server-side send), so it is a write_probe and only
    runs under --full/--branch + --yes. Fires only when the profile supplies a
    ``probe_body`` for a send endpoint (an operator-controlled safe recipient),
    so the harness never blindly sends mail. Asserts the send response carries no
    access/refresh token (V10.1.1, CWE-522).
    """
    ds = _delegated_send(profile)
    send_eps = list(ds.send_endpoints or [])
    if not send_eps:
        pytest.skip("oauth.delegated_send.send_endpoints not set; nothing to send.")

    fired = False
    for ep in send_eps:
        ep_dict = dict(ep.items()) if hasattr(ep, "items") else ep
        path = ep_dict["path"]
        method = (ep_dict.get("method") or "POST").upper()
        body = probe_body_for(ep_dict)
        if not body:
            # No operator-supplied body → do not send a blind/malformed request.
            continue
        fired = True
        url = _abs_url(profile, path)
        resp = _request_or_skip(
            lambda: user_a_client.request(method, url, json=body, timeout=20),
            f"delegated send to {path}",
        )
        resp_body = _safe_text(resp)
        evidence.capture(
            FakeResponse(resp.status_code, url, "[send response body omitted]", method),
            f"oauth_send_{path.strip('/').replace('/', '_')}",
        )
        if resp.status_code >= 400:
            continue  # send rejected; no token returned
        _assert_no_token_in_body(resp_body, f"Delegated-send endpoint {path}")

    if not fired:
        pytest.skip(
            "No send endpoint had a probe_body; supply one (a safe test recipient) "
            "under oauth.delegated_send.send_endpoints[].probe_body to enable the "
            "token-leakage check on a live send."
        )


# ---------------------------------------------------------------------------
# Offline unit tests for the pure parsing / assertion helpers
# ---------------------------------------------------------------------------
# Live probes skip against the placeholder-host example profiles, so the helper
# logic is exercised here directly (no fixtures), mirroring test_session.py's
# offline regression for _credential_for_comparison.

_GOOGLE_AUTHORIZE = (
    "https://accounts.google.com/o/oauth2/v2/auth?response_type=code"
    "&client_id=abc.apps.googleusercontent.com"
    "&redirect_uri=https%3A%2F%2Fexample.com%2Fcb"
    "&state=xyzstate1234&code_challenge=Q1W2E3R4T5Y6&code_challenge_method=S256"
    "&scope=openid%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.send"
)


def test_looks_like_authorize_url():
    assert _looks_like_authorize_url(_GOOGLE_AUTHORIZE)
    assert _looks_like_authorize_url("https://as/auth?client_id=a&response_type=code")
    # No client_id → not an authorize request.
    assert not _looks_like_authorize_url("https://example.com/dashboard?redirect_uri=x")
    assert not _looks_like_authorize_url("https://example.com/login")


def test_extract_authorize_url_from_location():
    resp = FakeResponse(302, "https://example.com/api/oauth/google/authorize", "")
    resp.headers = {"location": _GOOGLE_AUTHORIZE}
    assert _extract_authorize_url(resp) == _GOOGLE_AUTHORIZE


def test_extract_authorize_url_from_json_body():
    body = '{"authorizeUrl":"' + _GOOGLE_AUTHORIZE + '"}'
    resp = FakeResponse(200, "https://example.com/api/oauth/google/authorize", body)
    assert _extract_authorize_url(resp) == _GOOGLE_AUTHORIZE


def test_extract_authorize_url_none_when_absent():
    resp = FakeResponse(200, "https://example.com/x", '{"ok":true}')
    assert _extract_authorize_url(resp) is None


def test_requested_scopes_parsing():
    params = parse_qs(urlparse(_GOOGLE_AUTHORIZE).query)
    scopes = _requested_scopes(params)
    assert "openid" in scopes
    assert "https://www.googleapis.com/auth/gmail.send" in scopes
    # Plus-delimited fallback.
    assert _requested_scopes({"scope": ["a+b+c"]}) == ["a", "b", "c"]
    assert _requested_scopes({}) == []


def test_assert_no_token_in_body_flags_token_material():
    for leak in (
        '{"access_token":"x"}',
        '{"refresh_token":"x"}',
        "token=ya29.a0AfH6SMByExampleToken12345",
        '{"id_token":"x"}',
    ):
        with pytest.raises(AssertionError):
            _assert_no_token_in_body(leak, "test")


def test_assert_no_token_in_body_passes_benign():
    # No token markers / shapes → no assertion.
    _assert_no_token_in_body('{"connected":true,"email_count":3}', "test")
    _assert_no_token_in_body("", "test")
