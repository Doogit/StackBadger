"""Auth bypass tests for all Netlify Function endpoints.

Tests 7 bypass vectors across all JWT-authenticated endpoints:
1. No auth header
2. Expired JWT
3. Malformed JWT (alg: none)
4. Malformed JWT (HS256 confusion attack)
5. anon_session_id on auth-only endpoints
6. JWT from a different Clerk instance (wrong iss)
7. Stripped Bearer prefix (raw token, no "Bearer " prefix)

Additional tests:
- Internal endpoints reject requests without x-internal-secret
- Internal endpoints reject common guessable secrets
- Anonymous endpoints still require SOME form of auth
"""

from __future__ import annotations

import time
import uuid

import httpx
import jwt as pyjwt
import pytest

# ---------------------------------------------------------------------------
# Module-level constants — endpoint categories loaded at collection time
# from the YAML profile.  We defer to fixtures for the actual Profile object
# but need static lists for parametrize.  The profile loader is called once
# here and the result is used only for parametrisation; fixture-level profile
# access is used inside each test for URL construction so that the --profile
# CLI option is always respected.
# ---------------------------------------------------------------------------

import sys as _sys
from pathlib import Path as _Path

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from helpers import send_request  # noqa: E402


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


_AUTHENTICATED_ENDPOINTS = _collection_endpoints("authenticated")
_PAYMENT_ENDPOINTS = _collection_endpoints("payment")
_INTERNAL_ENDPOINTS = _collection_endpoints("internal")
_ANONYMOUS_ENDPOINTS = _collection_endpoints("anonymous")

# All endpoints that require a valid Clerk JWT (authenticated + payment).
_JWT_REQUIRED_ENDPOINTS = _AUTHENTICATED_ENDPOINTS + _PAYMENT_ENDPOINTS

# Common secrets to probe on internal endpoints.
# This is a generic wordlist — not site-specific.
_COMMON_SECRETS = ["secret", "password", "internal", "test", "admin", "changeme", "12345"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _endpoint_url(profile, endpoint: dict) -> str:
    """Build the full URL for an endpoint using the active profile."""
    base = (profile.target.base_url or "").rstrip("/")
    prefix = (profile.target.api_prefix or "/.netlify/functions").rstrip("/")
    path = endpoint.get("path", "")
    return f"{base}{prefix}{path}"


def _endpoint_id(endpoint: dict) -> str:
    """Human-readable pytest ID for an endpoint."""
    method = endpoint.get("method", "POST")
    path = endpoint.get("path", "unknown")
    return f"{method}:{path}"


def _make_expired_jwt() -> str:
    """Craft a JWT whose exp is 10 minutes in the past."""
    payload = {
        "sub": "user_pentest_expired",
        "iss": "https://clerk.example.com",
        "iat": int(time.time()) - 700,
        "exp": int(time.time()) - 600,  # expired 10 minutes ago
        "azp": "pentest",
    }
    # RS256 requires a real key; use HS256 with a dummy secret for a
    # syntactically valid but signature-invalid token.
    return pyjwt.encode(payload, "dummy-secret-not-valid", algorithm="HS256")


def _make_alg_none_jwt() -> str:
    """Craft a JWT with alg=none (unsigned).

    The token is hand-assembled so that the header literally contains
    ``"alg":"none"`` — PyJWT strips this header value in newer versions.
    """
    import base64
    import json

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "sub": "user_pentest_algnone",
        "iss": "https://clerk.example.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }).encode())
    # alg=none means an empty signature segment.
    return f"{header}.{payload}."


def _make_hs256_confusion_jwt() -> str:
    """Craft a JWT signed with HS256 using a random key.

    This tests for RS256→HS256 algorithm confusion: if the server
    verifies with the public key as an HMAC secret, the check passes.
    A correctly hardened server should reject a token signed with HS256
    when it expects RS256.
    """
    import secrets as _secrets
    random_key = _secrets.token_bytes(64)
    payload = {
        "sub": "user_pentest_hs256",
        "iss": "https://clerk.example.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return pyjwt.encode(payload, random_key, algorithm="HS256")


def _make_wrong_issuer_jwt() -> str:
    """Craft a JWT from a different Clerk instance (wrong iss claim)."""
    payload = {
        "sub": "user_pentest_wrongiss",
        "iss": "https://adversary.clerk.accounts.dev",  # different Clerk instance
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "azp": "pentest-adversary",
    }
    return pyjwt.encode(payload, "adversary-secret", algorithm="HS256")


# ---------------------------------------------------------------------------
# §P1-E — JWT audience / token-type hardening forgers
#
# These mirror the existing _make_*_jwt helpers: hand-built, structurally valid
# tokens signed with a throwaway HS256 secret. A correctly-hardened verifier
# rejects them on signature/issuer alone, but these probes specifically target
# the *claim-level* checks (aud, typ) so the forged claims are provider-shaped:
# the point is that even a token that otherwise looked plausible must be
# refused because its audience/type is wrong.
# ---------------------------------------------------------------------------

# Wrong-audience value the target must never accept.
_ATTACKER_AUDIENCE = "https://attacker.example"

# Per-provider iss values so the forged token at least carries a provider-shaped
# issuer; the aud/typ claim is the deliberately-wrong axis under test.
_PROVIDER_ISS = {
    "clerk": "https://clerk.example.com",
    "supabase-auth": "https://project.supabase.co/auth/v1",
    "firebase": "https://securetoken.google.com/example-project",
}


def _make_wrong_aud_jwt(provider: str) -> str:
    """Craft a structurally valid token whose ``aud`` is an attacker value.

    The token is provider-shaped (issuer + standard claims) but its audience is
    ``https://attacker.example`` — a value the target should never accept. If
    the endpoint returns 2xx the app ignores ``aud`` (ASVS V9.2.3 / CWE-345).
    """
    now = int(time.time())
    payload = {
        "sub": "user_pentest_wrong_aud",
        "iss": _PROVIDER_ISS.get(provider, "https://clerk.example.com"),
        "aud": _ATTACKER_AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "azp": "pentest",
    }
    return pyjwt.encode(payload, "wrong-aud-secret-not-valid", algorithm="HS256")


def _make_id_token_shaped_jwt(provider: str) -> str:
    """Craft an ID-token-shaped token presented where an access token is expected.

    Models an OIDC ``id_token``: ``typ: ID`` header, ``aud`` set to a client_id
    (the audience of an ID token, not a resource server), an OIDC identity
    profile (email / name), and deliberately NO scope/role/authorization claim.
    An access-token-expecting endpoint must reject it (ASVS V9.2.2 / CWE-347):
    an ID token authenticates the user to the *client*, it is not an
    authorization credential for an API.
    """
    now = int(time.time())
    header = {"alg": "HS256", "typ": "ID"}
    payload = {
        "sub": "user_pentest_idtoken",
        "iss": _PROVIDER_ISS.get(provider, "https://clerk.example.com"),
        # ID-token audience is the OIDC client_id, not the API/resource server.
        "aud": "pentest-oidc-client-id",
        "iat": now,
        "exp": now + 3600,
        "auth_time": now,
        "nonce": "pentest-nonce",
        "email": "pentest@attacker.example",
        "email_verified": True,
        "name": "Pentest Probe",
        # Intentionally NO scope / role / permission claim: this is an identity
        # token, not an access token.
    }
    return pyjwt.encode(
        payload, "id-token-secret-not-valid", algorithm="HS256", headers=header
    )


# JWT-bearer providers this family supports. NextAuth is cookie/session based
# (no JWT bearer to forge) and is handled with an explicit skip-with-reason.
_JWT_BEARER_PROVIDERS = ("clerk", "supabase-auth", "firebase")


def _auth_provider(profile) -> str:
    """Lower-cased active auth provider from the profile, or '' when absent."""
    return ((profile.stack and profile.stack.auth) or "").lower()


def _first_authenticated_url(profile) -> tuple[str, dict]:
    """Resolve the first authenticated endpoint URL from the profile, or skip.

    Derived from the profile (no hardcoded endpoint name); skips cleanly when
    the profile declares no authenticated endpoint.
    """
    from conftest import first_endpoint

    endpoint = first_endpoint(profile, "authenticated")
    return _endpoint_url(profile, endpoint), endpoint


def _skip_non_jwt_provider(provider: str) -> None:
    """Skip-with-reason for providers this JWT family cannot exercise."""
    if provider == "nextauth":
        pytest.skip(
            "NextAuth is cookie/session based (no JWT bearer to forge); "
            "audience/type token hardening is not applicable to it."
        )
    if provider not in _JWT_BEARER_PROVIDERS:
        pytest.skip(
            f"JWT audience/type probe does not support stack.auth='{provider or '(empty)'}'"
        )


# ---------------------------------------------------------------------------
# Vector 1 — No Authorization header
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.parametrize("endpoint", _JWT_REQUIRED_ENDPOINTS, ids=[_endpoint_id(e) for e in _JWT_REQUIRED_ENDPOINTS])
def test_no_auth_header(endpoint, profile, evidence):
    """JWT-required endpoint must return 401 when no Authorization header is sent."""
    url = _endpoint_url(profile, endpoint)
    resp = send_request(endpoint.get("method", "POST"), url)
    if resp.status_code != 401:
        evidence.capture(resp, "no_auth_header_unexpected")
    assert resp.status_code == 401, (
        f"{endpoint['path']} returned {resp.status_code} with no auth header; expected 401"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for no-auth request"
    )


# ---------------------------------------------------------------------------
# Vector 2 — Expired JWT
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.parametrize("endpoint", _JWT_REQUIRED_ENDPOINTS, ids=[_endpoint_id(e) for e in _JWT_REQUIRED_ENDPOINTS])
def test_expired_jwt(endpoint, profile, evidence):
    """JWT-required endpoint must return 401 for a token whose exp is in the past."""
    url = _endpoint_url(profile, endpoint)
    expired_token = _make_expired_jwt()
    headers = {"Authorization": f"Bearer {expired_token}"}
    resp = send_request(endpoint.get("method", "POST"), url, headers=headers)
    if resp.status_code != 401:
        evidence.capture(resp, "expired_jwt_unexpected")
    assert resp.status_code == 401, (
        f"{endpoint['path']} returned {resp.status_code} for expired JWT; expected 401"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for expired JWT"
    )


# ---------------------------------------------------------------------------
# Vector 3 — Malformed JWT (alg: none)
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.parametrize("endpoint", _JWT_REQUIRED_ENDPOINTS, ids=[_endpoint_id(e) for e in _JWT_REQUIRED_ENDPOINTS])
def test_alg_none_jwt(endpoint, profile, evidence):
    """JWT-required endpoint must return 401 for a JWT with alg=none (unsigned)."""
    url = _endpoint_url(profile, endpoint)
    token = _make_alg_none_jwt()
    headers = {"Authorization": f"Bearer {token}"}
    resp = send_request(endpoint.get("method", "POST"), url, headers=headers)
    if resp.status_code != 401:
        evidence.capture(resp, "alg_none_jwt_unexpected")
    assert resp.status_code == 401, (
        f"{endpoint['path']} returned {resp.status_code} for alg=none JWT; expected 401"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for alg=none JWT"
    )


# ---------------------------------------------------------------------------
# Vector 4 — Malformed JWT (HS256 algorithm confusion)
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.parametrize("endpoint", _JWT_REQUIRED_ENDPOINTS, ids=[_endpoint_id(e) for e in _JWT_REQUIRED_ENDPOINTS])
def test_hs256_confusion_jwt(endpoint, profile, evidence):
    """JWT-required endpoint must return 401 for an HS256-signed token (RS256 expected)."""
    url = _endpoint_url(profile, endpoint)
    token = _make_hs256_confusion_jwt()
    headers = {"Authorization": f"Bearer {token}"}
    resp = send_request(endpoint.get("method", "POST"), url, headers=headers)
    if resp.status_code != 401:
        evidence.capture(resp, "hs256_confusion_unexpected")
    assert resp.status_code == 401, (
        f"{endpoint['path']} returned {resp.status_code} for HS256-confusion JWT; expected 401"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for HS256-confusion JWT"
    )


# ---------------------------------------------------------------------------
# Vector 5 — anon_session_id on auth-only endpoints
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.parametrize("endpoint", _JWT_REQUIRED_ENDPOINTS, ids=[_endpoint_id(e) for e in _JWT_REQUIRED_ENDPOINTS])
def test_anon_session_id_rejected_on_auth_only(endpoint, profile, evidence):
    """Auth-only endpoint must return 401 when only an anon_session_id is provided (no JWT)."""
    url = _endpoint_url(profile, endpoint)
    # No Authorization header — only body with anon_session_id.
    body = {"anon_session_id": str(uuid.uuid4())}
    resp = send_request(endpoint.get("method", "POST"), url, json_body=body)
    if resp.status_code != 401:
        evidence.capture(resp, "anon_session_id_bypass_unexpected")
    assert resp.status_code == 401, (
        f"{endpoint['path']} returned {resp.status_code} when anon_session_id "
        "was sent to an auth-only endpoint; expected 401"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for anon_session_id bypass"
    )


# ---------------------------------------------------------------------------
# Vector 6 — JWT from a different Clerk instance (wrong iss)
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.parametrize("endpoint", _JWT_REQUIRED_ENDPOINTS, ids=[_endpoint_id(e) for e in _JWT_REQUIRED_ENDPOINTS])
def test_wrong_issuer_jwt(endpoint, profile, evidence):
    """JWT-required endpoint must return 401 for a token with a foreign iss claim."""
    url = _endpoint_url(profile, endpoint)
    token = _make_wrong_issuer_jwt()
    headers = {"Authorization": f"Bearer {token}"}
    resp = send_request(endpoint.get("method", "POST"), url, headers=headers)
    if resp.status_code != 401:
        evidence.capture(resp, "wrong_issuer_jwt_unexpected")
    assert resp.status_code == 401, (
        f"{endpoint['path']} returned {resp.status_code} for wrong-issuer JWT; expected 401"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for wrong-issuer JWT"
    )


# ---------------------------------------------------------------------------
# Vector 7 — Stripped Bearer prefix
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.parametrize("endpoint", _JWT_REQUIRED_ENDPOINTS, ids=[_endpoint_id(e) for e in _JWT_REQUIRED_ENDPOINTS])
def test_stripped_bearer_prefix(endpoint, profile, evidence):
    """JWT-required endpoint must return 401 when the raw token is sent without 'Bearer '."""
    url = _endpoint_url(profile, endpoint)
    # Use a syntactically valid but fake token (expired HS256).
    raw_token = _make_expired_jwt()
    # Send token value directly in the Authorization header without the "Bearer " prefix.
    headers = {"Authorization": raw_token}
    resp = send_request(endpoint.get("method", "POST"), url, headers=headers)
    if resp.status_code != 401:
        evidence.capture(resp, "stripped_bearer_unexpected")
    assert resp.status_code == 401, (
        f"{endpoint['path']} returned {resp.status_code} for stripped-Bearer token; expected 401"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for stripped-Bearer token"
    )


# ---------------------------------------------------------------------------
# Internal endpoints — missing x-internal-secret
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("endpoint", _INTERNAL_ENDPOINTS, ids=[_endpoint_id(e) for e in _INTERNAL_ENDPOINTS])
def test_internal_endpoint_no_secret(endpoint, profile, evidence):
    """Internal endpoint must return 401 or 403 when x-internal-secret header is absent."""
    url = _endpoint_url(profile, endpoint)
    resp = send_request(endpoint.get("method", "POST"), url)
    if resp.status_code not in (401, 403):
        evidence.capture(resp, "internal_no_secret_unexpected")
    assert resp.status_code in (401, 403), (
        f"{endpoint['path']} returned {resp.status_code} with no x-internal-secret; "
        "expected 401 or 403"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for missing internal secret"
    )


@pytest.mark.parametrize(
    "endpoint,secret",
    [
        (ep, sec)
        for ep in _INTERNAL_ENDPOINTS
        for sec in _COMMON_SECRETS
    ],
    ids=[
        f"{_endpoint_id(ep)}:secret={sec}"
        for ep in _INTERNAL_ENDPOINTS
        for sec in _COMMON_SECRETS
    ],
)
def test_internal_endpoint_common_secrets(endpoint, secret, profile, evidence):
    """Internal endpoint must reject common/guessable values for x-internal-secret."""
    url = _endpoint_url(profile, endpoint)
    headers = {"x-internal-secret": secret}
    resp = send_request(endpoint.get("method", "POST"), url, headers=headers)
    if resp.status_code not in (401, 403):
        evidence.capture(resp, f"internal_common_secret_{secret}_unexpected")
    assert resp.status_code in (401, 403), (
        f"{endpoint['path']} returned {resp.status_code} for common secret '{secret}'; "
        "expected 401 or 403"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for common secret '{secret}'"
    )


# ---------------------------------------------------------------------------
# Anonymous endpoints — still require SOME auth
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("endpoint", _ANONYMOUS_ENDPOINTS, ids=[_endpoint_id(e) for e in _ANONYMOUS_ENDPOINTS])
def test_anonymous_endpoint_requires_some_auth(endpoint, profile, evidence):
    """Anonymous endpoints (verifyAuthOrAnon) must reject totally unauthenticated requests.

    A request with no Authorization header and no anon_session_id body field
    should be rejected (401), since both anonymous auth paths are absent.
    """
    if endpoint.get("fully_anonymous"):
        pytest.skip("Endpoint is fully anonymous — no auth required by design")
    url = _endpoint_url(profile, endpoint)
    # No Authorization header, no anon_session_id — completely unauthenticated.
    resp = send_request(endpoint.get("method", "POST"), url)
    if resp.status_code not in (401, 403):
        evidence.capture(resp, "anon_endpoint_no_auth_unexpected")
    assert resp.status_code in (401, 403), (
        f"{endpoint['path']} returned {resp.status_code} with no auth at all; "
        "expected 401 or 403 — endpoint must require JWT or anon_session_id"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for completely unauthenticated request"
    )


@pytest.mark.parametrize("endpoint", _ANONYMOUS_ENDPOINTS, ids=[_endpoint_id(e) for e in _ANONYMOUS_ENDPOINTS])
def test_anonymous_endpoint_rejects_expired_jwt(endpoint, profile, evidence):
    """Anonymous endpoints must not accept an expired JWT even via the JWT code path."""
    url = _endpoint_url(profile, endpoint)
    expired_token = _make_expired_jwt()
    headers = {"Authorization": f"Bearer {expired_token}"}
    resp = send_request(endpoint.get("method", "POST"), url, headers=headers)
    # An expired token is worse than no token — the endpoint should not accept it.
    # 401 is expected; 422 (malformed body) is also acceptable if auth passed
    # validation — so we explicitly flag any 2xx as a failure.
    if resp.status_code < 400:
        evidence.capture(resp, "anon_endpoint_expired_jwt_accepted")
    assert resp.status_code >= 400, (
        f"{endpoint['path']} returned {resp.status_code} (success) for expired JWT on "
        "an anonymous endpoint; expected 4xx"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for expired JWT"
    )


# ---------------------------------------------------------------------------
# §P1-E — JWT audience / token-type hardening (ASVS V9.2.2 / V9.2.3)
#
# Cross-provider by design: each probe dispatches on profile.stack.auth and
# forges a provider-shaped token, deriving the target from the FIRST
# authenticated endpoint in the profile (no hardcoded endpoint names). NextAuth
# is cookie/session based — no JWT bearer to forge — so it skips with a reason.
#
# These send a forged bearer token to an existing endpoint and expect REJECTION
# (read-only, no mutation), matching this module's JWT-probe convention — so NO
# write_probe marker. They carry asvs_extended (heavy pre-audit scope) plus the
# dual asvs()/cwe() coverage tags. Findings inherit auth_bypass / HIGH from this
# module's aggregate mapping.
# ---------------------------------------------------------------------------


@pytest.mark.asvs_extended
@pytest.mark.asvs("9.2.3")
@pytest.mark.cwe("345")
def test_wrong_audience_jwt_rejected(profile, evidence):
    """An authenticated endpoint must reject a token whose ``aud`` is wrong.

    Presents a structurally valid, provider-shaped token whose ``aud`` claim is
    an attacker-controlled value (``https://attacker.example``) the target
    should never accept. A 2xx means the app does not validate ``aud`` and would
    accept tokens minted for a different audience (ASVS V9.2.3, CWE-345).
    """
    provider = _auth_provider(profile)
    _skip_non_jwt_provider(provider)

    url, endpoint = _first_authenticated_url(profile)
    token = _make_wrong_aud_jwt(provider)
    headers = {"Authorization": f"Bearer {token}"}
    resp = send_request(endpoint.get("method", "POST"), url, headers=headers)

    if resp.status_code < 400:
        evidence.capture(resp, "wrong_aud_jwt_accepted")
    assert resp.status_code in (401, 403), (
        f"{endpoint['path']} returned {resp.status_code} for a token with "
        f"aud='{_ATTACKER_AUDIENCE}' (provider '{provider}'); expected 401/403. "
        "A 2xx means the app ignores the audience claim and would accept a token "
        "minted for a different audience (ASVS V9.2.3, CWE-345)."
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for wrong-aud JWT"
    )


@pytest.mark.asvs_extended
@pytest.mark.asvs("9.2.2")
@pytest.mark.cwe("347")
def test_id_token_rejected_where_access_token_expected(profile, evidence):
    """An access-token endpoint must reject an ID-token-shaped token.

    Presents an OIDC ``id_token``-shaped token (``typ: ID`` header, ``aud`` set
    to a client_id, identity profile claims, no scope/role) where an access
    token is expected. An ID token authenticates the user to the client; it is
    not an authorization credential for an API. Acceptance (2xx) is a token-type
    confusion finding (ASVS V9.2.2, CWE-347).
    """
    provider = _auth_provider(profile)
    _skip_non_jwt_provider(provider)

    url, endpoint = _first_authenticated_url(profile)
    token = _make_id_token_shaped_jwt(provider)
    headers = {"Authorization": f"Bearer {token}"}
    resp = send_request(endpoint.get("method", "POST"), url, headers=headers)

    if resp.status_code < 400:
        evidence.capture(resp, "id_token_accepted_as_access_token")
    assert resp.status_code in (401, 403), (
        f"{endpoint['path']} returned {resp.status_code} for an ID-token-shaped "
        f"token (typ=ID, provider '{provider}') where an access token is "
        "expected; expected 401/403. Accepting an ID token as an authorization "
        "credential is token-type confusion (ASVS V9.2.2, CWE-347)."
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for ID-token-shaped JWT"
    )
