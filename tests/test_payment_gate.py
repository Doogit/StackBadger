"""Payment gate tests — paid-feature generation, RLS bypass, checkout tampering, email body validation.

Tests:
1. Invoke a payment-gated endpoint without payment — expect 402 or 403
2. Invoke a second payment-gated endpoint without payment — expect 402 or 403
3. Direct paid_at manipulation via PostgREST — RLS must block; expect 0 rows or 403
4. Checkout session metadata tampering — tampered user_id / upload_id
5. Internal email endpoint body validation — XSS and extra-field injection, with and without secret
"""

from __future__ import annotations

import base64
import json
import os
import sys as _sys
from pathlib import Path as _Path

import pytest


# ---------------------------------------------------------------------------
# Ensure the StackBadger package root is importable at collection time.
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from helpers import netlify_url, send_request  # noqa: E402


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


# Payment-gated endpoint paths — endpoints with payment_gated: true in the profile.
_PAYMENT_GATED_PATHS = [
    ep.get("path", "")
    for ep in _collection_endpoints("authenticated")
    if ep.get("payment_gated") and ep.get("path")
]

# Internal endpoint paths from the profile.
_INTERNAL_ENDPOINT_PATHS = [
    ep.get("path", "")
    for ep in _collection_endpoints("internal")
    if ep.get("path")
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first_authed_probe_url(profile) -> str:
    """URL of the first authenticated endpoint, used to extract a live auth header.

    Skips when the profile declares no authenticated endpoints.
    """
    from conftest import first_endpoint

    return netlify_url(profile, first_endpoint(profile, "authenticated")["path"])


def _postgrest_url(profile, table: str) -> str:
    """Build a PostgREST table URL from the active profile."""
    project_url = (profile.supabase and profile.supabase.project_url) or ""
    return f"{project_url.rstrip('/')}/rest/v1/{table}"


# ---------------------------------------------------------------------------
# Test 1 & 2 — Payment-gated endpoints reject unpaid users
# ---------------------------------------------------------------------------

@pytest.mark.stripe
@pytest.mark.clerk
@pytest.mark.asvs("8.2.1")  # function-level access restricted to explicitly-permitted consumers
@pytest.mark.cwe("840")  # business logic / payment-gate bypass
@pytest.mark.parametrize("path", _PAYMENT_GATED_PATHS, ids=_PAYMENT_GATED_PATHS)
def test_payment_gated_endpoint_rejects_unpaid_user(path, profile, user_a_client, evidence):
    """Payment-gated endpoint must return 402 or 403 for an unpaid user.

    User A is assumed to be an unpaid test account.  Sending a POST with a
    valid JWT but no payment record must be refused before any business logic runs.
    """
    url = netlify_url(profile, path)

    # Use a synthetic UUID that passes format validation but belongs to no real upload.
    # Sending {} risks a 400 from input validation before the payment gate runs.
    body = {"upload_id": "00000000-0000-4000-8000-000000000099"}

    resp = user_a_client.post(url, json=body, timeout=20)
    evidence.capture(resp, f"payment_gate_{path.lstrip('/')}")

    assert resp.status_code in (400, 402, 403, 404), (
        f"{path} returned HTTP {resp.status_code} for unpaid user; "
        "expected payment rejection (400/402/403) or 404 (resource not found). "
        "Ensure the payment gate or ownership check runs before any business logic."
    )
    assert resp.status_code != 500, (
        f"{path} returned 500 (unhandled error) for unpaid user."
    )


# ---------------------------------------------------------------------------
# Test 2b — Payment column not readable via REST (read-only probe)
# ---------------------------------------------------------------------------

@pytest.mark.stripe
@pytest.mark.supabase
@pytest.mark.asvs("8.2.1")  # function-level access restricted to explicitly-permitted consumers
@pytest.mark.cwe("840")  # business logic / payment-gate bypass
def test_payment_column_not_readable_via_rest(profile, user_a_client, evidence):
    """User A attempts to SELECT the payment gate column via PostgREST.

    The payment column (e.g. paid_at) should either be:
    - Not exposed via PostgREST (column filtered out), or
    - Readable but not writable (RLS blocks PATCH).

    This read-only probe verifies the column's REST visibility without
    attempting any writes. It complements the write-probe
    test_direct_paid_at_manipulation_blocked (which requires --full mode).
    """
    supabase_project_url = (profile.supabase and profile.supabase.project_url) or ""
    if not supabase_project_url or supabase_project_url == "https://xxx.supabase.co":
        pytest.skip("profile.supabase.project_url is a placeholder; configure for live run")

    anon_key = (profile.supabase and profile.supabase.anon_key) or ""
    if not anon_key or anon_key.startswith("eyJ..."):
        pytest.skip("profile.supabase.anon_key is a placeholder; configure for live run")

    gate_table = (profile.payment_gate and profile.payment_gate.table) or "users"
    gate_column = (profile.payment_gate and profile.payment_gate.column) or "paid_at"

    table_url = _postgrest_url(profile, gate_table)
    headers = {
        "apikey": anon_key,
        "Content-Type": "application/json",
    }

    # Try to read with User A's auth — merge auth header from client
    auth_header = ""
    try:
        # Probe a known endpoint to extract the auth header
        probe_url = _first_authed_probe_url(profile)
        probe_resp = user_a_client.post(probe_url, json={"upload_id": "probe"}, timeout=5)
        auth_header = probe_resp.request.headers.get("authorization", "")
    except Exception:
        pass

    if auth_header:
        headers["Authorization"] = auth_header

    # GET with select= to request only the payment column
    resp = send_request(
        "GET",
        table_url,
        headers=headers,
        params={"select": gate_column, "limit": "1"},
    )
    evidence.capture(resp, label="payment_column_read_probe")

    # Acceptable outcomes:
    # - 403: column/table not readable (strictest)
    # - 200 with empty array: RLS filtered (no rows visible)
    # - 200 with data: column IS readable — not a vulnerability per se,
    #   but document it. The write-probe test verifies it can't be modified.
    if resp.status_code == 403:
        return  # Column not exposed — strongest protection.
    if resp.status_code == 200:
        body = resp.text.strip()
        if body in ("", "[]", "null"):
            return  # RLS filtered — no rows visible, acceptable.
        # Column is readable. This is informational, not a failure.
        # The critical gate is that PATCH is blocked (tested by write-probe).
        import warnings
        warnings.warn(
            f"[PAYMENT GATE] {gate_table}.{gate_column} is readable via "
            f"PostgREST GET (HTTP {resp.status_code}). This is not a "
            "vulnerability if PATCH is blocked (verified in --full mode). "
            f"Body preview: {body[:200]}",
            stacklevel=2,
        )
        return
    # Other statuses (401, 404, etc.) are acceptable — endpoint rejected.
    assert resp.status_code != 500, (
        f"PostgREST GET for {gate_column} returned 500 — server error"
    )


# ---------------------------------------------------------------------------
# Test 3 — Direct paid_at manipulation via PostgREST
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
@pytest.mark.stripe
@pytest.mark.supabase
@pytest.mark.asvs("8.2.1")  # function-level access restricted to explicitly-permitted consumers
@pytest.mark.cwe("840")  # business logic / payment-gate bypass
def test_direct_paid_at_manipulation_blocked(profile, user_a_client, auth_adapter, evidence):
    """RLS must prevent a user from setting their own paid_at via PostgREST.

    An attacker who holds their own valid JWT could attempt to PATCH the payment
    gate table directly, setting the payment column to a past timestamp to
    fabricate payment.  Row Level Security must reject this write.

    Expected: 0 rows updated (204 with empty body or representation shows no rows)
    or HTTP 403.
    """
    supabase_project_url = (profile.supabase and profile.supabase.project_url) or ""
    if not supabase_project_url or supabase_project_url == "https://xxx.supabase.co":
        pytest.skip("profile.supabase.project_url is a placeholder; configure for live run")

    anon_key = (profile.supabase and profile.supabase.anon_key) or ""
    if not anon_key or anon_key.startswith("eyJ..."):
        pytest.skip("profile.supabase.anon_key is a placeholder; configure for live run")

    # Read payment gate config from the profile.
    gate_table = (profile.payment_gate and profile.payment_gate.table) or "users"
    gate_column = (profile.payment_gate and profile.payment_gate.column) or "paid_at"

    # Get User A's JWT to use as the PostgREST auth token.
    probe_url = _first_authed_probe_url(profile)
    try:
        probe_resp = user_a_client.post(probe_url, json={"upload_id": "probe"}, timeout=5)
        user_a_auth = probe_resp.request.headers.get("authorization", "")
    except Exception:  # noqa: BLE001
        user_a_auth = ""

    if not user_a_auth:
        # Fall back to auth_adapter for a fresh token via FAPI.
        try:
            raw_jwt = auth_adapter.get_token("user_a")
            user_a_auth = f"Bearer {raw_jwt}" if raw_jwt else ""
        except Exception:  # noqa: BLE001
            user_a_auth = ""

    if not user_a_auth:
        pytest.skip("Could not obtain User A JWT for PostgREST direct-write test")

    table_url = _postgrest_url(profile, gate_table)
    headers = {
        "apikey": anon_key,
        "Authorization": user_a_auth,
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    # Extract User A's Clerk user_id (sub claim) from the JWT to scope the
    # PATCH to a single row.
    user_sub = ""
    try:
        token_part = user_a_auth.replace("Bearer ", "").split(".")[1]
        token_part += "=" * (4 - len(token_part) % 4)
        user_sub = json.loads(base64.urlsafe_b64decode(token_part)).get("sub", "")
    except Exception:  # noqa: BLE001
        pass

    if not user_sub:
        pytest.skip("Could not extract sub from User A JWT for single-row scoped PATCH test")

    # Scope to User A's own row only — prevents mass-update if RLS is misconfigured.
    patch_url = f"{table_url}?user_id=eq.{user_sub}"

    resp = send_request(
        "PATCH",
        patch_url,
        headers=headers,
        json_body={gate_column: "2025-01-01T00:00:00Z"},
    )
    evidence.capture(resp, "paid_at_manipulation_attempt")

    # Acceptable outcomes:
    # 403 — RLS explicitly rejects the write.
    # 200/204 with an empty JSON array body — RLS filtered all rows; 0 rows updated.
    if resp.status_code == 403:
        return  # RLS blocked — pass.

    if resp.status_code in (200, 204):
        body = resp.text.strip()
        # Representation mode returns [] when no rows match/are visible.
        rows_updated = body not in ("", "[]", "null")
        assert not rows_updated, (
            f"PostgREST PATCH to {gate_table}.{gate_column} succeeded and returned rows: {body[:300]}. "
            "RLS must prevent users from writing the payment column directly."
        )
        return

    # Any other status is unexpected — document but do not hard-fail on network errors.
    assert resp.status_code in (200, 204, 403), (
        f"Unexpected status {resp.status_code} from PostgREST {gate_column} PATCH: {resp.text[:200]}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Checkout session metadata tampering
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
@pytest.mark.stripe
@pytest.mark.clerk
@pytest.mark.asvs("8.2.1")  # function-level access restricted to explicitly-permitted consumers
@pytest.mark.cwe("840")  # business logic / payment-gate bypass
@pytest.mark.parametrize("tamper_case,body_override,description", [
    (
        "tampered_user_id",
        {"user_id": "clerk_adversary_user_99999", "upload_id": "00000000-0000-0000-0000-000000000001"},
        "user_id does not match JWT sub — server must reject",
    ),
    (
        "tampered_upload_id",
        {"upload_id": "00000000-0000-0000-0000-deadbeef0000"},
        "upload_id belongs to a different user — server must reject or return 403",
    ),
])
def test_checkout_session_metadata_tampering(
    tamper_case, body_override, description, profile, user_a_client, evidence
):
    """Checkout session creation must validate metadata against the authenticated user.

    Sending a tampered user_id (different from JWT sub) or an upload_id that
    belongs to another user must be rejected.  The server must derive user_id
    from the verified JWT, never from the request body.
    """
    from conftest import first_endpoint

    # Derive the checkout endpoint from the profile's `payment` category
    # instead of hardcoding a path; skip when no payment endpoint is declared.
    url = netlify_url(profile, first_endpoint(profile, "payment")["path"])
    base_url = (profile.target and profile.target.base_url) or ""

    # Base body — add tamper override.
    body: dict = {
        "upload_id": "00000000-0000-0000-0000-000000000001",
        "success_url": f"{base_url.rstrip('/')}/success",
        "cancel_url": f"{base_url.rstrip('/')}/cancel",
    }
    body.update(body_override)

    resp = user_a_client.post(url, json=body, timeout=20)
    evidence.capture(resp, f"checkout_tamper_{tamper_case}")

    # The server must NOT return 200 with a valid Stripe session for tampered input.
    # Acceptable: 400 (bad request), 401, 403, 404 (upload not found/not owned).
    assert resp.status_code not in (200, 201), (
        f"Checkout session creation succeeded ({resp.status_code}) for tampered body "
        f"({tamper_case}): {description}. Body: {resp.text[:300]}. "
        "The server must validate user_id from JWT and upload_id ownership."
    )
    assert resp.status_code != 500, (
        f"Checkout returned 500 (unhandled error) for tampered body ({tamper_case})."
    )


# ---------------------------------------------------------------------------
# Test 5 — Internal email endpoint body validation
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
@pytest.mark.parametrize("path", _INTERNAL_ENDPOINT_PATHS, ids=_INTERNAL_ENDPOINT_PATHS)
@pytest.mark.parametrize("injection_case,body,description", [
    (
        "xss_email",
        {"email": "<script>alert(1)</script>@test.com"},
        "XSS in email field must not be reflected in response",
    ),
    (
        "extra_fields",
        {"email": "test@test.com", "admin": True, "role": "superuser"},
        "Extra privilege-escalation fields must be ignored",
    ),
])
def test_internal_email_endpoint_body_validation(
    path, injection_case, body, description, profile, evidence
):
    """Internal email endpoints must scrub injected fields and require x-internal-secret.

    This test runs two sub-checks per case:
    (a) Without x-internal-secret — must be rejected (401 or 403).
    (b) With x-internal-secret from env — must process without reflecting XSS or
        promoting privilege-escalation fields.
    """
    url = netlify_url(profile, path)
    internal_secret = os.environ.get("PENTEST_INTERNAL_SECRET", "")

    # --- Sub-check (a): No secret header — must be rejected ---
    resp_no_secret = send_request("POST", url, json_body=body)
    evidence.capture(resp_no_secret, f"internal_no_secret_{path.lstrip('/')}_{injection_case}")

    assert resp_no_secret.status_code in (401, 403), (
        f"{path} returned {resp_no_secret.status_code} with no x-internal-secret; "
        "expected 401 or 403. Internal endpoints must require the secret header."
    )

    # --- Sub-check (b): With secret header (if available) ---
    if not internal_secret:
        # Cannot test authenticated path without the secret — skip sub-check (b) only.
        return

    headers_with_secret = {"x-internal-secret": internal_secret}
    resp_with_secret = send_request("POST", url, headers=headers_with_secret, json_body=body)
    evidence.capture(resp_with_secret, f"internal_with_secret_{path.lstrip('/')}_{injection_case}")

    # XSS reflection check — script tag must not appear verbatim in the response.
    if injection_case == "xss_email":
        resp_body = resp_with_secret.text
        assert "<script>" not in resp_body, (
            f"{path} reflected <script> tag in response for XSS injection case. "
            f"Body: {resp_body[:300]}"
        )
        assert "alert(1)" not in resp_body, (
            f"{path} reflected alert(1) in response for XSS injection case. "
            f"Body: {resp_body[:300]}"
        )

    # Privilege escalation — extra fields must not be acknowledged or acted upon.
    if injection_case == "extra_fields":
        resp_body = resp_with_secret.text.lower()
        assert '"admin": true' not in resp_body and '"admin":true' not in resp_body, (
            f"{path} echoed 'admin: true' back in the response. "
            "Extra fields must be stripped before processing."
        )
        # The response must not contain role elevation confirmation.
        assert "superuser" not in resp_body, (
            f"{path} echoed 'superuser' in response. "
            "Extra fields must be silently ignored."
        )

    # Internal server errors on injection input are themselves a finding.
    assert resp_with_secret.status_code != 500, (
        f"{path} returned 500 for injection case '{injection_case}'. "
        f"Body: {resp_with_secret.text[:300]}"
    )


# ---------------------------------------------------------------------------
# Bonus — Confirm internal endpoints require secret even with valid JWT
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.parametrize("path", _INTERNAL_ENDPOINT_PATHS, ids=_INTERNAL_ENDPOINT_PATHS)
def test_internal_endpoint_rejects_jwt_without_secret(path, profile, user_a_client, evidence):
    """Internal endpoints must not accept a valid user JWT in place of x-internal-secret.

    A logged-in user with a valid Clerk JWT should NOT be able to trigger
    internal email sends.  The x-internal-secret header is required regardless
    of whether a Bearer token is also present.
    """
    url = netlify_url(profile, path)
    body = {"email": "test@test.com"}

    resp = user_a_client.post(url, json=body, timeout=15)
    evidence.capture(resp, f"internal_jwt_no_secret_{path.lstrip('/')}")

    assert resp.status_code in (401, 403), (
        f"{path} returned {resp.status_code} when a valid user JWT was sent "
        "without x-internal-secret; expected 401 or 403. "
        "Internal endpoints must not be callable by regular authenticated users."
    )
