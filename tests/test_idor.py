"""IDOR (Insecure Direct Object Reference) tests.

Tests horizontal privilege escalation across Netlify Function endpoints and
PostgREST RPC functions. User A attempts to access or mutate resources that
belong to User B using UUID placeholders.

Assertion rule
--------------
A test PASSES (no vulnerability) when the response is:
  - HTTP 401/403 — denied outright, or
  - HTTP 200 with an empty array/null body — RLS filtered the result.

A test FAILS (potential vulnerability) when the response is:
  - HTTP 200 with non-empty data belonging to another user.

Evidence is captured for all responses so failures can be triaged.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

import pytest

# ---------------------------------------------------------------------------
# Ensure the StackBadger package root is importable at collection time.
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from helpers import netlify_url, supabase_headers, USER_B_UPLOAD_ID  # noqa: E402


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


def _collection_tables(tier: str) -> list[str]:
    """Get tables for parametrize — returns empty list if profile unavailable."""
    if _PROFILE is None:
        return []
    from conftest import all_tables
    return all_tables(_PROFILE, tier)


_AUTHENTICATED_ENDPOINTS = _collection_endpoints("authenticated")
_CLIENT_CALLABLE_RPCS = _collection_rpcs("client_callable")
_USER_FACING_TABLES = _collection_tables("user_facing")


# ---------------------------------------------------------------------------
# Sentinel UUIDs — stable placeholders for "User B's resource IDs".
# These must not exist in User A's data; if they do, a test misconfiguration
# warning is issued but the test is not skipped (the server should still
# block access at the RLS layer).
# ---------------------------------------------------------------------------

# Represents a chat message owned by User B.
USER_B_MESSAGE_ID = "00000000-0000-4000-8000-000000000002"

# Represents a conversation owned by User B.
USER_B_CONVERSATION_ID = "00000000-0000-4000-8000-000000000003"

# An anon session UUID that was never merged into User A's account.
UNMERGED_ANON_ID = "00000000-0000-4000-8000-000000000099"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _supabase_rest_url(profile, table: str) -> str:
    """Return the PostgREST URL for *table*."""
    base = (profile.supabase and profile.supabase.project_url) or ""
    return f"{base}/rest/v1/{table}"


def _supabase_rpc_url(profile, fn_name: str) -> str:
    """Return the PostgREST RPC URL for *fn_name*."""
    base = (profile.supabase and profile.supabase.project_url) or ""
    return f"{base}/rest/v1/rpc/{fn_name}"


def _assert_no_data_leak(response, evidence, label: str) -> None:
    """Assert response does not contain another user's data.

    Acceptable outcomes:
    - 401 / 403 — outright denial
    - 200 with empty body ([], {}, null, "")
    """
    evidence.capture(response, label=label)
    status = response.status_code

    if status in (401, 403):
        # Denied — not a bypass.
        return

    if status == 200:
        try:
            body = response.json()
        except Exception:
            body = response.text

        # Empty array, empty dict, null, or empty string are all acceptable.
        if body in ([], {}, None, ""):
            return
        if isinstance(body, list) and len(body) == 0:
            return

        # Non-empty 200 response — potential IDOR bypass.
        pytest.fail(
            f"[IDOR] {label}: HTTP 200 with non-empty body — possible data leak. "
            f"Status={status}, body_preview={str(body)[:300]}"
        )
    elif 500 <= status < 600:
        # Server errors may mask authorization bugs — surface them.
        pytest.fail(
            f"[IDOR] {label}: HTTP {status} (server error) — endpoint may be crashing. "
            f"Investigate before assuming IDOR is absent. body_preview={response.text[:300]}"
        )
    else:
        # 404, 422, etc. — server rejected the request without returning
        # another user's data.
        return


# ===========================================================================
# Section 1: Netlify Function IDOR tests
# ===========================================================================


def _endpoint_id(ep: dict) -> str:
    """Human-readable pytest ID for a parametrized endpoint."""
    method = ep.get("method", "POST")
    path = ep.get("path", "unknown")
    return f"{method}:{path}"


def _cross_user_body(ep: dict) -> dict:
    """Build a cross-user probe body by substituting User B's sentinel IDs.

    Replaces any UUID placeholder field with USER_B_UPLOAD_ID or the
    appropriate User B sentinel, so the request exercises ownership checks
    rather than format validation.
    """
    from conftest import probe_body_for
    base = probe_body_for(ep)
    body: dict = {}
    for key, val in base.items():
        if key in ("upload_id",):
            body[key] = USER_B_UPLOAD_ID
        elif key in ("message_id",):
            body[key] = USER_B_MESSAGE_ID
        elif key in ("conversation_id",):
            body[key] = USER_B_CONVERSATION_ID
        elif isinstance(val, str) and "uuid" in val.lower():
            body[key] = USER_B_UPLOAD_ID
        else:
            body[key] = val
    # Always include at least one sentinel UUID so the ownership check fires.
    if not body:
        body = {"upload_id": USER_B_UPLOAD_ID}
    return body


@pytest.mark.write_probe
@pytest.mark.supabase
@pytest.mark.parametrize(
    "endpoint",
    _AUTHENTICATED_ENDPOINTS,
    ids=[_endpoint_id(e) for e in _AUTHENTICATED_ENDPOINTS],
)
def test_netlify_function_cross_user_idor(endpoint, profile, user_a_client, evidence):
    """User A calls a Netlify Function with User B's resource IDs.

    The function should reject or return empty — never User B's data.
    """
    path = endpoint.get("path", "")
    method = endpoint.get("method", "POST").lower()
    url = netlify_url(profile, path)
    body = _cross_user_body(endpoint)

    fn = getattr(user_a_client, method)
    resp = fn(url, json=body)
    _assert_no_data_leak(resp, evidence, label=f"netlify_idor_{path.lstrip('/')}")


# ===========================================================================
# Section 2: PostgREST RPC IDOR tests
# ===========================================================================


def _rpc_id(rpc: dict) -> str:
    return rpc.get("name", "unknown")


def _rpc_cross_user_body(rpc: dict) -> dict:
    """Build a cross-user payload for an RPC based on its declared params."""
    params = rpc.get("params") or []
    body: dict = {}
    for param in params:
        if isinstance(param, str):
            param_name = param
        else:
            param_name = param.get("name", "") if hasattr(param, "get") else str(param)

        if "upload_id" in param_name:
            body[param_name] = USER_B_UPLOAD_ID
        elif "anon_id" in param_name:
            body[param_name] = UNMERGED_ANON_ID
        elif "action" in param_name:
            body[param_name] = "include"
        elif "attestation" in param_name:
            body[param_name] = None
        else:
            body[param_name] = USER_B_UPLOAD_ID
    if not body:
        body = {"anon_id": UNMERGED_ANON_ID}
    return body


@pytest.mark.supabase
class TestRPCIDOR:
    """User A calls PostgREST RPC functions with User B's resource IDs."""

    def _rpc_headers(self, profile, user_a_client) -> dict[str, str]:
        """Merge Supabase anon key with User A's Authorization header."""
        headers = dict(supabase_headers(profile, include_auth=False))
        # Extract Authorization from User A's client (set by _AuthedClient).
        auth = user_a_client.headers.get("Authorization", "")
        if auth:
            headers["Authorization"] = auth
        return headers

    @pytest.mark.write_probe
    @pytest.mark.parametrize(
        "rpc",
        _CLIENT_CALLABLE_RPCS,
        ids=[_rpc_id(r) for r in _CLIENT_CALLABLE_RPCS],
    )
    def test_rpc_cross_user_idor(self, rpc, profile, user_a_client, evidence):
        """User A calls a client-callable RPC with User B's resource IDs.

        RLS on affected tables should filter the operation to 0 rows for User A.
        """
        rpc_name = rpc.get("name", "")
        url = _supabase_rpc_url(profile, rpc_name)
        headers = self._rpc_headers(profile, user_a_client)
        payload = _rpc_cross_user_body(rpc)
        resp = user_a_client.post(url, json=payload, headers=headers)
        _assert_no_data_leak(resp, evidence, label=f"rpc_idor_{rpc_name}")


# ===========================================================================
# Section 3: Anon-to-auth IDOR — unauthenticated user passing auth-owned IDs
# ===========================================================================


@pytest.mark.supabase
class TestAnonToAuthIDOR:
    """Unauthenticated requests that embed auth-user resource IDs.

    Verifies that anonymous callers cannot piggyback on authenticated users'
    data by guessing or knowing a UUID.
    """

    def test_anon_request_with_auth_resource_id(
        self, profile, anon_client, evidence
    ):
        """Anon caller sends an auth-owned resource id to a protected endpoint.

        Uses the first authenticated endpoint declared by the profile. Should
        receive 401/403 or an empty response.
        """
        from conftest import first_endpoint

        endpoint = first_endpoint(profile, "authenticated")
        resp = anon_client.post(
            netlify_url(profile, endpoint["path"]),
            json={"id": USER_B_UPLOAD_ID},
        )
        _assert_no_data_leak(resp, evidence, label="anon_auth_resource_id")

    @pytest.mark.parametrize(
        "table",
        _USER_FACING_TABLES,
        ids=_USER_FACING_TABLES,
    )
    def test_anon_postgrest_table_lookup(self, table, profile, anon_client, evidence):
        """Anon caller queries a user-facing table for a known UUID.

        PostgREST should return 0 rows (RLS filtered), not the record.
        """
        base = (profile.supabase and profile.supabase.project_url) or ""
        url = f"{base}/rest/v1/{table}"
        headers = supabase_headers(profile, include_auth=False)
        # Use a generic UUID filter that exercises RLS on whichever pk the table has.
        resp = anon_client.get(
            url,
            params={"id": f"eq.{USER_B_UPLOAD_ID}"},
            headers=headers,
        )
        _assert_no_data_leak(resp, evidence, label=f"anon_postgrest_{table}_lookup")

    def test_anon_merge_session_rpc(self, profile, anon_client, evidence):
        """Anon caller invokes the anon-session merge RPC without a user JWT.

        The RPC name is derived from the profile's client_callable RPCs (the
        single source of truth); skip when the profile declares none. Without a
        valid user JWT there is no target user to merge into — the RPC should
        return an error or empty result.
        """
        from conftest import all_rpcs

        merge_rpc = next(
            (
                r["name"]
                for r in all_rpcs(profile, "client_callable")
                if r.get("name") and "merge" in r["name"] and "anon" in r["name"]
            ),
            None,
        )
        if merge_rpc is None:
            pytest.skip("No anon-session merge RPC declared in profile")
        base = (profile.supabase and profile.supabase.project_url) or ""
        url = f"{base}/rest/v1/rpc/{merge_rpc}"
        headers = supabase_headers(profile, include_auth=False)
        payload = {"anon_id": UNMERGED_ANON_ID}
        resp = anon_client.post(url, json=payload, headers=headers)
        _assert_no_data_leak(resp, evidence, label="anon_rpc_merge_session")
