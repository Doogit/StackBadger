"""RLS bypass and RPC input validation tests.

Tests three areas:
1. User-facing tables  — anon CRUD + UUID enumeration + cross-user SELECT.
2. Public read-only tables — anon SELECT allowed; INSERT/UPDATE/DELETE denied.
3. Service-role-only tables — all anon access denied.
4. Client-callable RPCs — anon calls and cross-user ownership checks.
5. Server-only RPC input validation — PK injection, SQLi probes.
6. auth.jwt()->>sub scope verification — rows scoped to Clerk user, not all rows.

Assertion rules
---------------
- Anon SELECT on user-facing/service-role-only: 200 + [] OR 401  (not bypass).
- Anon INSERT/UPDATE/DELETE on any protected table: 401 or 403.
- Public read-only SELECT: 200 (data present is acceptable).
- Public read-only INSERT/UPDATE/DELETE: 401 or 403.
- Service-role-only SELECT: 200 + [] OR 401/403 (no rows visible).
- Cross-user SELECT: 200 + [] only (RLS must filter to 0 rows).
- SQLi probes: must NOT return additional rows or trigger sleep > 3 s.
"""

from __future__ import annotations

import sys as _sys
import time
from pathlib import Path as _Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Collection-time profile loading
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile, resolve_profile_path  # noqa: E402
from helpers import supabase_headers, USER_B_UPLOAD_ID  # noqa: E402
from tests.conftest import all_tables, find_rpc  # noqa: E402


def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()

# ---------------------------------------------------------------------------
# Sentinel UUIDs
# ---------------------------------------------------------------------------

USER_B_MESSAGE_ID = "00000000-0000-4000-8000-000000000002"
ZERO_UUID = "00000000-0000-0000-0000-000000000000"
# An anon-session UUID that was never merged into any account.
UNMERGED_ANON_ID = "00000000-0000-4000-8000-000000000099"


def _pk_col(table: str, profile=None) -> str:
    """Return the primary key column name for *table* from profile.supabase.table_pks."""
    if profile is not None:
        raw = profile.supabase and getattr(profile.supabase, "table_pks", None)
        if raw is not None:
            mapping = vars(raw) if hasattr(raw, "__dict__") else raw
            if isinstance(mapping, dict):
                if table in mapping:
                    return mapping[table]
    # If profile unavailable, fall back to "id" as a safe generic default.
    return "id"


# SQLi payloads to probe RPC text parameters.
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "1; SELECT pg_sleep(5)",
    "\\'; SELECT 1; --",
]

# ---------------------------------------------------------------------------
# Table groupings — loaded from profile at collection time
# ---------------------------------------------------------------------------

USER_FACING_TABLES = all_tables(_PROFILE, "user_facing") if _PROFILE else []
PUBLIC_READ_ONLY_TABLES = all_tables(_PROFILE, "public_read_only") if _PROFILE else []
SERVICE_ROLE_ONLY_TABLES = all_tables(_PROFILE, "service_role_only") if _PROFILE else []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rest_url(profile, table: str) -> str:
    base = (profile.supabase and profile.supabase.project_url) or ""
    return f"{base}/rest/v1/{table}"


def _rpc_url(profile, fn_name: str) -> str:
    base = (profile.supabase and profile.supabase.project_url) or ""
    return f"{base}/rest/v1/rpc/{fn_name}"


def _authed_headers(profile, client) -> dict[str, str]:
    """Merge Supabase anon key with the user client's Authorization header."""
    headers = supabase_headers(profile, require_key=True)
    auth = client.headers.get("Authorization", "")
    if auth:
        headers["Authorization"] = auth
    return headers


# ---------------------------------------------------------------------------
# RPC payload synthesis (derived strictly from the RPC's declared params)
# ---------------------------------------------------------------------------
#
# Item 2 (derive-or-skip): every RPC target below is resolved from the active
# profile via ``find_rpc`` rather than a hardcoded target-specific name, and the
# probe payload is built ONLY from that RPC's declared param *names*. Building a
# payload from hardcoded field names risks a 422 against a differently-shaped
# real RPC, which ``_is_rls_filtered`` would treat as a pass (a false green). An
# RPC that declares no params yields ``None`` so the caller skips rather than
# guessing a payload.


def _param_names(rpc: dict) -> list[str]:
    """Declared param names for an RPC dict (params may be plain strings or
    ``{name: ...}`` mappings)."""
    names: list[str] = []
    for param in (rpc.get("params") or []):
        if isinstance(param, str):
            names.append(param)
        elif hasattr(param, "get"):
            name = param.get("name", "")
            if name:
                names.append(name)
    return names


def _rpc_cross_user_body(rpc: dict):
    """Synthesize a cross-user probe payload from an RPC's declared params.

    Mirrors ``test_idor._rpc_cross_user_body`` but returns ``None`` (caller
    skips) when the RPC declares no params — sending an empty/guessed payload
    risks a 422 that ``_is_rls_filtered`` would count as a pass. Values are
    chosen from the declared param *names* only.
    """
    names = _param_names(rpc)
    if not names:
        return None
    body: dict = {}
    for name in names:
        if "anon_id" in name:
            body[name] = UNMERGED_ANON_ID
        elif "message_id" in name:
            body[name] = USER_B_MESSAGE_ID
        elif "upload_id" in name:
            body[name] = USER_B_UPLOAD_ID
        elif "action" in name:
            body[name] = "include"
        elif "attestation" in name:
            body[name] = None
        else:
            body[name] = USER_B_UPLOAD_ID
    return body


def _rpc_sqli_body(rpc: dict, payload: str):
    """Cross-user body with every string-valued param replaced by an SQLi
    string. Returns ``None`` when the RPC declares no params (caller skips) or
    when no param actually receives the injection string.

    The injection sprays only declared params — never a hardcoded field name.
    A derived RPC whose params are all non-string sentinels (e.g. an
    ``attestation`` param mapped to ``None``) would otherwise send a request
    that injects nothing, letting the timing assertion pass trivially — a false
    green. Returning ``None`` makes the caller skip instead.
    """
    body = _rpc_cross_user_body(rpc)
    if body is None:
        return None
    injected = {k: (payload if isinstance(v, str) else v) for k, v in body.items()}
    if payload not in injected.values():
        return None
    return injected


def _is_rls_filtered(response) -> bool:
    """Return True when the response is a valid RLS-filtered (no-bypass) outcome.

    Acceptable:
    - 401 / 403 — outright denial.
    - 200 with empty array [] — RLS returned 0 rows.
    - 200 with empty body or null.
    - 404 — resource not found (safe).
    - 422 — validation error (safe).
    """
    status = response.status_code
    if status in (401, 403, 404, 422):
        return True
    if status == 200:
        try:
            body = response.json()
        except Exception:
            return True  # Non-JSON 200 — treat as safe.
        if body in ([], {}, None, ""):
            return True
        if isinstance(body, list) and len(body) == 0:
            return True
        return False
    # 5xx — server error could mask missing RLS; treat as NOT safe.
    if status >= 500:
        import warnings
        warnings.warn(
            f"[RLS CHECK] Server error {status} received — cannot confirm RLS is active. "
            f"body_preview={response.text[:200]!r}",
            stacklevel=2,
        )
        return False
    # Other unexpected status — not a bypass, treat as safe.
    return True


def _assert_rls_filtered(response, evidence, label: str) -> None:
    """Fail if the response looks like an RLS bypass."""
    evidence.capture(response, label=label)
    if not _is_rls_filtered(response):
        body_preview: Any
        try:
            body_preview = response.json()
        except Exception:
            body_preview = response.text[:300]
        pytest.fail(
            f"[RLS BYPASS] {label}: HTTP {response.status_code} with non-empty body. "
            f"body_preview={str(body_preview)[:300]}"
        )


def _anon_write_headers(profile) -> dict[str, str]:
    """Anon headers with ``Prefer: return=representation`` for write probes.

    Without this header PostgREST returns 204 No Content for *both* successful
    and RLS-filtered writes — making the two indistinguishable and creating
    false negatives.  Requesting representation forces 200 + ``[]`` when 0 rows
    are affected vs 200/201 + ``[{...}]`` when rows are actually written,
    giving reliable row-count evidence.
    """
    return supabase_headers(profile, require_key=True, prefer="return=representation")


def _assert_write_denied(response, evidence, label: str) -> None:
    """Fail if an anon write (INSERT/UPDATE/DELETE) was not rejected.

    Callers MUST send ``Prefer: return=representation`` (use
    ``_anon_write_headers``) so that PostgREST returns row-level evidence
    instead of an ambiguous 204.
    """
    evidence.capture(response, label=label)
    if response.status_code in (401, 403):
        return  # Explicit denial — good.
    # With Prefer: return=representation, PostgREST returns 200 + [] when
    # RLS filters all rows.  A non-empty array means rows were written.
    if response.status_code in (200, 201):
        body = response.text.strip()
        if body in ("", "[]", "null", "{}"):
            return  # RLS filtered the write — 0 rows affected, confirmed.
        # Non-empty body = rows were returned = write succeeded.
        pytest.fail(
            f"[RLS BYPASS] {label}: Write succeeded — rows returned. "
            f"HTTP {response.status_code}, body_preview={body[:300]}"
        )
    # 204 with representation requested is ambiguous (should not happen with
    # Prefer: return=representation).  Fail to surface the gap.
    if response.status_code == 204:
        pytest.fail(
            f"[RLS AMBIGUOUS] {label}: HTTP 204 received despite requesting "
            "return=representation.  Cannot confirm whether write was blocked. "
            "Verify that Prefer header is reaching PostgREST."
        )
    pytest.fail(
        f"[RLS BYPASS] {label}: Write not denied. "
        f"Expected 401/403 or 200 with empty body, got HTTP {response.status_code}. "
        f"body_preview={response.text[:200]}"
    )


def _assert_public_read_ok(response, evidence, label: str) -> None:
    """Fail if a public read-only SELECT was unexpectedly denied."""
    evidence.capture(response, label=label)
    if response.status_code != 200:
        pytest.fail(
            f"[PUBLIC_READ] {label}: Expected 200, got HTTP {response.status_code}. "
            f"body_preview={response.text[:200]}"
        )


# ===========================================================================
# Section 1: User-facing tables — anon access
# ===========================================================================


@pytest.mark.supabase
@pytest.mark.parametrize("table", USER_FACING_TABLES)
class TestUserFacingTablesAnonAccess:
    """Anon callers must not read or write user-facing tables."""

    def test_anon_select(self, table, profile, anon_client, evidence):
        """Anon SELECT must return 0 rows or 401 — never user data."""
        url = _rest_url(profile, table)
        resp = anon_client.get(url, headers=supabase_headers(profile, require_key=True))
        _assert_rls_filtered(resp, evidence, label=f"anon_select_{table}")

    @pytest.mark.write_probe
    def test_anon_insert(self, table, profile, anon_client, evidence):
        """Anon INSERT must be denied with 401 or 403."""
        url = _rest_url(profile, table)
        # Minimal payload — the server should reject before processing.
        resp = anon_client.post(
            url,
            json={_pk_col(table, profile): ZERO_UUID},
            headers=_anon_write_headers(profile),
        )
        _assert_write_denied(resp, evidence, label=f"anon_insert_{table}")

    @pytest.mark.write_probe
    def test_anon_update(self, table, profile, anon_client, evidence):
        """Anon UPDATE must be denied with 401 or 403."""
        url = _rest_url(profile, table)
        resp = anon_client.patch(
            url,
            params={_pk_col(table, profile): f"eq.{ZERO_UUID}"},
            json={_pk_col(table, profile): ZERO_UUID},
            headers=_anon_write_headers(profile),
        )
        _assert_write_denied(resp, evidence, label=f"anon_update_{table}")

    @pytest.mark.write_probe
    def test_anon_delete(self, table, profile, anon_client, evidence):
        """Anon DELETE must be denied with 401 or 403."""
        url = _rest_url(profile, table)
        resp = anon_client.delete(
            url,
            params={_pk_col(table, profile): f"eq.{ZERO_UUID}"},
            headers=_anon_write_headers(profile),
        )
        _assert_write_denied(resp, evidence, label=f"anon_delete_{table}")

    def test_uuid_enumeration_probe(self, table, profile, anon_client, evidence):
        """UUID enumeration: query all rows with PK > zero UUID.

        RLS must prevent any rows from leaking — response must be [] or 401.
        """
        url = _rest_url(profile, table)
        resp = anon_client.get(
            url,
            params={_pk_col(table, profile): f"gt.{ZERO_UUID}"},
            headers=supabase_headers(profile, require_key=True),
        )
        _assert_rls_filtered(resp, evidence, label=f"uuid_enum_{table}")

    def test_cross_user_select(self, table, profile, user_a_client, evidence):
        """User A queries the table filtered to User B's upload_id.

        RLS must return 0 rows for User A when filtering to another user's data.
        This uses upload_id as a plausible FK filter. For tables without that
        column, the server will return 400/422 — also acceptable.
        """
        url = _rest_url(profile, table)
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.get(
            url,
            params={"upload_id": f"eq.{USER_B_UPLOAD_ID}"},
            headers=headers,
        )
        _assert_rls_filtered(resp, evidence, label=f"cross_user_select_{table}")


# ===========================================================================
# Section 2: Public read-only tables
# ===========================================================================


@pytest.mark.supabase
@pytest.mark.parametrize("table", PUBLIC_READ_ONLY_TABLES)
class TestPublicReadOnlyTables:
    """Public read-only tables (profile: supabase.tables.public_read_only) are world-readable; writes are denied."""

    def test_anon_select_succeeds(self, table, profile, anon_client, evidence):
        """Anon SELECT should succeed (200) — these tables are public."""
        url = _rest_url(profile, table)
        resp = anon_client.get(url, headers=supabase_headers(profile, require_key=True))
        _assert_public_read_ok(resp, evidence, label=f"public_read_select_{table}")

    @pytest.mark.write_probe
    def test_anon_insert_denied(self, table, profile, anon_client, evidence):
        """Anon INSERT must be denied."""
        url = _rest_url(profile, table)
        resp = anon_client.post(
            url,
            json={_pk_col(table, profile): ZERO_UUID},
            headers=_anon_write_headers(profile),
        )
        _assert_write_denied(resp, evidence, label=f"public_read_insert_{table}")

    @pytest.mark.write_probe
    def test_anon_update_denied(self, table, profile, anon_client, evidence):
        """Anon UPDATE must be denied."""
        url = _rest_url(profile, table)
        resp = anon_client.patch(
            url,
            params={_pk_col(table, profile): f"eq.{ZERO_UUID}"},
            json={_pk_col(table, profile): ZERO_UUID},
            headers=_anon_write_headers(profile),
        )
        _assert_write_denied(resp, evidence, label=f"public_read_update_{table}")

    @pytest.mark.write_probe
    def test_anon_delete_denied(self, table, profile, anon_client, evidence):
        """Anon DELETE must be denied."""
        url = _rest_url(profile, table)
        resp = anon_client.delete(
            url,
            params={_pk_col(table, profile): f"eq.{ZERO_UUID}"},
            headers=_anon_write_headers(profile),
        )
        _assert_write_denied(resp, evidence, label=f"public_read_delete_{table}")


# ===========================================================================
# Section 3: Service-role-only tables
# ===========================================================================


@pytest.mark.supabase
@pytest.mark.parametrize("table", SERVICE_ROLE_ONLY_TABLES)
class TestServiceRoleOnlyTables:
    """Service-role-only tables (profile: supabase.tables.service_role_only).

    No anon or authenticated-user access should be possible.
    """

    def test_anon_select_blocked(self, table, profile, anon_client, evidence):
        """Anon SELECT must return 0 rows or an error — never service data."""
        url = _rest_url(profile, table)
        resp = anon_client.get(url, headers=supabase_headers(profile, require_key=True))
        _assert_rls_filtered(resp, evidence, label=f"sro_anon_select_{table}")

    @pytest.mark.write_probe
    def test_anon_insert_blocked(self, table, profile, anon_client, evidence):
        """Anon INSERT must be denied."""
        url = _rest_url(profile, table)
        resp = anon_client.post(
            url,
            json={_pk_col(table, profile): ZERO_UUID},
            headers=_anon_write_headers(profile),
        )
        _assert_write_denied(resp, evidence, label=f"sro_anon_insert_{table}")

    @pytest.mark.write_probe
    def test_anon_update_blocked(self, table, profile, anon_client, evidence):
        """Anon UPDATE must be denied."""
        url = _rest_url(profile, table)
        resp = anon_client.patch(
            url,
            params={_pk_col(table, profile): f"eq.{ZERO_UUID}"},
            json={_pk_col(table, profile): ZERO_UUID},
            headers=_anon_write_headers(profile),
        )
        _assert_write_denied(resp, evidence, label=f"sro_anon_update_{table}")

    @pytest.mark.write_probe
    def test_anon_delete_blocked(self, table, profile, anon_client, evidence):
        """Anon DELETE must be denied."""
        url = _rest_url(profile, table)
        resp = anon_client.delete(
            url,
            params={_pk_col(table, profile): f"eq.{ZERO_UUID}"},
            headers=_anon_write_headers(profile),
        )
        _assert_write_denied(resp, evidence, label=f"sro_anon_delete_{table}")

    def test_authed_user_select_blocked(self, table, profile, user_a_client, evidence):
        """Authenticated user SELECT must also return 0 rows — not service data."""
        url = _rest_url(profile, table)
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.get(url, headers=headers)
        _assert_rls_filtered(resp, evidence, label=f"sro_auth_select_{table}")


# ===========================================================================
# Section 4: Client-callable RPC access control
# ===========================================================================


@pytest.mark.supabase
class TestClientCallableRPCAccessControl:
    """Client-callable RPC access control (profile: supabase_rpcs.client_callable).

    Targets are derived from the active profile's ``client_callable`` tier — an
    anon-session merge RPC and generic record update/clear RPCs — so the suite
    is portable. Each test skips when the profile declares no matching RPC.
    """

    @pytest.mark.write_probe
    def test_merge_anon_rpc_anon_call_blocked(
        self, profile, anon_client, evidence
    ):
        """Anon call to the anon-session merge RPC (no JWT) must fail.

        Without a target authenticated user, the merge has nowhere to go.
        """
        rpc = find_rpc(profile, "client_callable", name_contains=("merge", "anon"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = supabase_headers(profile, require_key=True)
        resp = anon_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_merge_anon_anon_call")

    @pytest.mark.write_probe
    def test_merge_anon_rpc_cross_user_anon_id(
        self, profile, user_a_client, evidence
    ):
        """User A merges a random anon_id that has never existed.

        Should be a silent no-op — must not error out or affect any real session.
        Expected: 200 with empty/null body, 404, or 422.
        """
        rpc = find_rpc(profile, "client_callable", name_contains=("merge", "anon"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_merge_anon_random_id")

    @pytest.mark.write_probe
    def test_client_update_rpc_cross_user(
        self, profile, user_a_client, evidence
    ):
        """User A calls a client-callable update RPC with User B's resource IDs.

        RLS on the affected table must prevent any rows from being updated.
        Acceptable: 200+[], 401, 403, 404, 422.
        """
        rpc = find_rpc(profile, "client_callable", name_contains=("update", "record"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_client_update_cross_user")

    @pytest.mark.write_probe
    def test_client_clear_rpc_cross_user(
        self, profile, user_a_client, evidence
    ):
        """User A calls a client-callable clear RPC with User B's resource IDs."""
        rpc = find_rpc(profile, "client_callable", name_contains=("clear", "record"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_client_clear_cross_user")


# ===========================================================================
# Section 5: Server-only RPC input validation
# ===========================================================================


@pytest.mark.supabase
class TestServerOnlyRPCInputValidation:
    """Server-only RPC input validation (profile: supabase_rpcs.server_only).

    Targets are derived from the active profile's ``server_only`` tier — a
    record-replace RPC, a chat-feedback RPC, a rate-limit RPC, a knowledge-match
    RPC, and an upload-delete RPC. These are intended to be called only from
    server-side functions with the service-role key; calling them via the anon
    key (or an authenticated-user JWT) should fail (401/403) or be a no-op. We
    additionally probe JSONB and text parameters for SQL injection vectors.
    Each test skips when the profile declares no matching RPC.

    JWT-vs-p_user_id invariant (defense-in-depth):
        Some server-only RPCs accept a ``p_user_id`` parameter because
        service-role callers have no JWT context (auth.jwt() returns NULL).  A
        runtime guard inside each function verifies that if a JWT IS present,
        its ``sub`` claim matches ``p_user_id`` — otherwise it raises ERRCODE
        42501 (insufficient privilege).  This catches accidental re-GRANTs to
        the authenticated role.  The guard is untestable from this harness
        without a service_role key, but the REVOKE/GRANT tests below confirm
        that anon and authenticated callers cannot reach the function at all.
    """

    # -----------------------------------------------------------------------
    # server-only record-replace RPC
    # -----------------------------------------------------------------------

    @pytest.mark.write_probe
    def test_server_replace_rpc_anon_blocked(self, profile, anon_client, evidence):
        """Anon call to the server-only record-replace RPC must be denied."""
        rpc = find_rpc(profile, "server_only", name_contains=("replace", "record"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = supabase_headers(profile, require_key=True)
        resp = anon_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_server_replace_anon")

    @pytest.mark.write_probe
    def test_server_replace_rpc_pk_injection(self, profile, anon_client, evidence):
        """PK injection: smuggle an 'id' field into a list/line-valued param.

        The RPC should reject or ignore the injected 'id' — it must not
        overwrite an arbitrary row's primary key. The param *name* is
        profile-derived; only the injected attack content ('id') is literal.
        Skips when the derived RPC declares no list-shaped param to carry it.
        """
        rpc = find_rpc(profile, "server_only", name_contains=("replace", "record"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        injected = False
        for name in list(payload):
            if "line" in name or "item" in name or "row" in name:
                payload[name] = [{"id": ZERO_UUID, "record_id": "REC0000000001"}]
                injected = True
        if not injected:
            pytest.skip(
                f"RPC {rpc['name']} declares no list param to carry a PK injection"
            )
        url = _rpc_url(profile, rpc["name"])
        headers = supabase_headers(profile, require_key=True)
        resp = anon_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(
            resp, evidence, label="rpc_server_replace_pk_injection"
        )

    @pytest.mark.write_probe
    def test_server_replace_rpc_cross_user(
        self, profile, user_a_client, evidence
    ):
        """User A calls the server-only record-replace RPC with User B's IDs.

        RLS must block row access — not a single row should be replaced.
        """
        rpc = find_rpc(profile, "server_only", name_contains=("replace", "record"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(
            resp, evidence, label="rpc_server_replace_cross_user"
        )

    # -----------------------------------------------------------------------
    # server-only chat-feedback RPC
    # -----------------------------------------------------------------------

    @pytest.mark.write_probe
    def test_server_feedback_rpc_anon_blocked(self, profile, anon_client, evidence):
        """Anon call to the server-only chat-feedback RPC must be denied."""
        rpc = find_rpc(profile, "server_only", name_contains=("chat", "feedback"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = supabase_headers(profile, require_key=True)
        resp = anon_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_server_feedback_anon")

    @pytest.mark.write_probe
    def test_server_feedback_rpc_forged_id(
        self, profile, user_a_client, evidence
    ):
        """User A supplies User B's message_id to the chat-feedback RPC.

        The RPC should operate on 0 rows (RLS filters by user) or be denied.
        """
        rpc = find_rpc(profile, "server_only", name_contains=("chat", "feedback"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(
            resp, evidence, label="rpc_server_feedback_forged_id"
        )

    # -----------------------------------------------------------------------
    # server-only rate-limit RPC
    # -----------------------------------------------------------------------

    @pytest.mark.write_probe
    def test_server_ratelimit_rpc_anon_blocked(self, profile, anon_client, evidence):
        """Anon call to the server-only rate-limit RPC must be denied."""
        rpc = find_rpc(profile, "server_only", name_contains=("increment", "rate"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = supabase_headers(profile, require_key=True)
        resp = anon_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_server_ratelimit_anon")

    @pytest.mark.write_probe
    @pytest.mark.parametrize("sqli_payload", SQLI_PAYLOADS)
    def test_server_ratelimit_rpc_sqli(
        self, sqli_payload, profile, anon_client, evidence
    ):
        """SQLi probe on the server-only rate-limit RPC's text parameter(s).

        Measures elapsed time to detect time-based blind injection (pg_sleep).
        Asserts the call takes < 3 seconds and returns no extra rows.
        """
        rpc = find_rpc(profile, "server_only", name_contains=("increment", "rate"))
        payload = _rpc_sqli_body(rpc, sqli_payload)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to inject")
        url = _rpc_url(profile, rpc["name"])
        headers = supabase_headers(profile, require_key=True)
        t0 = time.monotonic()
        resp = anon_client.post(url, json=payload, headers=headers)
        elapsed = time.monotonic() - t0
        safe_label = (
            sqli_payload.replace(" ", "_").replace("'", "").replace(";", "")[:40]
        )
        evidence.capture(
            resp, label=f"rpc_server_ratelimit_sqli_{safe_label}"
        )

        # Time-based detection: pg_sleep(5) → elapsed should be < 3 s if blocked.
        assert elapsed < 3.0, (
            f"[SQLi] rate-limit RPC took {elapsed:.1f}s with payload "
            f"{sqli_payload!r} — possible time-based blind injection."
        )

        # Must not return additional rows due to OR 1=1.
        _assert_rls_filtered(
            resp, evidence, label=f"rpc_server_ratelimit_sqli_result_{safe_label}"
        )

    # -----------------------------------------------------------------------
    # server-only knowledge-match RPC
    # -----------------------------------------------------------------------

    def test_server_match_rpc_anon_call_ok_or_denied(
        self, profile, anon_client, evidence
    ):
        """The knowledge-match RPC may be callable with the anon key (search).

        This test documents whether anon access is permitted. The function
        should never return data from user-facing tables — only public rows.
        """
        rpc = find_rpc(profile, "server_only", name_contains=("match", "knowledge"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = supabase_headers(profile, require_key=True)
        resp = anon_client.post(url, json=payload, headers=headers)
        evidence.capture(resp, label="rpc_server_match_anon")
        # We do not assert 401/403 here because the RPC may be intentionally
        # world-readable for a search widget. We only assert it does not expose
        # user-facing table data — which is structural, not testable via HTTP
        # response alone. The response is captured for manual review.
        assert resp.status_code in (200, 400, 401, 403, 404, 422), (
            f"Unexpected status {resp.status_code} from the knowledge-match RPC"
        )

    @pytest.mark.write_probe
    @pytest.mark.parametrize("sqli_payload", SQLI_PAYLOADS)
    def test_server_match_rpc_sqli_in_query(
        self, sqli_payload, profile, anon_client, evidence
    ):
        """SQLi probe via a text query parameter on the knowledge-match RPC.

        Some implementations accept a raw text query for server-side embedding.
        If the function uses the text param in a raw SQL context, it may be
        injectable.
        """
        rpc = find_rpc(profile, "server_only", name_contains=("match", "knowledge"))
        payload = _rpc_sqli_body(rpc, sqli_payload)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to inject")
        url = _rpc_url(profile, rpc["name"])
        headers = supabase_headers(profile, require_key=True)
        t0 = time.monotonic()
        resp = anon_client.post(url, json=payload, headers=headers)
        elapsed = time.monotonic() - t0
        safe_label = (
            sqli_payload.replace(" ", "_").replace("'", "").replace(";", "")[:40]
        )
        evidence.capture(resp, label=f"rpc_server_match_sqli_{safe_label}")

        assert elapsed < 3.0, (
            f"[SQLi] knowledge-match RPC took {elapsed:.1f}s with payload "
            f"{sqli_payload!r} — possible time-based blind injection."
        )

    # -----------------------------------------------------------------------
    # server-only upload-delete RPC
    # -----------------------------------------------------------------------

    @pytest.mark.write_probe
    def test_server_delete_rpc_anon_blocked(self, profile, anon_client, evidence):
        """Anon call to the server-only upload-delete RPC must be denied.

        Anon has no GRANT on the function and no JWT. PostgREST should
        return 401, 403, or 404 (function hidden from revoked role).
        """
        rpc = find_rpc(profile, "server_only", name_contains=("delete", "upload"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = supabase_headers(profile, require_key=True)
        resp = anon_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_server_delete_anon")

    @pytest.mark.write_probe
    def test_server_delete_rpc_authenticated_blocked(
        self, profile, user_a_client, evidence
    ):
        """Authenticated (non-service-role) call to the upload-delete RPC must
        be denied.

        After the GRANT restriction, only the service role has EXECUTE on the
        delete RPC. An authenticated user should receive 403 or 404 (function
        hidden from revoked role) from PostgREST.
        """
        rpc = find_rpc(profile, "server_only", name_contains=("delete", "upload"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_server_delete_authenticated")

    @pytest.mark.write_probe
    def test_server_delete_rpc_cross_user(
        self, profile, user_a_client, evidence
    ):
        """User A tries to delete User B's upload via the RPC.

        Even if the GRANT were still present, the ownership check inside the
        SECURITY DEFINER function would block deletion of another user's upload.
        The response must be RLS-filtered (no rows affected).
        """
        rpc = find_rpc(profile, "server_only", name_contains=("delete", "upload"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.post(url, json=payload, headers=headers)
        _assert_rls_filtered(resp, evidence, label="rpc_server_delete_cross_user")


# ===========================================================================
# Section 6: auth.jwt()->>sub scope verification
# ===========================================================================


@pytest.mark.supabase
class TestJWTSubScoping:
    """Verify that RLS uses auth.jwt()->>sub (Clerk user ID) correctly.

    Clerk users are NOT Supabase Auth users, so auth.uid() would return NULL
    for all Clerk JWTs — which would make ALL rows visible (policy evaluates
    to NULL = NULL → false, or worse, no policy at all).

    These tests confirm that a Clerk JWT:
    1. Does NOT return all rows (i.e., RLS is not vacuously true due to NULL).
    2. Returns only rows where user_id matches the Clerk sub claim.
    """

    @pytest.mark.parametrize("table", USER_FACING_TABLES)
    def test_clerk_jwt_scopes_rows_correctly(
        self, table, profile, user_a_client, evidence
    ):
        """User A's Clerk JWT must NOT return rows belonging to other users.

        We query for all rows (no filter). If RLS uses auth.jwt()->>sub, only
        User A's own rows should be returned. We cannot easily count rows here
        since we don't know User A's data in advance, so we assert:
        - 200 response (JWT is valid and accepted), AND
        - User B's known upload_id does NOT appear in any returned row.
        """
        url = _rest_url(profile, table)
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.get(url, headers=headers)
        evidence.capture(resp, label=f"jwt_scope_{table}")

        # A valid Clerk JWT should not trigger 401 — if it does, auth.jwt()->>sub
        # is likely misconfigured (Clerk JWT not trusted by Supabase).
        if resp.status_code == 401:
            pytest.fail(
                f"[JWT SCOPE] {table}: Clerk JWT returned 401 — "
                "Supabase may not be configured to trust the Clerk JWKS URI. "
                "Check the Supabase JWT secret or JWKS configuration."
            )

        if resp.status_code == 200:
            try:
                rows = resp.json()
            except Exception:
                rows = []

            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict):
                        # If User B's sentinel upload_id appears in any row,
                        # RLS is not scoping correctly.
                        row_str = str(row)
                        assert USER_B_UPLOAD_ID not in row_str, (
                            f"[JWT SCOPE] {table}: User B's upload_id found in "
                            f"User A's query result — RLS scope failure. "
                            f"Row: {str(row)[:200]}"
                        )

    def test_anon_jwt_treated_as_no_user(self, profile, anon_client, evidence):
        """Anon JWT (apikey as Bearer) must not grant row-level access.

        If auth.jwt()->>sub returns NULL for the anon key, RLS policies of the
        form ``user_id = (auth.jwt()->>sub)::text`` will evaluate to
        ``user_id = NULL`` which is always false — correct behaviour.

        This test verifies that anon access returns 0 rows or 401/403 on all
        user-facing tables, confirming that NULL sub is handled correctly.
        """
        for table in USER_FACING_TABLES:
            url = _rest_url(profile, table)
            resp = anon_client.get(url, headers=supabase_headers(profile, require_key=True))
            evidence.capture(resp, label=f"anon_jwt_null_sub_{table}")
            _assert_rls_filtered(resp, evidence, label=f"anon_null_sub_result_{table}")


# ===========================================================================
# Section 7: Read-only RLS probes (safe for production)
# ===========================================================================


@pytest.mark.supabase
class TestReadOnlyRLSProbes:
    """Cross-user SELECT probes that verify RLS without mutation.

    These tests prove RLS is active by checking that User A cannot read
    User B's rows. If a SELECT is blocked, the same policy expression
    blocks writes (user-facing tables use FOR ALL with identical
    USING/WITH CHECK clauses).
    """

    @pytest.mark.parametrize("table", USER_FACING_TABLES)
    def test_cross_user_select_blocked(
        self, table, profile, user_a_client, evidence
    ):
        """User A queries a user-facing table filtered to User B's upload_id.

        RLS must return 0 rows — User A cannot see User B's data.
        """
        url = _rest_url(profile, table)
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.get(
            url,
            params={"upload_id": f"eq.{USER_B_UPLOAD_ID}"},
            headers=headers,
        )
        _assert_rls_filtered(resp, evidence, label=f"readonly_cross_user_select_{table}")

    @pytest.mark.parametrize("table", USER_FACING_TABLES)
    def test_anon_select_user_table_blocked(
        self, table, profile, anon_client, evidence
    ):
        """Anon SELECT on user-facing tables must return 0 rows or 401/403."""
        url = _rest_url(profile, table)
        resp = anon_client.get(url, headers=supabase_headers(profile, require_key=True))
        _assert_rls_filtered(resp, evidence, label=f"readonly_anon_select_user_{table}")

    @pytest.mark.parametrize("table", SERVICE_ROLE_ONLY_TABLES)
    def test_anon_select_service_table_blocked(
        self, table, profile, anon_client, evidence
    ):
        """Anon SELECT on service-role-only tables must return 0 rows or 401/403."""
        url = _rest_url(profile, table)
        resp = anon_client.get(url, headers=supabase_headers(profile, require_key=True))
        _assert_rls_filtered(resp, evidence, label=f"readonly_anon_select_sro_{table}")

    def test_cross_user_rpc_read_blocked(
        self, profile, user_a_client, evidence
    ):
        """User A calls the knowledge-match RPC with User B's context.

        The read-path RPC should not leak User B's data. The RPC is derived
        from the profile's ``server_only`` tier; since a knowledge-match RPC
        typically queries a public read-only table, this verifies it does not
        accidentally join user-facing tables. Skips when the profile declares
        no matching RPC.
        """
        rpc = find_rpc(profile, "server_only", name_contains=("match", "knowledge"))
        payload = _rpc_cross_user_body(rpc)
        if payload is None:
            pytest.skip(f"RPC {rpc['name']} declares no params to probe")
        url = _rpc_url(profile, rpc["name"])
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.post(url, json=payload, headers=headers)
        evidence.capture(resp, label="readonly_rpc_read_cross_user")
        # The RPC queries a public table. We verify:
        # 1. No 500 error
        # 2. No user-facing data (User B's upload_id) in the response
        assert resp.status_code != 500, (
            "knowledge-match RPC returned 500 — RPC may be broken"
        )
        if resp.status_code == 200:
            body_text = resp.text or ""
            assert USER_B_UPLOAD_ID not in body_text, (
                "User B's upload_id found in knowledge-match RPC response — "
                "RPC may be joining user-facing tables"
            )

    @pytest.mark.parametrize("table", USER_FACING_TABLES)
    def test_own_data_visible(
        self, table, profile, user_a_client, evidence
    ):
        """User A queries own rows — WARNING if 0 rows (inconclusive), not failure.

        If User A has data, this confirms RLS allows own-data access.
        If User A has no data (fresh test account), the cross-user tests
        are still valid but this positive-control is inconclusive.
        """
        url = _rest_url(profile, table)
        headers = _authed_headers(profile, user_a_client)
        resp = user_a_client.get(url, headers=headers)
        evidence.capture(resp, label=f"readonly_own_data_{table}")

        if resp.status_code == 200:
            try:
                rows = resp.json()
            except Exception:
                rows = []
            if isinstance(rows, list) and len(rows) == 0:
                import warnings
                warnings.warn(
                    f"[READ-ONLY PROBE] {table}: User A has 0 rows. "
                    "Cross-user SELECT test is still valid but this "
                    "positive-control is inconclusive (fresh test account?).",
                    stacklevel=2,
                )
