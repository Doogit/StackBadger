"""Mass-assignment / BOPLA probes: privileged-field injection with read-back.

ASVS 5.0:
  - V8.2.3 (L2): the application protects against mass assignment / Broken Object
    Property Level Authorization. A client must not be able to set object
    properties it is not authorized to modify (role, admin flags, ownership,
    balances) by including them in a write payload.
  - V15.3.3 (L2): the application does not bind client-supplied data to internal
    object properties without an explicit allow-list of writable fields.

CWE-915 (improperly controlled modification of dynamically-determined object
attributes; mass assignment).

What "mass assignment" means here
---------------------------------
The classic attack: an update/insert handler binds the whole request body onto a
record, so an attacker adds a privileged field the UI never exposes
(``"is_admin": true``, ``"role": "admin"``, ``"balance": 1000000``) and the
server persists it. The control is proven only by READ-BACK: send the field, read
the record back, and confirm the injected value did NOT stick. A 200 on the write
alone is not proof, because the field may have been silently ignored (good) or
silently persisted (the finding). Both probe families below confirm via an
independent read-back, never the write status code.

Provider variants (selected by ``stack.database``)
--------------------------------------------------
- **PostgREST** (``stack.database == supabase``): for each user-facing table, GET
  the signed-in user's own row (RLS-scoped), detect which privileged columns
  actually exist on it, PATCH those columns with foreign sentinels one field at a
  time, then GET the row again and confirm no sentinel persisted. Probing only
  columns that already exist on the row avoids 400 "column does not exist" noise.
- **Firestore** (``stack.database == firestore``): PATCH the signed-in user's own
  document with privileged fields via ``updateMask``, then GET the document back
  and confirm none of the injected sentinels persisted. The separate read-back is
  what distinguishes this from the status-only privilege-field write in
  ``tests/test_firestore_rules.py``: here a 200 is not the finding, a persisted
  value is.

Scope / safety
--------------
- Every probe MUTATES (PATCH) and carries ``@pytest.mark.write_probe``: it runs
  only under ``--full``/``--branch`` (``PENTEST_MODE=full``), never in the
  read-only default. It also carries ``@pytest.mark.asvs_extended`` so it is
  deselected unless ``SCAN_SCOPE=asvs``. Dual-tagged ``asvs``+``cwe`` for the
  coverage ledger.
- The probes write to the TEST ACCOUNT'S OWN record (the row/doc user_a already
  owns) and then **best-effort restore** the original values in a ``finally``
  block, so a vulnerable target is not left with sentinel privilege flags on the
  test account. The restore is best-effort: a failed revert never masks the
  finding. Ownership-transfer columns (``owner_id`` / ``tenant_id`` / ``user_id``)
  are deliberately not mutated, because reassigning them on the live row would
  move it out of the test account's RLS scope and orphan it. Cross-tenant
  ownership escalation is covered separately by the cross-user probes in
  ``tests/test_rls_bypass.py`` and ``tests/test_idor.py``.
- Residual limitation (documented, not a bug): the PostgREST variant probes only
  columns present on the fetched row. Categorical columns are probed with a
  realistic privileged value (role='admin', plan='enterprise') so an enum/CHECK
  does not reject the probe outright, and an all-value-rejected outcome is treated
  as inconclusive (skip), never clean. What still escapes detection is a privileged
  column that is write-allowed but read-withheld, or a privileged literal this
  catalogue does not guess (e.g. role='superadmin'). A green run is evidence the
  obvious mass-assignment vectors are closed, not a proof of full BOPLA safety.
- On the shipped example profiles the placeholder host short-circuits every live
  request via the ``profile`` fixture, so these skip before any traffic. The
  offline unit tests at the bottom exercise the pure reflection helpers with no
  network.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

import pytest

# ---------------------------------------------------------------------------
# Package-root import shim + collection-time profile loading
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile, resolve_profile_path  # noqa: E402
from helpers import FakeResponse, supabase_headers  # noqa: E402
from tests.conftest import all_tables  # noqa: E402


def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:  # noqa: BLE001
        return None


_PROFILE = _collection_profile()

USER_FACING_TABLES: list[str] = (
    all_tables(_PROFILE, "user_facing") if _PROFILE else []
)

_FIRESTORE_COLLECTIONS: list[str] = (
    list(_PROFILE.firebase.firestore_collections)
    if _PROFILE and _PROFILE.firebase and _PROFILE.firebase.firestore_collections
    else []
)

_TEST_DOC_IDS = (
    _PROFILE.firebase.test_document_ids
    if _PROFILE and _PROFILE.firebase and _PROFILE.firebase.test_document_ids
    else None
)


# ---------------------------------------------------------------------------
# Privileged field catalogues
# ---------------------------------------------------------------------------
#
# Each maps a privileged field NAME to the value the client must never be able to
# assign. Two kinds of value are used deliberately:
#   - Booleans / numerics (is_admin, balance, ...) get an unmistakable sentinel
#     (True, an implausible balance). These columns have no enum/CHECK domain, so
#     the sentinel is always accepted-or-denied, never value-rejected.
#   - Categorical string columns (role, plan, tier) get a REALISTIC privileged
#     value (admin, enterprise). A foreign literal like "sb_mass_assign_probe"
#     would be 400-rejected by an enum/CHECK on those columns even on a target
#     that wrongly allows role='admin', so the probe would miss the canonical
#     role-escalation case. The PostgREST loop additionally treats an all-4xx
#     outcome as inconclusive (skip), so a value-rejection never reads as clean.
# Ownership-transfer columns are intentionally absent (see the module docstring
# "Scope / safety" note).

# A balance/credit sentinel that is implausible as real data.
_BALANCE_SENTINEL = 133713371337

# PostgREST tables conventionally use snake_case columns.
_POSTGREST_PRIVILEGED_FIELDS: dict[str, object] = {
    "is_admin": True,
    "role": "admin",
    "is_verified": True,
    "email_verified": True,
    "plan": "enterprise",
    "subscription_tier": "enterprise",
    "balance": _BALANCE_SENTINEL,
    "credits": _BALANCE_SENTINEL,
}

# Firestore documents are schemaless (no enum/CHECK), so a distinctive foreign
# sentinel is safe for the string fields and avoids granting a real privileged
# value. Cover both snake_case and camelCase so the probe fires regardless of the
# app's naming convention.
_FIRESTORE_PRIVILEGED_FIELDS: dict[str, object] = {
    "isAdmin": True,
    "is_admin": True,
    "role": "sb_mass_assign_probe",
    "isVerified": True,
    "plan": "sb_mass_assign_probe",
    "subscription": "sb_mass_assign_probe",
    "tier": "sb_mass_assign_probe",
    "balance": _BALANCE_SENTINEL,
}


# ---------------------------------------------------------------------------
# URL / header helpers
# ---------------------------------------------------------------------------


def _rest_url(profile, table: str) -> str:
    base = (profile.supabase and profile.supabase.project_url) or ""
    return f"{base}/rest/v1/{table}"


def _authed_headers(profile, client, **extra: str) -> dict[str, str]:
    """Supabase anon key plus the signed-in user's Bearer token (mirror rls_bypass)."""
    headers = supabase_headers(profile, require_key=True, **extra)
    auth = client.headers.get("Authorization", "")
    if auth:
        headers["Authorization"] = auth
    return headers


def _pk_col(profile, table: str) -> str | None:
    """Primary-key column for *table* from profile.supabase.table_pks, or None."""
    raw = profile.supabase and getattr(profile.supabase, "table_pks", None)
    if raw is None:
        return None
    mapping = vars(raw) if hasattr(raw, "__dict__") else raw
    if isinstance(mapping, dict):
        return mapping.get(table)
    return None


# ---------------------------------------------------------------------------
# Pure reflection helpers (offline-testable)
# ---------------------------------------------------------------------------


def _values_equal(returned: object, sentinel: object) -> bool:
    """True when a read-back value equals the injected sentinel.

    Compared as strings so that ``True``/``"true"`` and ``1337``/``"1337"`` (a
    JSON number a backend may stringify, or vice-versa) count as the same
    persisted value. A mass-assignment finding must not be missed because the
    store round-tripped the type.
    """
    return str(returned).strip().lower() == str(sentinel).strip().lower()


def _existing_privileged_columns(row, catalogue: dict[str, object]) -> dict[str, object]:
    """Privileged fields from *catalogue* that already exist as keys on *row*.

    Restricting the PATCH to columns that already exist on the fetched row keeps
    PostgREST from rejecting the whole statement with a 400 "column does not
    exist", which is a schema fact rather than a finding. A column whose current
    value already equals the sentinel is dropped (nothing to prove).
    """
    if not isinstance(row, dict):
        return {}
    return {
        field: sentinel
        for field, sentinel in catalogue.items()
        if field in row and not _values_equal(row.get(field), sentinel)
    }


def _reflected_privileged_fields(returned, injected: dict[str, object]) -> list[str]:
    """Names of injected fields whose sentinel value survived into *returned*.

    *returned* is the read-back object (a PostgREST row dict or a decoded
    Firestore document field map). A non-empty result is the mass-assignment
    finding: the client controlled a field it must not.
    """
    if not isinstance(returned, dict):
        return []
    return [
        field
        for field, sentinel in injected.items()
        if field in returned and _values_equal(returned[field], sentinel)
    ]


def _first_representation_row(resp) -> dict:
    """Extract the first row from a PostgREST select / representation response."""
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return {}
    if isinstance(body, list):
        return body[0] if body and isinstance(body[0], dict) else {}
    return body if isinstance(body, dict) else {}


# Firestore typed-value helpers ----------------------------------------------

# Firestore REST wraps each field value in a single-key type envelope, e.g.
# {"booleanValue": true} / {"stringValue": "x"} / {"integerValue": "1337"}.
_FIRESTORE_VALUE_KEYS = (
    "booleanValue",
    "stringValue",
    "integerValue",
    "doubleValue",
)


def _firestore_field_map(doc) -> dict[str, object]:
    """Flatten a Firestore document's ``fields`` map to ``{name: scalar}``.

    Unwraps the single-key type envelope so the shared reflection helper can
    compare scalars uniformly. Unknown / complex value types (mapValue,
    arrayValue) are skipped, since the privileged fields probed here are scalars.
    """
    fields = doc.get("fields") if isinstance(doc, dict) else None
    if not isinstance(fields, dict):
        return {}
    flat: dict[str, object] = {}
    for name, envelope in fields.items():
        if not isinstance(envelope, dict):
            continue
        for key in _FIRESTORE_VALUE_KEYS:
            if key in envelope:
                flat[name] = envelope[key]
                break
    return flat


def _firestore_typed_fields(injected: dict[str, object]) -> dict[str, dict]:
    """Wrap injected scalars in Firestore type envelopes for a PATCH body."""
    typed: dict[str, dict] = {}
    for name, value in injected.items():
        if isinstance(value, bool):
            typed[name] = {"booleanValue": value}
        elif isinstance(value, int):
            typed[name] = {"integerValue": str(value)}
        else:
            typed[name] = {"stringValue": str(value)}
    return typed


# ---------------------------------------------------------------------------
# Best-effort teardown (restore the test account's own record)
# ---------------------------------------------------------------------------


def _restore_postgrest_row(client, url, pk, pkval, originals, headers, evidence, table) -> None:
    """Revert probed columns to their snapshot values. Best-effort, never raises.

    A vulnerable target would otherwise be left with sentinel privilege flags
    (is_admin=true, an absurd balance) on the test account. A failed restore is
    captured as evidence but never masks the finding.
    """
    try:
        resp = client.patch(url, params={pk: f"eq.{pkval}"}, json=originals, headers=headers)
        status = resp.status_code
    except Exception:  # noqa: BLE001
        status = 0
    evidence.capture(
        FakeResponse(status, url, f"[body omitted] best-effort restore of {list(originals)}", "PATCH"),
        label=f"mass_assign_restore_{table}",
    )


def _restore_firestore_doc(client, doc_url, headers, wrote, pre_fields, evidence, collection) -> None:
    """Restore (or delete) each privileged field written during the probe.

    Fields that pre-existed are reset to their exact original typed envelope;
    fields the probe introduced are deleted (an empty ``fields`` map under the
    field's updateMask removes it). currentDocument.exists keeps the restore a
    pure update so it can never re-create a since-deleted document. Best-effort,
    never raises.
    """
    for field in wrote:
        if field in pre_fields:
            body = {"fields": {field: pre_fields[field]}}
        else:
            body = {"fields": {}}
        try:
            client.patch(
                doc_url,
                json=body,
                headers=headers,
                params={"updateMask.fieldPaths": field, "currentDocument.exists": "true"},
            )
        except Exception:  # noqa: BLE001
            pass
    evidence.capture(
        FakeResponse(0, doc_url, f"[body omitted] best-effort restore of {wrote}", "PATCH"),
        label=f"mass_assign_restore_{collection}",
    )


# ===========================================================================
# PostgREST variant: own-row privileged-column injection
# ===========================================================================


@pytest.mark.supabase
@pytest.mark.write_probe
@pytest.mark.asvs_extended
@pytest.mark.asvs("8.2.3")
@pytest.mark.asvs("15.3.3")
@pytest.mark.cwe("915")
@pytest.mark.parametrize("table", USER_FACING_TABLES or ["skip"])
def test_postgrest_mass_assignment_own_row(table, profile, user_a_client, evidence):
    """A client must not set privileged columns on its own PostgREST row.

    Steps (all RLS-scoped to user_a, so only the test account's own data is
    touched):
      1. GET the user's own row (``?limit=1``) and snapshot it.
      2. Detect which privileged columns from the catalogue already exist on it.
      3. PATCH those columns with a privileged value, one field per request.
      4. GET the row again (authoritative read-back) and confirm the value did
         NOT persist.
      5. Best-effort restore the original values.

    If every column write is rejected by value/constraint validation (no 2xx and
    no 401/403), the result is inconclusive and the probe skips rather than
    reporting clean.

    A persisted sentinel is a CWE-915 / V8.2.3 mass-assignment finding: the write
    handler bound a client-supplied privileged field instead of allow-listing
    writable columns. The read-back is an independent GET (not the PATCH
    representation) so a stripped ``Prefer`` header or a 204 cannot mask a
    persisted write. Skips cleanly when the table is unreadable, the user owns no
    row, no usable primary key is configured, none of the privileged columns
    exist, or the read-back is itself unconfirmable.
    """
    if table == "skip":
        pytest.skip("No user-facing tables in profile, nothing to mass-assign (V8.2.3).")

    url = _rest_url(profile, table)
    read_headers = _authed_headers(profile, user_a_client)
    sel = user_a_client.get(url, params={"limit": 1, "select": "*"}, headers=read_headers)
    evidence.capture(
        FakeResponse(sel.status_code, url, f"[body omitted] read own row of {table}", "GET"),
        label=f"mass_assign_select_{table}",
    )

    if sel.status_code != 200:
        pytest.skip(
            f"Cannot read own rows of '{table}' (HTTP {sel.status_code}), "
            "no baseline to probe for mass assignment."
        )
    own_row = _first_representation_row(sel)
    if not own_row:
        pytest.skip(f"User owns no row in '{table}', nothing to PATCH for mass assignment.")

    pk = _pk_col(profile, table)
    if not pk or pk not in own_row:
        pytest.skip(
            f"No usable primary key for '{table}' (table_pks missing or pk absent "
            "from row), cannot target a single row for the mass-assignment PATCH."
        )

    injected = _existing_privileged_columns(own_row, _POSTGREST_PRIVILEGED_FIELDS)
    if not injected:
        pytest.skip(
            f"No privileged columns present on '{table}' rows, no mass-assignment "
            "surface to probe."
        )

    # Snapshot originals for teardown before mutating anything.
    originals = {field: own_row.get(field) for field in injected}
    patch_headers = _authed_headers(profile, user_a_client)
    pkval = own_row[pk]
    persisted: list[str] = []
    # A write is "conclusive" when PostgREST either accepted it (2xx, persistence
    # then decided by read-back) or denied it on authorization grounds (401/403,
    # column is write-protected). A 400/409/422 is value/constraint rejection: it
    # proves nothing about whether a VALID privileged value would be accepted, so
    # it is inconclusive. If every probed column was only value-rejected we must
    # NOT report clean (see the inconclusive skip after the loop).
    saw_conclusive = False
    try:
        # One PATCH per field: a single multi-column UPDATE is atomic, so one
        # protected column would roll the whole statement back and mask a
        # genuinely writable sibling (an attacker would simply send that field
        # alone). The finding is decided by the independent read-back below.
        for field, value in injected.items():
            resp = user_a_client.patch(
                url, params={pk: f"eq.{pkval}"}, json={field: value}, headers=patch_headers
            )
            evidence.capture(
                FakeResponse(resp.status_code, url, f"[body omitted] PATCH {field}", "PATCH"),
                label=f"mass_assign_patch_{table}_{field}",
            )
            if resp.status_code in (401, 403) or 200 <= resp.status_code < 300:
                saw_conclusive = True

        rb = user_a_client.get(url, params={pk: f"eq.{pkval}", "select": "*"}, headers=read_headers)
        evidence.capture(
            FakeResponse(rb.status_code, url, f"[body omitted] read-back of {table}", "GET"),
            label=f"mass_assign_readback_{table}",
        )
        rb_row = _first_representation_row(rb)
        if rb.status_code != 200 or not rb_row:
            pytest.skip(
                f"Cannot read back row of '{table}' after PATCH (HTTP {rb.status_code}), "
                "cannot confirm whether the privileged columns persisted."
            )
        persisted = _reflected_privileged_fields(rb_row, injected)
    finally:
        _restore_postgrest_row(user_a_client, url, pk, pkval, originals, patch_headers, evidence, table)

    if not persisted and not saw_conclusive:
        pytest.skip(
            f"Every privileged-column write on '{table}' was rejected by value/"
            "constraint validation (no 2xx accept and no 401/403 denial), so the "
            "mass-assignment surface is undetermined: a valid privileged value for "
            "this schema may still be assignable. Configure schema-appropriate "
            "privileged values to probe it conclusively."
        )

    assert not persisted, (
        f"Mass assignment accepted on table '{table}': the client set privileged "
        f"column(s) {persisted} on its own row via a PATCH body and the value "
        "persisted on read-back. The write handler binds client-supplied fields "
        "instead of allow-listing writable columns (ASVS V8.2.3 / V15.3.3, "
        "CWE-915). Restrict writable columns with a PostgREST column grant / RLS "
        "WITH CHECK, or strip privileged keys in the API layer before the write."
    )


# ===========================================================================
# Firestore variant: own-document privileged-field injection (read-back)
# ===========================================================================


@pytest.mark.firestore
@pytest.mark.write_probe
@pytest.mark.asvs_extended
@pytest.mark.asvs("8.2.3")
@pytest.mark.asvs("15.3.3")
@pytest.mark.cwe("915")
@pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
def test_firestore_mass_assignment_own_doc(collection, profile, user_a_client, evidence):
    """A client must not persist privileged fields onto its own Firestore doc.

    Confirm user_a can read their own document (positive control), then PATCH it
    with privileged fields via ``updateMask`` one field at a time, then GET the
    document back and confirm none of the injected sentinels persisted. Unlike
    the status-only privilege-field write in ``test_firestore_rules.py``, the
    finding here is a PERSISTED value confirmed by read-back, not a 200. Security
    Rules that allow arbitrary self-writes let the app trust a self-asserted
    ``isAdmin`` / ``role`` from the document store (CWE-915 / V8.2.3).

    Firestore's PATCH upserts, so every write carries ``currentDocument.exists``
    and the probe runs only when the baseline document already exists. That keeps
    a missing/misconfigured ``test_document_ids.user_a`` from turning the probe
    into document creation and a false positive. The probe best-effort restores
    the document afterward. Skips cleanly when the collection list or
    ``test_document_ids.user_a`` is absent, or the baseline doc is unreadable.
    """
    if collection == "skip":
        pytest.skip("No Firestore collections in profile, nothing to mass-assign (V8.2.3).")

    doc_id = _TEST_DOC_IDS and getattr(_TEST_DOC_IDS, "user_a", None)
    if not doc_id:
        pytest.skip(
            f"No test_document_ids.user_a in profile, cannot probe mass assignment "
            f"for collection '{collection}'."
        )

    project_id = (profile.firebase and profile.firebase.project_id) or ""
    base = (
        f"https://firestore.googleapis.com/v1/projects/{project_id}"
        f"/databases/(default)/documents"
    )
    doc_url = f"{base}/{collection}/{doc_id}"
    auth = user_a_client.headers.get("Authorization", "")
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = auth

    # Positive-control gate (mirrors test_firestore_rules): the probe is only
    # meaningful against a PRE-EXISTING document the user already owns. Firestore's
    # PATCH upserts, so without this gate a missing/misconfigured user_a doc would
    # turn the probe into document CREATION, and read-back would then find the
    # fields the probe itself wrote and report a false positive. Skip unless the
    # baseline document is readable now.
    pre = user_a_client.get(doc_url, headers=headers)
    evidence.capture(
        FakeResponse(pre.status_code, doc_url, f"[body omitted] read own doc in {collection}", "GET"),
        label=f"mass_assign_select_{collection}",
    )
    try:
        pre_body = pre.json() if pre.status_code == 200 else {}
    except Exception:  # noqa: BLE001
        pre_body = {}
    if not (isinstance(pre_body, dict) and pre_body.get("name")):
        pytest.skip(
            f"Positive control failed: cannot read user_a's own document "
            f"'{doc_id}' in collection '{collection}' (HTTP {pre.status_code}). "
            "Without a readable baseline the upserting PATCH would create the "
            "document rather than test mass assignment, so the probe is skipped."
        )
    pre_fields = pre_body.get("fields") or {}

    injected = dict(_FIRESTORE_PRIVILEGED_FIELDS)
    wrote: list[str] = []
    persisted: list[str] = []
    saw_conclusive = False
    try:
        # One PATCH per field: a Firestore commit is atomic, so a rule that denies
        # any single field in a multi-field write fails the whole commit and would
        # mask a field the attacker could set on its own. currentDocument.exists
        # makes every write a pure UPDATE: if the doc vanished (TOCTOU after the
        # gate), Firestore returns FAILED_PRECONDITION instead of creating it.
        for field, sentinel in injected.items():
            patch_resp = user_a_client.patch(
                doc_url,
                json={"fields": _firestore_typed_fields({field: sentinel})},
                headers=headers,
                params={"updateMask.fieldPaths": field, "currentDocument.exists": "true"},
            )
            evidence.capture(
                FakeResponse(patch_resp.status_code, doc_url, f"[body omitted] PATCH {field}", "PATCH"),
                label=f"mass_assign_patch_{collection}_{field}",
            )
            if 200 <= patch_resp.status_code < 300:
                wrote.append(field)
                saw_conclusive = True
            elif patch_resp.status_code in (401, 403):
                saw_conclusive = True

        if not wrote:
            if not saw_conclusive:
                pytest.skip(
                    f"Every privileged write to '{collection}' was rejected for a "
                    "non-authorization reason (no 2xx, no 401/403), e.g. a failed "
                    "currentDocument precondition; mass-assignment safety is "
                    "undetermined."
                )
            return  # Security Rules denied every privileged write. Control enforced.

        # Read-back: a 200 does not prove persistence, so confirm the stored doc.
        get_resp = user_a_client.get(doc_url, headers=headers)
        evidence.capture(
            FakeResponse(get_resp.status_code, doc_url, f"[body omitted] read-back of {collection}", "GET"),
            label=f"mass_assign_readback_{collection}",
        )
        if get_resp.status_code != 200:
            pytest.skip(
                f"Cannot read back document after PATCH for '{collection}' "
                f"(HTTP {get_resp.status_code}), cannot confirm whether the "
                "privileged fields persisted."
            )
        persisted = _reflected_privileged_fields(_firestore_field_map(get_resp.json()), injected)
    finally:
        _restore_firestore_doc(user_a_client, doc_url, headers, wrote, pre_fields, evidence, collection)

    assert not persisted, (
        f"Mass assignment accepted on collection '{collection}': the client wrote "
        f"privileged field(s) {persisted} to its own document with a standard "
        "token and the value persisted on read-back. If the app later trusts these "
        "fields from the document store, a user can self-grant privileges (ASVS "
        "V8.2.3 / V15.3.3, CWE-915). Security Rules must block writes to "
        "privilege-bearing fields unless the request carries the appropriate "
        "custom claim."
    )


# ===========================================================================
# Offline unit tests for the pure helpers (no live target). Lock the read-back
# semantics so the type-coercion, column-existence, and PostgREST/Firestore
# extraction logic cannot silently regress.
# ===========================================================================


@pytest.mark.parametrize(
    "returned,sentinel,expected",
    [
        (True, True, True),
        ("true", True, True),       # backend stringified the bool
        (1337, "1337", True),       # number vs string round-trip
        (" Admin ", "admin", True), # whitespace + case folded
        ("user", "sb_mass_assign_probe", False),
        (False, True, False),
        (None, True, False),
    ],
)
def test_values_equal_coerces_types(returned, sentinel, expected):
    assert _values_equal(returned, sentinel) is expected


def test_existing_privileged_columns_filters_to_present_and_changed():
    row = {"id": "x", "role": "user", "is_admin": False, "title": "doc"}
    present = _existing_privileged_columns(row, _POSTGREST_PRIVILEGED_FIELDS)
    # role + is_admin exist and differ from the sentinel, so probe them.
    assert set(present) == {"role", "is_admin"}
    # 'balance'/'plan' are not columns on this row, so exclude them (would 400).
    assert "balance" not in present


def test_existing_privileged_columns_drops_value_already_at_sentinel():
    row = {"id": "x", "role": "sb_mass_assign_probe"}
    # Nothing to prove if the row already carries the sentinel.
    assert _existing_privileged_columns(row, {"role": "sb_mass_assign_probe"}) == {}


def test_existing_privileged_columns_guards_non_dict():
    assert _existing_privileged_columns(None, _POSTGREST_PRIVILEGED_FIELDS) == {}
    assert _existing_privileged_columns(["not", "a", "dict"], {}) == {}


def test_reflected_privileged_fields_detects_persisted_sentinel():
    injected = {"is_admin": True, "role": "sb_mass_assign_probe", "balance": 1337}
    returned = {"id": "x", "is_admin": True, "role": "user", "balance": 0}
    # Only is_admin survived as the injected sentinel.
    assert _reflected_privileged_fields(returned, injected) == ["is_admin"]


def test_reflected_privileged_fields_empty_when_ignored():
    injected = {"is_admin": True, "role": "sb_mass_assign_probe"}
    returned = {"id": "x", "is_admin": False, "role": "user"}
    assert _reflected_privileged_fields(returned, injected) == []


def test_reflected_privileged_fields_guards_non_dict():
    assert _reflected_privileged_fields(None, {"is_admin": True}) == []
    assert _reflected_privileged_fields("string", {}) == []


class _FakeJSON:
    """Minimal stub exposing .json() for _first_representation_row tests."""

    def __init__(self, payload, raises: bool = False):
        self._payload = payload
        self._raises = raises

    def json(self):
        if self._raises:
            raise ValueError("not JSON")
        return self._payload


@pytest.mark.parametrize(
    "resp,expected",
    [
        (_FakeJSON([{"id": "x", "is_admin": True}]), {"id": "x", "is_admin": True}),
        (_FakeJSON({"id": "y"}), {"id": "y"}),     # bare object (maxRows ignored)
        (_FakeJSON([]), {}),                        # empty list
        (_FakeJSON(["scalar"]), {}),                # list whose [0] is not a dict
        (_FakeJSON("oops", raises=True), {}),       # non-JSON body
        (_FakeJSON(42), {}),                         # neither list nor dict
    ],
)
def test_first_representation_row_handles_all_shapes(resp, expected):
    assert _first_representation_row(resp) == expected


def test_firestore_field_map_unwraps_typed_envelopes():
    doc = {
        "name": "projects/p/databases/(default)/documents/users/u",
        "fields": {
            "isAdmin": {"booleanValue": True},
            "role": {"stringValue": "user"},
            "balance": {"integerValue": "1337"},
            "score": {"doubleValue": 3.14},
            "nested": {"mapValue": {"fields": {}}},  # skipped (non-scalar)
        },
    }
    flat = _firestore_field_map(doc)
    assert flat == {"isAdmin": True, "role": "user", "balance": "1337", "score": 3.14}


def test_firestore_field_map_guards_missing_or_non_dict_fields():
    assert _firestore_field_map(None) == {}
    assert _firestore_field_map({"name": "x"}) == {}          # no 'fields' key
    assert _firestore_field_map({"fields": "nope"}) == {}     # non-dict 'fields'


def test_firestore_typed_fields_wraps_scalars():
    typed = _firestore_typed_fields({"isAdmin": True, "role": "x", "balance": 1337})
    assert typed == {
        "isAdmin": {"booleanValue": True},
        "role": {"stringValue": "x"},
        "balance": {"integerValue": "1337"},
    }


def test_firestore_roundtrip_detects_persisted_isadmin():
    # End-to-end of the read-back logic: inject isAdmin=true, read back a doc that
    # kept it (finding) vs a doc that ignored it (clean).
    injected = dict(_FIRESTORE_PRIVILEGED_FIELDS)
    kept = {"fields": {"isAdmin": {"booleanValue": True}, "role": {"stringValue": "user"}}}
    ignored = {"fields": {"isAdmin": {"booleanValue": False}, "role": {"stringValue": "user"}}}
    assert _reflected_privileged_fields(_firestore_field_map(kept), injected) == ["isAdmin"]
    assert _reflected_privileged_fields(_firestore_field_map(ignored), injected) == []
