"""Firestore Security Rules misconfiguration tests.

Tests six areas:
1. Positive control  — authenticated user can read own documents before probing.
2. Unauthenticated access — unauthenticated GET must return 403 PERMISSION_DENIED.
3. Cross-user read   — User A reading User B's document must be denied.
4. List-vs-get gap   — runQuery may expose documents that direct GET denies.
5. Write bypass      — PATCH another user's document; inject admin claim.
6. Custom claim gate — write ops requiring elevated custom claims with standard token.

Assertion rules
---------------
- Firestore returns HTTP 403 with ``PERMISSION_DENIED`` for actual denials.
- Unlike PostgREST, a denied read is NOT 200+[].  403 body contains the
  error status string "PERMISSION_DENIED".
- SPA catch-all detection is not applicable to Firestore REST calls.

Markers
-------
All tests carry ``@pytest.mark.firestore`` so they are skipped when
``stack.auth`` is not ``firebase``.
"""

from __future__ import annotations

import sys as _sys
import warnings
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
from tests.helpers import send_request  # noqa: E402


def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()

# ---------------------------------------------------------------------------
# Collection-time config extracted from profile
# ---------------------------------------------------------------------------

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
# Module-scoped positive-control state gate
# ---------------------------------------------------------------------------
# Tracks which collections passed the positive control.  Dependent probe
# tests consult this dict and skip automatically when the baseline auth
# check for their collection failed or was never run.

_positive_control_passed: dict[str, bool] = {}


def _require_positive_control(collection: str) -> None:
    """Skip the calling test if the positive control did not pass for *collection*."""
    if not _positive_control_passed.get(collection, False):
        pytest.skip(
            f"Positive control did not pass for collection '{collection}' "
            f"— skipping dependent probe"
        )


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def _firestore_base(profile) -> str:
    """Return the Firestore REST v1 base URL for the project."""
    project_id = (profile.firebase and profile.firebase.project_id) or ""
    return (
        f"https://firestore.googleapis.com/v1/projects/{project_id}"
        f"/databases/(default)/documents"
    )


def _doc_url(profile, collection: str, doc_id: str) -> str:
    """Build a URL for a single Firestore document."""
    return f"{_firestore_base(profile)}/{collection}/{doc_id}"


def _runquery_url(profile, collection: str) -> str:
    """Build the :runQuery URL.

    Firestore ``runQuery`` requires the parent to be the ``documents`` root
    (or a full document path) — NOT ``documents/{collection}``.  The target
    collection is conveyed exclusively via ``structuredQuery.from`` in the
    request body.  Building the URL with a collection segment makes the
    request hit an invalid parent and produces false failures unrelated to
    Security Rules.
    """
    return f"{_firestore_base(profile)}:runQuery"


# ---------------------------------------------------------------------------
# Auth header helpers
# ---------------------------------------------------------------------------


def _firebase_auth_headers(client) -> dict[str, str]:
    """Extract the Authorization header from a Firebase-authed client."""
    auth = client.headers.get("Authorization", "")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = auth
    return headers


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


def _is_permission_denied(response) -> bool:
    """Return True when the response represents a Firestore PERMISSION_DENIED."""
    if response.status_code == 403:
        return True
    # Firestore sometimes returns 200 with an empty document list or a single
    # error object in the array for runQuery responses.
    if response.status_code == 200:
        try:
            body = response.json()
        except Exception:
            return False
        # runQuery returns a list; a denial entry has status.code == 7 (PERMISSION_DENIED).
        if isinstance(body, list):
            for entry in body:
                if isinstance(entry, dict):
                    status = entry.get("status") or entry.get("error") or {}
                    if isinstance(status, dict):
                        if status.get("code") == 7 or status.get("status") == "PERMISSION_DENIED":
                            return True
    return False


def _has_document_content(response) -> bool:
    """Return True when the response contains a readable Firestore document."""
    if response.status_code != 200:
        return False
    try:
        body = response.json()
    except Exception:
        return False
    # Single document GET — contains 'name' and 'fields'.
    if isinstance(body, dict) and "name" in body:
        return True
    # runQuery — list with at least one document entry.
    if isinstance(body, list):
        for entry in body:
            if isinstance(entry, dict) and "document" in entry:
                return True
    return False


def _doc_ids_from_runquery(response) -> list[str]:
    """Extract document name/path strings from a :runQuery response."""
    doc_ids: list[str] = []
    try:
        body = response.json()
    except Exception:
        return doc_ids
    if isinstance(body, list):
        for entry in body:
            if isinstance(entry, dict):
                doc = entry.get("document") or {}
                name = doc.get("name") or ""
                if name:
                    # The name is a full resource path; extract the last segment.
                    doc_ids.append(name.split("/")[-1])
    return doc_ids


# ---------------------------------------------------------------------------
# Skip guard for empty collection list
# ---------------------------------------------------------------------------

def _skip_if_no_collections(collection: str) -> None:
    if collection == "skip":
        pytest.skip("No Firestore collections configured in profile")


# ===========================================================================
# Section 1: Positive control
# ===========================================================================


@pytest.mark.firestore
class TestFirestorePositiveControl:
    """Verify test user can read own documents before probing.

    If this fails, the remaining probe classes are unreliable and their
    findings should be treated as inconclusive.
    """

    @pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
    def test_positive_control_authenticated_read(
        self, collection, profile, user_a_client, evidence
    ):
        """Authenticated user_a should be able to GET their own document.

        Uses test_document_ids.user_a from the profile.  If the profile does
        not provide a document ID, this test is skipped.
        """
        _skip_if_no_collections(collection)

        doc_id = _TEST_DOC_IDS and getattr(_TEST_DOC_IDS, "user_a", None)
        if not doc_id:
            pytest.skip(
                f"No test_document_ids.user_a in profile — "
                f"cannot run positive control for collection '{collection}'"
            )

        url = _doc_url(profile, collection, doc_id)
        headers = _firebase_auth_headers(user_a_client)
        resp = user_a_client.get(url, headers=headers)
        evidence.capture(resp, label=f"firestore_positive_control_{collection}")

        if not _has_document_content(resp):
            _positive_control_passed[collection] = False
            warnings.warn(
                f"[FIRESTORE POSITIVE CONTROL] collection='{collection}': "
                f"Expected 200 with document content for user_a own doc, "
                f"got HTTP {resp.status_code}. "
                f"Remaining Firestore probes for this collection may be inconclusive. "
                f"body_preview={resp.text[:200]!r}",
                stacklevel=2,
            )
            pytest.skip(
                f"Positive control failed for collection '{collection}' "
                f"(HTTP {resp.status_code}) — skipping dependent probes"
            )

        _positive_control_passed[collection] = True


# ===========================================================================
# Section 2: Unauthenticated access
# ===========================================================================


@pytest.mark.firestore
class TestFirestoreUnauthenticatedAccess:
    """Unauthenticated GET should return 403 PERMISSION_DENIED."""

    @pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
    def test_unauthenticated_get(self, collection, profile, evidence):
        """GET a known document with no Authorization header.

        Any response other than 403 PERMISSION_DENIED is a HIGH finding.
        """
        _skip_if_no_collections(collection)
        _require_positive_control(collection)

        doc_id = _TEST_DOC_IDS and getattr(_TEST_DOC_IDS, "user_a", None)
        if not doc_id:
            pytest.skip(
                f"No test_document_ids.user_a in profile — "
                f"cannot probe unauthenticated access for collection '{collection}'"
            )

        url = _doc_url(profile, collection, doc_id)
        # Deliberately no auth headers.
        resp = send_request("GET", url, headers={"Content-Type": "application/json"})
        evidence.capture(resp, label=f"firestore_unauth_read_{collection}")

        assert _is_permission_denied(resp), (
            f"[HIGH] Firestore unauthenticated read succeeded for "
            f"collection='{collection}', doc_id='{doc_id}'. "
            f"Expected 403 PERMISSION_DENIED, got HTTP {resp.status_code}. "
            f"body_preview={resp.text[:300]!r}"
        )

    @pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
    def test_unauthenticated_list(self, collection, profile, evidence):
        """runQuery with no Authorization header must be denied.

        Tests whether unauthenticated clients can enumerate collection contents.
        """
        _skip_if_no_collections(collection)
        _require_positive_control(collection)

        url = _runquery_url(profile, collection)
        query_body = {
            "structuredQuery": {
                "from": [{"collectionId": collection}],
                "limit": 10,
            }
        }
        resp = send_request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            json_body=query_body,
        )
        evidence.capture(resp, label=f"firestore_unauth_list_{collection}")

        assert _is_permission_denied(resp), (
            f"[HIGH] Firestore unauthenticated runQuery succeeded for "
            f"collection='{collection}'. "
            f"Expected 403 PERMISSION_DENIED, got HTTP {resp.status_code}. "
            f"body_preview={resp.text[:300]!r}"
        )


# ===========================================================================
# Section 3: Cross-user read
# ===========================================================================


@pytest.mark.firestore
class TestFirestoreCrossUserRead:
    """User A reading User B's document should be denied."""

    @pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
    def test_cross_user_document_read(
        self, collection, profile, user_a_client, evidence
    ):
        """Authenticated as user_a, attempt to GET a document owned by user_b.

        Uses test_document_ids.user_b from the profile.  A 200 with content
        is a HIGH finding — Security Rules are not scoping by owner/uid.
        """
        _skip_if_no_collections(collection)
        _require_positive_control(collection)

        user_b_doc_id = _TEST_DOC_IDS and getattr(_TEST_DOC_IDS, "user_b", None)
        if not user_b_doc_id:
            pytest.skip(
                f"No test_document_ids.user_b in profile — "
                f"cannot probe cross-user read for collection '{collection}'"
            )

        url = _doc_url(profile, collection, user_b_doc_id)
        headers = _firebase_auth_headers(user_a_client)
        resp = user_a_client.get(url, headers=headers)
        evidence.capture(resp, label=f"firestore_cross_user_read_{collection}")

        if _has_document_content(resp):
            pytest.fail(
                f"[HIGH] Firestore cross-user read succeeded: user_a read "
                f"user_b's document in collection='{collection}', "
                f"doc_id='{user_b_doc_id}'. "
                f"Security Rules are not scoping by owner. "
                f"HTTP {resp.status_code}, body_preview={resp.text[:300]!r}"
            )

        assert _is_permission_denied(resp), (
            f"[HIGH] Cross-user GET not explicitly denied for "
            f"collection='{collection}', doc_id='{user_b_doc_id}'. "
            f"Expected 403 PERMISSION_DENIED, got HTTP {resp.status_code}. "
            f"body_preview={resp.text[:200]!r}"
        )


# ===========================================================================
# Section 4: List-vs-get rule gap
# ===========================================================================


@pytest.mark.firestore
class TestFirestoreListVsGet:
    """Detect list-vs-get rule gaps via runQuery.

    A common Security Rules misconfiguration allows ``get`` but not ``list``
    (or vice-versa).  If runQuery returns documents that a direct GET denies,
    the rules have a list-vs-get gap — a MEDIUM finding.
    """

    @pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
    def test_list_vs_get_runquery(
        self, collection, profile, user_a_client, evidence
    ):
        """Compare runQuery results against direct GET for the same doc IDs.

        Steps:
        1. POST :runQuery for the collection (authenticated as user_a).
        2. For each returned doc ID, attempt a direct GET.
        3. If runQuery returns a doc that GET denies → MEDIUM gap finding.
        """
        _skip_if_no_collections(collection)
        _require_positive_control(collection)

        query_url = _runquery_url(profile, collection)
        query_body: dict[str, Any] = {
            "structuredQuery": {
                "from": [{"collectionId": collection}],
                "limit": 10,
            }
        }
        headers = _firebase_auth_headers(user_a_client)
        list_resp = user_a_client.post(query_url, json=query_body, headers=headers)
        evidence.capture(list_resp, label=f"firestore_runquery_{collection}")

        # If listing is denied entirely, there is no gap to detect.
        if _is_permission_denied(list_resp):
            return

        returned_ids = _doc_ids_from_runquery(list_resp)
        if not returned_ids:
            # Nothing returned — no gap detectable.
            return

        gaps: list[str] = []
        for doc_id in returned_ids:
            get_url = _doc_url(profile, collection, doc_id)
            get_resp = user_a_client.get(get_url, headers=headers)
            evidence.capture(get_resp, label=f"firestore_get_after_list_{collection}_{doc_id[:8]}")
            if _is_permission_denied(get_resp):
                gaps.append(doc_id)

        assert not gaps, (
            f"[MEDIUM] Firestore list-vs-get gap detected in "
            f"collection='{collection}': runQuery returned {len(gaps)} doc(s) "
            f"that direct GET denies. "
            f"Doc IDs (first 3): {gaps[:3]}. "
            f"Security Rules allow list but not get (or rules differ between operations)."
        )


# ===========================================================================
# Section 5: Write bypass
# ===========================================================================


@pytest.mark.firestore
@pytest.mark.write_probe
class TestFirestoreWriteBypass:
    """Write probes: PATCH another user's doc, inject admin claim."""

    @pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
    def test_write_bypass_patch(
        self, collection, profile, user_a_client, evidence
    ):
        """Authenticated as user_a, PATCH a document owned by user_b.

        Uses the Firestore PATCH endpoint with updateMask to attempt a
        targeted field write.  A 200 response is a HIGH finding.
        """
        _skip_if_no_collections(collection)
        _require_positive_control(collection)

        user_b_doc_id = _TEST_DOC_IDS and getattr(_TEST_DOC_IDS, "user_b", None)
        if not user_b_doc_id:
            pytest.skip(
                f"No test_document_ids.user_b in profile — "
                f"cannot probe write bypass for collection '{collection}'"
            )

        url = _doc_url(profile, collection, user_b_doc_id)
        headers = _firebase_auth_headers(user_a_client)
        patch_body = {
            "fields": {
                "isAdmin": {"booleanValue": True}
            }
        }
        resp = user_a_client.patch(
            url,
            json=patch_body,
            headers=headers,
            params={"updateMask.fieldPaths": "isAdmin"},
        )
        evidence.capture(resp, label=f"firestore_write_bypass_patch_{collection}")

        assert _is_permission_denied(resp), (
            f"[HIGH] Firestore cross-user PATCH succeeded for "
            f"collection='{collection}', doc_id='{user_b_doc_id}'. "
            f"user_a wrote to user_b's document. "
            f"Expected 403 PERMISSION_DENIED, got HTTP {resp.status_code}. "
            f"body_preview={resp.text[:300]!r}"
        )

    @pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
    def test_create_in_other_user_path(
        self, collection, profile, user_a_client, evidence
    ):
        """Attempt to CREATE a document with a path that mimics user_b's namespace.

        Some Firestore rules grant write access to ``/users/{userId}/...`` paths
        by checking ``userId == request.auth.uid``.  If the rule is missing or
        uses the wrong field, user_a can create documents under user_b's path.
        A 200/201 response is a HIGH finding.
        """
        _skip_if_no_collections(collection)
        _require_positive_control(collection)

        user_b_doc_id = _TEST_DOC_IDS and getattr(_TEST_DOC_IDS, "user_b", None)
        if not user_b_doc_id:
            pytest.skip(
                f"No test_document_ids.user_b in profile — "
                f"cannot probe path-scoped create for collection '{collection}'"
            )

        # Build a true nested subcollection path to exercise path-scoped
        # Firestore security rules (e.g. /users/{userId}/documents/{docId}).
        # A flat top-level ID like "{user_b_doc_id}__pentest_probe" would NOT
        # trigger the /users/{userId}/... rule path.
        nested_path = f"{user_b_doc_id}/documents/pentest_probe"
        url = _doc_url(profile, collection, nested_path)
        headers = _firebase_auth_headers(user_a_client)
        create_body = {
            "fields": {
                "pentest": {"stringValue": "probe"},
            }
        }
        resp = user_a_client.patch(
            url,
            json=create_body,
            headers=headers,
        )
        evidence.capture(resp, label=f"firestore_create_other_path_{collection}")

        assert _is_permission_denied(resp), (
            f"[HIGH] Firestore path-scoped create succeeded: user_a created a "
            f"document under user_b's path in collection='{collection}'. "
            f"Expected 403 PERMISSION_DENIED, got HTTP {resp.status_code}. "
            f"body_preview={resp.text[:300]!r}"
        )


# ===========================================================================
# Section 6: Custom claim gate
# ===========================================================================


@pytest.mark.firestore
@pytest.mark.write_probe
class TestFirestoreCustomClaimGate:
    """Probe write ops that require elevated custom claims.

    Security Rules that gate on custom claims (e.g. ``request.auth.token.isAdmin``)
    can be bypassed if the rule also allows writes to a user's own document — a
    standard token can then be used to write ``isAdmin: true`` into the user's
    own document, which the app may later trust.
    """

    @pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
    def test_custom_claim_gate_probe(
        self, collection, profile, user_a_client, evidence
    ):
        """Write ``isAdmin: true`` to user_a's own document using a standard token.

        If the write succeeds, Security Rules either:
        - Do not enforce the custom claim on the ``isAdmin`` field, OR
        - Allow arbitrary field writes to own document (which is still a HIGH
          finding if the application trusts this field from the database).
        """
        _skip_if_no_collections(collection)
        _require_positive_control(collection)

        user_a_doc_id = _TEST_DOC_IDS and getattr(_TEST_DOC_IDS, "user_a", None)
        if not user_a_doc_id:
            pytest.skip(
                f"No test_document_ids.user_a in profile — "
                f"cannot probe custom claim gate for collection '{collection}'"
            )

        url = _doc_url(profile, collection, user_a_doc_id)
        headers = _firebase_auth_headers(user_a_client)
        patch_body = {
            "fields": {
                "isAdmin": {"booleanValue": True},
            }
        }
        resp = user_a_client.patch(
            url,
            json=patch_body,
            headers=headers,
            params={"updateMask.fieldPaths": "isAdmin"},
        )
        evidence.capture(resp, label=f"firestore_custom_claim_gate_{collection}")

        if resp.status_code == 200:
            pytest.fail(
                f"[HIGH] Firestore custom claim gate not enforced: "
                f"user_a wrote isAdmin=true to their own document in "
                f"collection='{collection}', doc_id='{user_a_doc_id}', "
                f"using a standard (non-elevated) Firebase token. "
                f"Security Rules rely on a custom claim that is self-writable. "
                f"HTTP {resp.status_code}, body_preview={resp.text[:300]!r}"
            )

    @pytest.mark.parametrize("collection", _FIRESTORE_COLLECTIONS or ["skip"])
    def test_privilege_field_write_own_doc(
        self, collection, profile, user_a_client, evidence
    ):
        """Attempt to write several common privilege-escalation field names.

        Tests whether Security Rules block writes to well-known privilege
        fields on a user's own document.  A 200 on any field is a HIGH finding.
        """
        _skip_if_no_collections(collection)
        _require_positive_control(collection)

        user_a_doc_id = _TEST_DOC_IDS and getattr(_TEST_DOC_IDS, "user_a", None)
        if not user_a_doc_id:
            pytest.skip(
                f"No test_document_ids.user_a in profile — "
                f"cannot probe privilege field write for collection '{collection}'"
            )

        privilege_fields = ["isAdmin", "role", "subscription", "plan", "tier"]
        url = _doc_url(profile, collection, user_a_doc_id)
        headers = _firebase_auth_headers(user_a_client)

        written_fields: list[str] = []
        for field in privilege_fields:
            patch_body = {
                "fields": {
                    field: {"stringValue": "admin"},
                }
            }
            resp = user_a_client.patch(
                url,
                json=patch_body,
                headers=headers,
                params={"updateMask.fieldPaths": field},
            )
            evidence.capture(
                resp,
                label=f"firestore_priv_field_{collection}_{field}",
            )
            if resp.status_code == 200:
                written_fields.append(field)

        assert not written_fields, (
            f"[HIGH] Firestore privilege field write succeeded on own document: "
            f"collection='{collection}', doc_id='{user_a_doc_id}', "
            f"fields written without elevated claims: {written_fields}. "
            f"Security Rules must block writes to privilege-bearing fields "
            f"unless the request carries the appropriate custom claim."
        )
