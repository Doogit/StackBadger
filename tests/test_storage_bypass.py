"""Storage bypass tests for the user-files Supabase Storage bucket.

Tests attempt to access, list, upload to, and traverse paths within the
user-files bucket using anonymous or cross-user credentials.  Every test
asserts that the operation is denied; any 200/success response is captured
as evidence and fails the test.

Markers
-------
All tests carry ``@pytest.mark.storage`` so they are skipped when the profile
does not declare ``stack.storage: supabase``.

Synthetic UUIDs
---------------
Tests use fixed synthetic path segments rather than real user IDs to avoid
any accidental correlation with production data:

- User A storage path: ``user-a-id/upload-a-id/test.csv``
- User B storage path: ``user-b-id/upload-b-id/test.csv``
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

import pytest

# ---------------------------------------------------------------------------
# Collection-time profile loading
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile, resolve_profile_path  # noqa: E402


def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()

# ---------------------------------------------------------------------------
# Constants — bucket names loaded from profile; empty list → tests not collected
# ---------------------------------------------------------------------------

_BUCKETS: list[str] = (
    list(_PROFILE.supabase.storage_buckets)
    if _PROFILE and _PROFILE.supabase and _PROFILE.supabase.storage_buckets
    else []
)

# Synthetic path segments (not real Clerk user IDs or upload UUIDs).
USER_A_PATH = "user-a-id/upload-a-id/test.csv"
USER_B_PATH = "user-b-id/upload-b-id/test.csv"

# Minimal file payload for upload tests — generic CSV content, not site-specific.
_CSV_CONTENT = b"id,value\n1,test\n"

# Status codes that indicate the storage operation was correctly denied.
DENY_CODES = {400, 401, 403, 404}

# Path traversal payloads — each should be rejected or resolve to a
# non-existent / forbidden path rather than leaking another user's file.
TRAVERSAL_PAYLOADS = [
    f"user-a-id/../user-b-id/upload-b-id/test.csv",
    f"user-a-id/..%2fuser-b-id/upload-b-id/test.csv",
    f"user-a-id/..%252fuser-b-id/upload-b-id/test.csv",
    f"user-a-id/....//user-b-id/upload-b-id/test.csv",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(params=_BUCKETS, ids=_BUCKETS)
def bucket(request):
    """Yield each configured storage bucket for parametrized testing."""
    return request.param


@pytest.fixture(autouse=True)
def _require_supabase_storage_config(profile):
    """Skip storage probes when Supabase config was not discovered.

    Without a project_url + anon_key there is no Supabase Storage endpoint to
    probe, and building an ``Authorization: Bearer {anon_key}`` header from an
    empty anon_key raises ``httpx.LocalProtocolError: Illegal header value
    b'Bearer '`` before any request is sent. Skip cleanly with a clear reason
    instead of crashing.
    """
    supa = profile.supabase
    if not (supa and supa.project_url and supa.anon_key):
        pytest.skip(
            "Supabase storage config (project_url + anon_key) not available — "
            "cannot probe storage buckets."
        )


def _storage_object_url(profile, bucket: str, path: str) -> str:
    """Build the full Supabase Storage object URL for the given path."""
    base = (profile.supabase and profile.supabase.project_url) or ""
    return f"{base.rstrip('/')}/storage/v1/object/{bucket}/{path}"


def _storage_list_url(profile, bucket: str) -> str:
    """Build the Supabase Storage bucket-list URL."""
    base = (profile.supabase and profile.supabase.project_url) or ""
    return f"{base.rstrip('/')}/storage/v1/object/list/{bucket}"


def _anon_storage_headers(profile) -> dict:
    """Return minimal headers for an anonymous storage request."""
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""
    return {
        "apikey": anon_key,
        "Authorization": f"Bearer {anon_key}",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.storage
def test_anon_download_denied(profile, anon_client, evidence, bucket):
    """Anonymous requests to download a file must be denied (no auth token)."""
    url = _storage_object_url(profile, bucket, USER_A_PATH)
    headers = _anon_storage_headers(profile)

    resp = anon_client.get(url, headers=headers)

    if resp.status_code not in DENY_CODES:
        evidence.capture(resp, label="anon_download_unexpectedly_allowed")

    assert resp.status_code in DENY_CODES, (
        f"Expected denial ({DENY_CODES}) for anon download, "
        f"got HTTP {resp.status_code}. "
        "Storage bucket is publicly readable — this is a HIGH-severity finding."
    )


@pytest.mark.storage
def test_cross_user_download_denied(profile, user_a_client, evidence, bucket):
    """User A must not be able to download a file at User B's storage path.

    The RLS / Storage policy should scope access to the authenticated user's
    own path prefix.  Accessing another user's prefix should yield 400/401/403/404.
    """
    base = (profile.supabase and profile.supabase.project_url) or ""
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""
    url = _storage_object_url(profile, bucket, USER_B_PATH)

    # user_a_client carries User A's JWT; add the required apikey header.
    resp = user_a_client.get(url, headers={"apikey": anon_key})

    if resp.status_code not in DENY_CODES:
        evidence.capture(resp, label="cross_user_download_unexpectedly_allowed")

    assert resp.status_code in DENY_CODES, (
        f"User A received HTTP {resp.status_code} for User B's storage path. "
        "Cross-user file access is a HIGH-severity finding."
    )


@pytest.mark.storage
@pytest.mark.parametrize("traversal_path", TRAVERSAL_PAYLOADS)
def test_path_traversal_denied(profile, user_a_client, evidence, traversal_path, bucket):
    """Path traversal attempts in the storage path must be denied or return no data.

    Supabase Storage normalises paths server-side, so a ``../`` sequence should
    either be rejected outright or resolve to a path the requester is not
    authorised to access.
    """
    base = (profile.supabase and profile.supabase.project_url) or ""
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""
    url = _storage_object_url(profile, bucket, traversal_path)

    resp = user_a_client.get(url, headers={"apikey": anon_key})

    if resp.status_code == 200:
        evidence.capture(resp, label="path_traversal_succeeded")

    assert resp.status_code in DENY_CODES, (
        f"Path traversal payload '{traversal_path}' returned HTTP {resp.status_code}. "
        "If content was returned this is a HIGH-severity storage bypass."
    )


@pytest.mark.storage
def test_bucket_listing_denied_anon(profile, anon_client, evidence, bucket):
    """Anonymous bucket listing must be denied or return an empty result.

    A successful listing of bucket contents exposes all user file paths,
    which is a privacy violation and potential HIGH-severity finding.
    """
    url = _storage_list_url(profile, bucket)
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""
    headers = {
        "apikey": anon_key,
        "Authorization": f"Bearer {anon_key}",
        "Content-Type": "application/json",
    }

    resp = anon_client.post(url, json={"prefix": "", "limit": 10}, headers=headers)

    # Denied outright — ideal outcome.
    if resp.status_code in DENY_CODES:
        return

    # 200 with an empty list is also acceptable (no data leaked).
    if resp.status_code == 200:
        try:
            body = resp.json()
        except Exception:
            body = []
        if isinstance(body, list) and len(body) == 0:
            return  # Empty listing — no data exposed.
        # Non-empty listing — capture and fail.
        evidence.capture(resp, label="bucket_listing_leaked_data")
        pytest.fail(
            f"Anon bucket listing returned {len(body)} item(s). "
            "Bucket contents are publicly enumerable — HIGH-severity finding."
        )
    else:
        # Unexpected status; capture for review.
        evidence.capture(resp, label="bucket_listing_unexpected_status")
        pytest.fail(
            f"Unexpected HTTP {resp.status_code} from anon bucket listing. "
            "Manual review of captured evidence is required."
        )


@pytest.mark.write_probe
@pytest.mark.storage
def test_upload_to_other_user_path_denied(profile, user_a_client, evidence, bucket):
    """User A must not be able to upload a file to User B's storage path prefix.

    If the storage policy is path-prefix scoped to the authenticated user's ID,
    uploading to another user's prefix must return 400/401/403.
    """
    base = (profile.supabase and profile.supabase.project_url) or ""
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""
    url = _storage_object_url(profile, bucket, USER_B_PATH)

    resp = user_a_client.post(
        url,
        content=_CSV_CONTENT,
        headers={
            "apikey": anon_key,
            "Content-Type": "text/csv",
        },
    )

    if resp.status_code not in DENY_CODES:
        evidence.capture(resp, label="cross_user_upload_unexpectedly_allowed")

    assert resp.status_code in DENY_CODES, (
        f"User A received HTTP {resp.status_code} when uploading to User B's path. "
        "Cross-user write access is a HIGH-severity finding."
    )


@pytest.mark.storage
@pytest.mark.skip(
    reason=(
        "Signed URL reuse test requires a pre-existing signed URL with a known "
        "expiry time.  Generate one manually, wait for expiry, then replay the "
        "request and assert HTTP 400/401/403."
    )
)
def test_signed_url_reuse_requires_manual_setup():
    """Document: signed URL reuse test requires a pre-existing signed URL.

    To run this test manually:
    1. Generate a signed URL for a real file via the Supabase dashboard or
       ``supabase storage sign <bucket>/<path> --expires-in 3600``.
    2. Record the full URL (includes ``?token=...``).
    3. Use the URL after the original signed window has elapsed.
    4. The request should return 400/401/403 once the signature is expired.

    This cannot be automated in the harness without pre-existing production
    artefacts.  Mark as xfail or skip when no signed URL is available.
    """
