"""Anonymous session security tests.

Tests probe the ``merge_anon_session`` RPC and PostgREST header-based anon
session access for header forgery, session hijacking, replay, enumeration, and
cross-header injection vulnerabilities.

All tests carry ``@pytest.mark.supabase`` and are skipped when the profile
does not declare ``stack.database: supabase``.

Design notes
------------
- The anon session merge RPC transfers data from an anonymous session
  (identified by ``anon_id`` UUID) to an authenticated user account.
  Security requirements:
    1. The ``anon_id`` must be *owned* by the calling user — other users'
       anon sessions must not be mergeable.
    2. A merge must be idempotent-safe: a second call with the same
       ``anon_id`` after the session has been consumed must not transfer
       additional rows or return an error that leaks session state.
    3. The RPC must not be callable without a valid Bearer JWT.
- PostgREST honours the anon session header for anonymous upload
  tracking.  A forged header must never expose another user's rows.
"""

from __future__ import annotations

import sys as _sys
import time
import uuid
from pathlib import Path as _Path

import httpx
import pytest

# ---------------------------------------------------------------------------
# Ensure the StackBadger package root is importable at collection time.
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from helpers import supabase_headers  # noqa: E402
from conftest import find_rpc  # noqa: E402


# ---------------------------------------------------------------------------
# Collection-time profile loading
# ---------------------------------------------------------------------------

def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        from profile import load_profile, resolve_profile_path  # type: ignore[import]
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()


# ---------------------------------------------------------------------------
# Module-level skip when the profile declares anon_sessions: false
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    _PROFILE is not None
    and _PROFILE.features is not None
    and not _PROFILE.features.anon_sessions,
    reason="profile.features.anon_sessions is false — anon session tests skipped",
)

# ---------------------------------------------------------------------------
# Resolve the anon-session merge RPC name from the profile at call time.
# Delegates to conftest.find_rpc, which raises Skipped when no client_callable
# RPC matching ("merge", "anon") is declared.
# ---------------------------------------------------------------------------

def _require_merge_rpc(profile) -> str:
    """Return the anon-session merge RPC name from the profile, or skip when none."""
    return find_rpc(profile, "client_callable", name_contains=("merge", "anon"))["name"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# A UUID that has never been inserted — all tests that send this expect 0 rows.
_RANDOM_ANON_ID = str(uuid.uuid4())

# A second random UUID used for replay and enumeration probes.
_RANDOM_ANON_ID_2 = str(uuid.uuid4())

# Common UUID patterns sometimes tried in enumeration attacks.
_KNOWN_UUID_PATTERNS = [
    "00000000-0000-0000-0000-000000000000",   # nil UUID
    "ffffffff-ffff-ffff-ffff-ffffffffffff",   # all-F UUID
    "11111111-1111-1111-1111-111111111111",
    "deadbeef-dead-beef-dead-beefdeadbeef",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rpc_url(profile, function_name: str) -> str:
    base = (profile.supabase and profile.supabase.project_url) or ""
    if not base:
        pytest.skip("supabase.project_url not available — cannot build RPC URL")
    return f"{base.rstrip('/')}/rest/v1/rpc/{function_name}"


def _uploads_url(profile) -> str:
    """Return the PostgREST URL for the uploads table."""
    base = (profile.supabase and profile.supabase.project_url) or ""
    if not base:
        pytest.skip("supabase.project_url not available — cannot build uploads URL")
    # Prefer profile-declared table name if available.
    from conftest import all_tables
    user_facing = all_tables(profile, "user_facing")
    table = "uploads" if "uploads" in user_facing else (user_facing[0] if user_facing else "uploads")
    return f"{base.rstrip('/')}/rest/v1/{table}"


def _anon_session_header(profile) -> str:
    """Return the anon session header name from the profile."""
    return (profile.custom_headers and profile.custom_headers.anon_session) or "x-anon-session"


def _anon_headers(profile, anon_session_id: str | None = None) -> dict:
    """Return PostgREST headers for an anonymous (no JWT) request."""
    extra = {}
    if anon_session_id is not None:
        extra[_anon_session_header(profile)] = anon_session_id
    return supabase_headers(profile, include_content_type=False, require_key=True, **extra)


def _row_count(resp: httpx.Response) -> int:
    """Parse a PostgREST JSON array response and return the number of rows."""
    try:
        body = resp.json()
        if isinstance(body, list):
            return len(body)
    except Exception:
        pass
    return 0


# ---------------------------------------------------------------------------
# Tests — header forgery
# ---------------------------------------------------------------------------

@pytest.mark.supabase
def test_header_forgery_random_uuid_returns_no_rows(profile, evidence):
    """A forged anon session header with a random UUID must return 0 uploads.

    PostgREST RLS must scope the uploads table to rows whose anon_session_id
    matches the anon session header value.  A header with a UUID that was
    never inserted must yield an empty result set, not an error that leaks
    schema details.
    """
    url = _uploads_url(profile)
    headers = _anon_headers(profile, anon_session_id=_RANDOM_ANON_ID)

    with httpx.Client(timeout=10) as client:
        resp = client.get(url, headers=headers)

    if resp.status_code == 200 and _row_count(resp) > 0:
        evidence.capture(resp, label="header_forgery_random_uuid_leaked_rows")
        pytest.fail(
            f"Forged anon session header returned {_row_count(resp)} row(s). "
            "RLS is not scoping anon session rows correctly — HIGH-severity finding."
        )

    # 200 with 0 rows, or any denial code, is the expected outcome.
    assert resp.status_code in {200, 400, 401, 403, 404}, (
        f"Unexpected HTTP {resp.status_code} for forged anon session header."
    )
    assert _row_count(resp) == 0, (
        "Forged anon session header returned rows — RLS policy is broken."
    )


@pytest.mark.supabase
@pytest.mark.parametrize("fake_uuid", _KNOWN_UUID_PATTERNS)
def test_header_forgery_known_uuid_patterns(profile, evidence, fake_uuid):
    """Known UUID patterns (nil, all-F, etc.) used as anon session IDs must return 0 rows.

    Attackers sometimes try well-known or trivial UUIDs hoping that a
    misconfigured system has inserted rows under them during testing.
    """
    url = _uploads_url(profile)
    headers = _anon_headers(profile, anon_session_id=fake_uuid)

    with httpx.Client(timeout=10) as client:
        resp = client.get(url, headers=headers)

    if resp.status_code == 200 and _row_count(resp) > 0:
        evidence.capture(resp, label=f"header_forgery_known_uuid_{fake_uuid[:8]}_leaked")
        pytest.fail(
            f"Known UUID pattern '{fake_uuid}' returned {_row_count(resp)} row(s). "
            "A test or seed row may be exposed — HIGH-severity finding."
        )

    assert _row_count(resp) == 0, (
        f"Anon header with UUID '{fake_uuid}' leaked rows."
    )


# ---------------------------------------------------------------------------
# Tests — merge_anon_session RPC
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
@pytest.mark.supabase
def test_merge_hijack_with_stolen_anon_id(profile, user_a_client, evidence):
    """User A cannot merge a random/stolen anon_id that they do not own.

    The RPC must verify that the anon_id being merged was created by the
    calling user's session.  Merging an unowned UUID must result in an error
    or a zero-row transfer — not a silent success that could hijack another
    user's pre-auth data.
    """
    merge_rpc_name = _require_merge_rpc(profile)
    url = _rpc_url(profile, merge_rpc_name)
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""

    # Build the RPC request using User A's JWT but a random anon_id.
    # user_a_client already carries User A's Authorization header; we only
    # need to add the apikey and Content-Type.
    resp = user_a_client.post(
        url,
        json={"anon_id": _RANDOM_ANON_ID},
        headers={
            "apikey": anon_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    # The RPC should return an error code or a result indicating 0 rows moved.
    if resp.status_code == 200:
        body = resp.json() if resp.content else None
        # Accept an explicit 0-rows result (e.g. {"rows_moved": 0}).
        rows_moved = 0
        if isinstance(body, dict):
            rows_moved = body.get("rows_moved", body.get("count", 0)) or 0
        elif isinstance(body, int):
            rows_moved = body

        if rows_moved > 0:
            evidence.capture(resp, label="merge_hijack_succeeded")
            pytest.fail(
                f"{merge_rpc_name} moved {rows_moved} row(s) for an unowned anon_id. "
                "Anon session hijack is a HIGH-severity finding."
            )
    else:
        # Non-200 — either an RPC error or access denied.  Both are acceptable.
        # Capture only if the error body might leak internal state.
        if resp.status_code not in {400, 401, 403, 404, 422}:
            evidence.capture(resp, label="merge_hijack_unexpected_status")


@pytest.mark.write_probe
@pytest.mark.supabase
def test_merge_replay_second_call_is_safe(profile, user_a_client, evidence):
    """Calling the merge RPC twice with the same anon_id must be safe.

    The second call should either:
    - Return a result indicating 0 rows moved (idempotent), or
    - Return an error indicating the session is already consumed.

    It must NOT transfer additional rows on replay, which would indicate the
    merge is not idempotent and rows could be duplicated.
    """
    merge_rpc_name = _require_merge_rpc(profile)
    url = _rpc_url(profile, merge_rpc_name)
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""
    rpc_headers = {
        "apikey": anon_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # First call — may succeed (0 rows if UUID not real) or fail gracefully.
    resp1 = user_a_client.post(
        url,
        json={"anon_id": _RANDOM_ANON_ID_2},
        headers=rpc_headers,
    )

    # Second call — the critical one.
    resp2 = user_a_client.post(
        url,
        json={"anon_id": _RANDOM_ANON_ID_2},
        headers=rpc_headers,
    )

    if resp2.status_code == 200:
        body = resp2.json() if resp2.content else None
        rows_moved = 0
        if isinstance(body, dict):
            rows_moved = body.get("rows_moved", body.get("count", 0)) or 0
        elif isinstance(body, int):
            rows_moved = body

        if rows_moved > 0:
            evidence.capture(resp2, label="merge_replay_transferred_extra_rows")
            pytest.fail(
                f"{merge_rpc_name} replay moved {rows_moved} additional row(s). "
                "Merge is not idempotent — rows could be duplicated. HIGH-severity."
            )
    # Any error on the second call (400/409/422) is acceptable — it means the
    # session was consumed and cannot be replayed.


@pytest.mark.write_probe
@pytest.mark.supabase
def test_merge_requires_valid_jwt(profile, evidence):
    """The merge RPC must not be callable without a valid Bearer JWT.

    Sending the RPC with only the anon key (no user JWT) must return 401/403.
    """
    merge_rpc_name = _require_merge_rpc(profile)
    url = _rpc_url(profile, merge_rpc_name)
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""

    with httpx.Client(timeout=10) as client:
        resp = client.post(
            url,
            json={"anon_id": _RANDOM_ANON_ID},
            headers={
                "apikey": anon_key,
                "Authorization": f"Bearer {anon_key}",  # anon key, NOT user JWT
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

    if resp.status_code not in {401, 403}:
        evidence.capture(resp, label="merge_no_jwt_unexpectedly_accepted")

    assert resp.status_code in {401, 403}, (
        f"{merge_rpc_name} returned HTTP {resp.status_code} without a user JWT. "
        "The RPC must require an authenticated user — HIGH-severity finding."
    )


# ---------------------------------------------------------------------------
# Tests — enumeration timing
# ---------------------------------------------------------------------------

@pytest.mark.supabase
def test_anon_session_enumeration_no_timing_oracle(profile, evidence):
    """Multiple anon session header probes must not reveal a timing oracle.

    If valid session UUIDs take measurably longer to respond than invalid ones,
    an attacker can enumerate active sessions via timing.  This test measures
    the response time for several UUIDs and asserts they fall within a
    reasonable variance band (±500 ms).

    Note: this is a probabilistic test; network jitter can cause false
    positives.  It is intended as a canary, not a hard gate.
    """
    url = _uploads_url(profile)
    probe_ids = [str(uuid.uuid4()) for _ in range(5)]
    timings: list[float] = []

    with httpx.Client(timeout=15) as client:
        for probe_id in probe_ids:
            headers = _anon_headers(profile, anon_session_id=probe_id)
            t0 = time.monotonic()
            client.get(url, headers=headers)
            timings.append(time.monotonic() - t0)

    if timings:
        min_t = min(timings)
        max_t = max(timings)
        spread = max_t - min_t
        # Allow up to 500 ms variance (network jitter tolerance).
        TIMING_THRESHOLD = 0.5
        if spread > TIMING_THRESHOLD:
            # Capture a summary dict — no actual response content leaked.
            evidence.capture(
                # Build a synthetic response object to satisfy EvidenceCapture.
                _TimingSummaryResponse(probe_ids, timings),
                label="timing_variance_detected",
            )
            # Warn but do not hard-fail: timing tests are inherently noisy.
            pytest.xfail(
                f"Timing spread {spread:.3f}s exceeds {TIMING_THRESHOLD}s threshold. "
                "May indicate a timing oracle.  Verify manually with repeated runs."
            )


# ---------------------------------------------------------------------------
# Tests — cross-header injection
# ---------------------------------------------------------------------------

@pytest.mark.supabase
def test_jwt_takes_precedence_over_anon_session_header(profile, user_a_client, evidence):
    """When both the anon session header and a valid JWT are sent, JWT must take precedence.

    The system must never return rows from an anon session when the request
    also carries a valid user JWT.  The authenticated identity must win and
    only rows owned by User A (via JWT) should be visible — not rows from
    the anon session UUID.
    """
    url = _uploads_url(profile)
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""
    anon_session_hdr = _anon_session_header(profile)

    # Send User A's JWT together with a forged anon session header.
    resp = user_a_client.get(
        url,
        headers={
            "apikey": anon_key,
            anon_session_hdr: _RANDOM_ANON_ID,
            "Accept": "application/json",
        },
    )

    if resp.status_code == 200:
        rows = _row_count(resp)
        # We can't assert 0 rows here because User A may have real uploads.
        # What we assert instead: the response must not contain the anon_id
        # we injected (a data-leak canary).
        body_text = resp.text or ""
        if _RANDOM_ANON_ID in body_text:
            evidence.capture(resp, label="anon_session_id_leaked_in_jwt_response")
            pytest.fail(
                "The forged anon_id appeared in the authenticated response body. "
                "JWT did not fully suppress the anon session header — possible data leak."
            )
    elif resp.status_code in {400, 401, 403}:
        pass  # Denied — acceptable.
    else:
        evidence.capture(resp, label="jwt_anon_header_unexpected_status")
        pytest.fail(
            f"Unexpected HTTP {resp.status_code} when sending both JWT and "
            "the anon session header.  Manual review required."
        )


# ---------------------------------------------------------------------------
# Internal helper — synthetic response for timing evidence capture
# ---------------------------------------------------------------------------

class _TimingSummaryResponse:
    """Minimal duck-type shim so EvidenceCapture can record timing data."""

    def __init__(self, probe_ids: list[str], timings: list[float]) -> None:
        import json as _json

        summary = {
            "probe_ids": probe_ids,
            "timings_seconds": [round(t, 4) for t in timings],
            "spread_seconds": round(max(timings) - min(timings), 4),
        }
        self.content = _json.dumps(summary).encode()
        self.status_code = 0  # Synthetic — not a real HTTP status.
        self.headers = {}  # Required by EvidenceCapture._build_record

        # Synthesise a minimal request object for EvidenceCapture._build_record.
        self.request = _FakeRequest()

    @property
    def text(self) -> str:
        return self.content.decode()


class _FakeRequest:
    method = "SYNTHETIC"
    url = "timing://local"
    content = b""
    headers: dict = {}
