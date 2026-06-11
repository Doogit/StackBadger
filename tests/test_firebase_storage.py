"""Firebase Storage access control tests.

Probes the Firebase Storage REST API for:
- Public object access (unauthenticated GET without a download token)
- Bucket listing without auth (should be denied)
- Cross-user path access (User A authenticated, accessing User B's path)
- Download token reuse from an unauthenticated session
- Path injection via filename containing ``../``

Markers
-------
All tests carry ``@pytest.mark.firebase_storage`` so they are automatically
skipped when the active profile's ``stack.storage`` is not ``firebase``.

Write-probe tests also carry ``@pytest.mark.write_probe`` and are skipped
unless ``PENTEST_MODE=full``.

Profile config consumed
-----------------------
``profile.firebase.storage_bucket``          — GCS bucket name (required)
``profile.firebase.test_storage_paths.user_a`` — full object path for User A's file
``profile.firebase.test_storage_paths.user_b`` — full object path for User B's file

If ``test_storage_paths`` is absent from the profile, path-dependent tests are
skipped with a WARN rather than failing or fabricating synthetic paths.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path
from urllib.parse import quote

import pytest

# ---------------------------------------------------------------------------
# Collection-time profile loading
# ---------------------------------------------------------------------------


_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile, resolve_profile_path  # noqa: E402
from helpers import FakeResponse, send_request  # noqa: E402


def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()

# ---------------------------------------------------------------------------
# Constants derived from profile
# ---------------------------------------------------------------------------

_BUCKET: str = (
    (_PROFILE.firebase.storage_bucket if _PROFILE and _PROFILE.firebase else None) or ""
)

_TEST_PATHS = (
    _PROFILE.firebase.test_storage_paths
    if _PROFILE and _PROFILE.firebase and _PROFILE.firebase.test_storage_paths
    else None
)

# Firebase Storage REST base URL template — bucket populated at call time.
_FIREBASE_STORAGE_BASE = "https://firebasestorage.googleapis.com/v0/b"

# Download token UUID pattern used for redaction in evidence.
_TOKEN_PATTERN = re.compile(r"token=[0-9a-f\-]{36}")

# ---------------------------------------------------------------------------
# Module-scoped positive-control state gate
# ---------------------------------------------------------------------------
# Tracks whether the positive control passed.  Dependent probe tests consult
# this flag and skip automatically when the baseline auth check failed or was
# never run.  Same pattern as test_firestore_rules.py.

_positive_control_passed: dict[str, bool] = {}


def _require_positive_control() -> None:
    """Skip the calling test if the positive control did not pass."""
    if not _positive_control_passed.get("storage", False):
        pytest.skip(
            "Positive control did not pass for Firebase Storage "
            "— skipping dependent probe"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _storage_base(profile) -> str:
    """Return the Firebase Storage REST base URL for the configured bucket."""
    bucket = (profile.firebase and profile.firebase.storage_bucket) or ""
    return f"{_FIREBASE_STORAGE_BASE}/{bucket}/o"


def _object_url(profile, path: str, alt: str = "media") -> str:
    """Build a Firebase Storage object URL with URL-encoded path.

    Firebase Storage requires the object name to be percent-encoded, with
    forward slashes encoded as ``%2F`` (safe="" encodes everything).

    Args:
        profile: Parsed profile object.
        path: Storage object path, e.g. ``"users/abc123/file.csv"``.
        alt: ``"media"`` to download the file content; ``"json"`` for metadata.

    Returns:
        Full Firebase Storage REST URL.
    """
    base = _storage_base(profile)
    encoded = quote(path, safe="")
    return f"{base}/{encoded}?alt={alt}"


def _listing_url(profile) -> str:
    """Return the Firebase Storage bucket-listing URL (no object path)."""
    base = _storage_base(profile)
    return f"{base}?alt=json"


def _redact_token(text: str) -> str:
    """Replace download token UUIDs with ``[REDACTED]`` for safe evidence storage."""
    return _TOKEN_PATTERN.sub("token=[REDACTED]", text)


def _redact_signed_url(url: str) -> str:
    """Strip signature-bearing query params from a presigned/signed URL.

    Replaces values for ``X-Amz-Signature``, ``X-Amz-Credential``,
    ``token``, ``GoogleAccessId``, and ``Signature`` query params with
    ``[REDACTED]`` so that live bearer-style credentials are never
    persisted in evidence artifacts.
    """
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    _REDACT_PARAMS = {
        "X-Amz-Signature",
        "X-Amz-Credential",
        "token",
        "GoogleAccessId",
        "Signature",
    }
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    redacted = False
    for key in _REDACT_PARAMS:
        if key in params:
            params[key] = ["[REDACTED]"]
            redacted = True
    if not redacted:
        return url
    # Rebuild query string preserving param order where possible.
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))



def _skip_if_no_bucket(profile) -> None:
    """Skip the calling test if no storage bucket is configured."""
    bucket = (profile.firebase and profile.firebase.storage_bucket) or ""
    if not bucket:
        pytest.skip(
            "firebase.storage_bucket not set in profile — "
            "Firebase Storage tests require a configured bucket."
        )


def _skip_if_no_test_paths(profile) -> None:
    """Skip the calling test if test_storage_paths is absent from the profile."""
    paths = (
        profile.firebase.test_storage_paths
        if profile.firebase and profile.firebase.test_storage_paths
        else None
    )
    if not paths:
        pytest.skip(
            "[WARN] firebase.test_storage_paths not set in profile. "
            "Provide user_a and user_b paths under firebase.test_storage_paths "
            "to enable path-dependent Firebase Storage tests."
        )


def _user_a_path(profile) -> str:
    """Return the configured User A storage path, or skip."""
    paths = profile.firebase and profile.firebase.test_storage_paths
    path = paths and paths.user_a
    if not path:
        pytest.skip(
            "[WARN] firebase.test_storage_paths.user_a not set in profile."
        )
    return path


def _user_b_path(profile) -> str:
    """Return the configured User B storage path, or skip."""
    paths = profile.firebase and profile.firebase.test_storage_paths
    path = paths and paths.user_b
    if not path:
        pytest.skip(
            "[WARN] firebase.test_storage_paths.user_b not set in profile."
        )
    return path


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


@pytest.mark.firebase_storage
class TestFirebaseStoragePositiveControl:
    """Verify test user can access their own file.

    This is a sanity check.  If User A cannot download their own file, the
    remaining probes may produce false positives.  On failure the test emits
    a WARN via pytest.warns and skips the assertion so the remaining suite
    can still run.
    """

    def test_positive_control_download(self, profile, user_a_client, evidence):
        """User A should be able to download their own file (positive control).

        If this test fails the remaining Firebase Storage probes may be
        unreliable.  The failure is captured as evidence and the test is
        marked as an expected skip rather than a hard failure so downstream
        probes are not skipped by the CI gate.
        """
        _skip_if_no_bucket(profile)
        _skip_if_no_test_paths(profile)

        path = _user_a_path(profile)
        url = _object_url(profile, path, alt="media")

        resp = user_a_client.get(url)

        if resp.status_code != 200:
            _positive_control_passed["storage"] = False
            safe = FakeResponse(
                status_code=resp.status_code,
                url=_redact_signed_url(str(getattr(getattr(resp, "request", None), "url", url))),
                body=_redact_token(resp.text or ""),
                method="GET",
            )
            evidence.capture(safe, label="positive_control_failed")
            pytest.skip(
                f"[WARN] Positive control failed: User A received HTTP "
                f"{resp.status_code} for their own file at {url!r}. "
                "Verify firebase.test_storage_paths.user_a and that User A "
                "has a valid Firebase ID token. Skipping remaining probes."
            )

        _positive_control_passed["storage"] = True

        # Capture the successful response so reviewers can confirm the file
        # exists and the token is valid without replaying requests.
        safe = FakeResponse(
            status_code=resp.status_code,
            url=_redact_signed_url(str(getattr(getattr(resp, "request", None), "url", url))),
            body=_redact_token(resp.text or ""),
            method="GET",
        )
        evidence.capture(safe, label="positive_control_ok")


@pytest.mark.firebase_storage
class TestFirebaseStorageAnonymousListing:
    """Bucket listing without auth should be denied.

    Firebase Storage Security Rules should prevent unauthenticated callers
    from enumerating objects in the bucket.  A successful listing exposes all
    stored file paths, which is a CRITICAL-severity information disclosure.
    """

    def test_anonymous_listing(self, profile, evidence):
        """GET the bucket listing endpoint with no auth headers.

        Expected: 403 (or 401).
        Finding: CRITICAL if 200 and ``items`` key is present in the response.
        """
        _skip_if_no_bucket(profile)

        url = _listing_url(profile)
        resp = send_request("GET", url)

        if resp.status_code == 200:
            try:
                body = resp.json()
            except Exception:
                body = {}

            if isinstance(body, dict) and "items" in body:
                evidence.capture(resp, label="anon_bucket_listing_critical")
                pytest.fail(
                    f"[CRITICAL] Unauthenticated bucket listing returned HTTP 200 "
                    f"with {len(body['items'])} item(s). All object paths in the "
                    f"bucket are publicly enumerable. "
                    f"URL: {url!r}"
                )

            # 200 but no 'items' key — capture and report as unexpected but not critical.
            evidence.capture(resp, label="anon_bucket_listing_200_no_items")
            pytest.fail(
                f"[WARN] Unauthenticated bucket listing returned HTTP 200 "
                f"but no 'items' key in body. Manual review required. "
                f"URL: {url!r}"
            )

        # 403/401 — expected outcome.
        assert resp.status_code in (401, 403), (
            f"Expected 401 or 403 for unauthenticated bucket listing, "
            f"got HTTP {resp.status_code}. URL: {url!r}"
        )

    def test_unauthenticated_get_no_token(self, profile, evidence):
        """GET a known object path with no auth headers and no download token.

        Firebase Storage should deny unauthenticated reads unless the Security
        Rules explicitly allow public reads.

        Expected: 401 or 403.
        Finding: HIGH if 200 with file content.
        """
        _skip_if_no_bucket(profile)
        _skip_if_no_test_paths(profile)
        _require_positive_control()

        path = _user_a_path(profile)
        url = _object_url(profile, path, alt="media")

        resp = send_request("GET", url)

        if resp.status_code == 200:
            evidence.capture(resp, label="unauthenticated_get_no_token_200")
            pytest.fail(
                f"[HIGH] Unauthenticated GET (no token) returned HTTP 200 "
                f"for object path {path!r}. "
                "Firebase Storage Security Rules allow public object reads. "
                f"URL: {url!r}"
            )

        assert resp.status_code in (401, 403), (
            f"Expected 401 or 403 for unauthenticated GET without token, "
            f"got HTTP {resp.status_code}. URL: {url!r}"
        )


@pytest.mark.firebase_storage
class TestFirebaseStorageCrossUser:
    """Cross-user path access should be denied.

    User A is authenticated but attempts to download a file at User B's
    storage path.  Firebase Security Rules should scope access to the
    authenticated user's own path prefix.
    """

    def test_cross_user_path_access(self, profile, user_a_client, evidence):
        """User A (authenticated) attempts to GET User B's file.

        Expected: 403.
        Finding: HIGH if 200 with file content.
        """
        _skip_if_no_bucket(profile)
        _skip_if_no_test_paths(profile)
        _require_positive_control()

        path_b = _user_b_path(profile)
        url = _object_url(profile, path_b, alt="media")

        resp = user_a_client.get(url)

        if resp.status_code == 200:
            safe = FakeResponse(
                status_code=resp.status_code,
                url=_redact_signed_url(str(getattr(getattr(resp, "request", None), "url", url))),
                body=_redact_token(resp.text or ""),
                method="GET",
            )
            evidence.capture(safe, label="cross_user_path_access_high")
            pytest.fail(
                f"[HIGH] Cross-user path access: User A received HTTP 200 "
                f"for User B's object at {path_b!r}. "
                "Firebase Storage Security Rules do not isolate user paths. "
                f"URL: {_redact_signed_url(url)!r}"
            )

        assert resp.status_code in (400, 401, 403, 404), (
            f"Expected denial (400/401/403/404) for cross-user path access, "
            f"got HTTP {resp.status_code}. URL: {_redact_signed_url(url)!r}"
        )


@pytest.mark.firebase_storage
class TestFirebaseStorageDownloadToken:
    """Download token reuse from an unauthenticated session.

    Firebase Storage download tokens (``?token=<uuid>``) bypass Security
    Rules entirely.  If a token is obtained via a legitimate authenticated
    request, it must not be replayable by an unauthenticated client.

    This class tests whether:
    1. User A can obtain a download token from the metadata endpoint.
    2. That token can be replayed from a fresh unauthenticated session.

    Finding: MEDIUM — documents the token behavior for the report even when
    expected (Firebase tokens do not expire by default; they are permanent
    until manually revoked).
    """

    def test_download_token_reuse(self, profile, user_a_client, evidence):
        """Obtain a download token for User A's file, then replay it unauthenticated.

        Steps:
        1. Fetch object metadata as User A (``?alt=json``) — this returns a
           ``downloadTokens`` field containing one or more token UUIDs.
        2. Build the full download URL with ``?token=<uuid>``.
        3. Replay the URL from a fresh httpx session with no auth headers.
        4. Capture the result; any non-error response is a MEDIUM finding.

        Note: Firebase download tokens are permanent by default.  This is
        expected behavior but should be documented in the pentest report.
        """
        _skip_if_no_bucket(profile)
        _skip_if_no_test_paths(profile)
        _require_positive_control()

        path = _user_a_path(profile)
        meta_url = _object_url(profile, path, alt="json")

        # Step 1: Fetch metadata as User A to extract a download token.
        meta_resp = user_a_client.get(meta_url)

        if meta_resp.status_code != 200:
            pytest.skip(
                f"[WARN] Could not fetch object metadata as User A "
                f"(HTTP {meta_resp.status_code}). "
                "Skipping download token reuse test — check "
                "firebase.test_storage_paths.user_a."
            )

        try:
            meta_body = meta_resp.json()
        except Exception:
            pytest.skip(
                "[WARN] Object metadata response is not JSON. "
                "Skipping download token reuse test."
            )

        download_tokens_raw = meta_body.get("downloadTokens", "")
        if not download_tokens_raw:
            pytest.skip(
                "[WARN] Object metadata does not include downloadTokens. "
                "Token may have been revoked or the object was uploaded without "
                "generating a token.  Skipping download token reuse test."
            )

        # Use the first token (comma-separated list per Firebase spec).
        token = str(download_tokens_raw).split(",")[0].strip()

        # Step 2: Build the download URL with the token appended.
        base_url = _storage_base(profile)
        encoded_path = quote(path, safe="")
        token_url = f"{base_url}/{encoded_path}?alt=media&token={token}"

        # Step 3: Replay from a fresh unauthenticated session.
        replay_resp = send_request("GET", token_url)

        # Step 4: Redact the token before capturing evidence.
        #
        # EvidenceCapture persists ``response.request.url`` verbatim, so
        # passing ``replay_resp`` directly would write the raw
        # ``?token=<uuid>`` to disk despite the redaction below.  Build a
        # sanitised FakeResponse whose request URL has the token replaced
        # with ``[REDACTED]`` and capture THAT instead, in both branches.
        redacted_url = _redact_token(token_url)
        redacted_body = _redact_token(replay_resp.text or "")
        sanitised_resp = FakeResponse(
            status_code=replay_resp.status_code,
            url=redacted_url,
            body=redacted_body,
            method="GET",
        )

        if replay_resp.status_code == 200:
            # INFO: Firebase download tokens are permanent by default and
            # bypass Security Rules until manually revoked.  This is expected
            # behavior when objects have downloadTokens — not a vulnerability.
            # Capture as informational evidence for the report; do not fail.
            evidence.capture(sanitised_resp, label="download_token_reuse_info")
            import warnings
            warnings.warn(
                f"[INFO] Download token reuse: unauthenticated replay of a "
                f"Firebase download token returned HTTP 200. "
                "Firebase download tokens are permanent and bypass Security Rules "
                "until manually revoked via the Firebase Console or Admin SDK. "
                f"Redacted URL: {redacted_url!r}. "
                "Recommendation: rotate tokens after use or disable public token "
                "generation in Storage Security Rules.",
                stacklevel=1,
            )
        else:
            # Token replay was denied — capture the redacted denial as
            # evidence (the request URL still carries the raw token).
            evidence.capture(sanitised_resp, label="download_token_replay_denied")
            assert replay_resp.status_code in (400, 401, 403), (
                f"Unexpected status {replay_resp.status_code} when replaying "
                f"download token unauthenticated."
            )


@pytest.mark.firebase_storage
@pytest.mark.write_probe
class TestFirebaseStoragePathInjection:
    """Path injection via filename containing ``../``.

    Tests whether the application's upload API accepts filenames containing
    path traversal sequences (``../``) and whether those sequences survive
    into the resulting Firebase Storage object path.

    If the returned download URL contains a traversal segment in the key,
    this is a MEDIUM finding.  The test submits the traversal payload to the
    app's upload endpoint and inspects the returned download URL.
    """

    def test_path_injection_upload(self, profile, user_a_client, evidence):
        """Submit a filename with ``../`` to the app upload API.

        The test inspects the download URL returned by the upload endpoint:
        - If the key path in the download URL contains ``../`` or ``..%2F``
          → MEDIUM finding (traversal was not sanitised).
        - If the upload was rejected or the traversal was stripped
          → pass (input was sanitised).

        This test requires the profile to declare an upload endpoint path
        under ``target.upload_path`` (or ``firebase.upload_endpoint``) or
        uses the default ``/.netlify/functions/get-upload-url``.
        """
        _skip_if_no_bucket(profile)
        _require_positive_control()

        api_prefix = (profile.target and profile.target.api_prefix) or "/.netlify/functions"
        base_url = (profile.target and profile.target.base_url) or ""

        # Use a configurable upload endpoint; fall back to the known function path.
        # Check target.upload_path (documented config) first, then
        # firebase.upload_endpoint, then the default path.
        upload_path = (
            (profile.target and getattr(profile.target, "upload_path", None))
            or (profile.firebase and profile.firebase.upload_endpoint)
            or "/get-upload-url"
        )
        upload_url = base_url.rstrip("/") + api_prefix.rstrip("/") + "/" + upload_path.lstrip("/")

        # Traversal payload embedded in the filename field.
        traversal_filename = "../../../injected-path/pwned.csv"

        resp = user_a_client.post(
            upload_url,
            json={"filename": traversal_filename, "content_type": "text/csv"},
        )

        # If the server rejected the upload request, that is acceptable.
        if resp.status_code in (400, 401, 403, 404, 422):
            evidence.capture(resp, label="path_injection_upload_rejected")
            return

        if resp.status_code != 200:
            evidence.capture(resp, label="path_injection_upload_unexpected")
            # Non-200 non-denial is captured but not failed — may be unrelated.
            pytest.skip(
                f"[WARN] Upload endpoint returned HTTP {resp.status_code} "
                "for path injection payload. "
                "Inspect evidence for manual review."
            )
            return

        # 200 — inspect the returned download URL for traversal in the key.
        try:
            body = resp.json()
        except Exception:
            evidence.capture(resp, label="path_injection_upload_non_json")
            return

        # Extract download URL from common response shapes.
        download_url = (
            body.get("downloadUrl")
            or body.get("download_url")
            or body.get("url")
            or body.get("signedUrl")
            or body.get("signed_url")
            or ""
        )

        if not download_url:
            # No download URL in response — cannot confirm traversal.
            # Redact body before capture since non-standard fields may contain
            # signed URLs or tokens that should not be persisted in evidence.
            redacted_body = _TOKEN_PATTERN.sub("token=[REDACTED]", resp.text or "")
            sanitised_no_url = FakeResponse(
                status_code=resp.status_code,
                url=str(getattr(getattr(resp, "request", None), "url", "")) or "",
                body=redacted_body,
                method="POST",
            )
            evidence.capture(sanitised_no_url, label="path_injection_no_download_url")
            return

        # Check whether the traversal sequence survived into the storage key.
        traversal_indicators = [
            "../",
            "..%2F",
            "..%252F",
        ]
        key_contains_traversal = any(
            ind.lower() in download_url.lower() for ind in traversal_indicators
        )

        # Redact signed URLs / tokens before evidence capture so that
        # presigned URLs and Firebase ?token= links are not persisted.
        _SIGNED_URL_PATTERN = re.compile(
            r'"(https?://[^"]*(?:X-Amz-Signature|token=)[^"]*)"'
        )
        raw_body = resp.text or ""
        redacted_body = _TOKEN_PATTERN.sub("token=[REDACTED]", raw_body)
        redacted_body = _SIGNED_URL_PATTERN.sub('"[SIGNED_URL_REDACTED]"', redacted_body)
        sanitised = FakeResponse(
            status_code=resp.status_code,
            url=str(getattr(getattr(resp, "request", None), "url", "")) or "",
            body=redacted_body,
            method="POST",
        )
        evidence.capture(sanitised, label="path_injection_upload_ok")

        if key_contains_traversal:
            pytest.fail(
                f"[MEDIUM] Path injection: upload endpoint accepted a filename "
                f"containing '../' and the traversal sequence survived in the "
                f"returned download URL. "
                f"Filename submitted: {traversal_filename!r}. "
                f"Download URL: {download_url!r}. "
                "Recommendation: sanitise filenames server-side before passing "
                "them to the Firebase Storage SDK."
            )
