"""S3 and R2 storage security tests — external attacker perspective.

Tests cover:
- Bucket enumeration (public listing without auth)
- Presigned URL expiry window
- Presigned URL reuse from a fresh session (design-level documentation)
- IDOR via the presigned URL issuer endpoint
- Path injection in presigned URL key generation
- Access key type disclosure via X-Amz-Credential

No AWS credentials are used.  All probes are from the perspective of an
unauthenticated external attacker or an authenticated-but-wrong-user.

Markers
-------
All tests carry ``@pytest.mark.s3`` so they are skipped when the active
profile does not declare ``stack.storage: s3`` or ``stack.storage: r2``.

Backend selection
-----------------
The module reads ``profile.stack.storage`` at collection time to determine
whether the target uses S3 (``s3``) or Cloudflare R2 (``r2``).  Both share
the same presigned URL mechanics but have different bucket-listing URLs.

Profile config used
-------------------
AWS S3:
    aws.s3_bucket          — bucket name
    aws.s3_region          — AWS region (default: us-east-1)
    aws.presigned_url_endpoint — app endpoint that issues presigned URLs

Cloudflare R2:
    cloudflare.r2_account_id   — Cloudflare account ID
    cloudflare.r2_bucket       — R2 bucket name
    aws.presigned_url_endpoint — same app endpoint (R2 uses S3-compat signing)
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
from urllib.parse import parse_qs, urlparse

import pytest

# ---------------------------------------------------------------------------
# Package-root bootstrap (so ``from helpers import ...`` resolves)
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

# ---------------------------------------------------------------------------
# Runtime config resolution
# ---------------------------------------------------------------------------
#
# Bucket/account/region/endpoint values are resolved from the runtime
# ``profile`` fixture at call time (see helper functions below), NOT from
# collection-time module constants.  Runtime profile assembly can enrich or
# override these values, so any collection-time snapshot would go stale and
# point probes at the wrong target (or wrongly skip as "not configured").
#
# Stack-marker gating (@pytest.mark.s3) is handled centrally in conftest's
# pytest_collection_modifyitems, so this module needs no collection-time
# profile load of its own.

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_r2(profile) -> bool:
    """Return True when the profile declares R2 as the storage backend."""
    storage = (profile.stack and profile.stack.storage) or ""
    return storage == "r2"


def _s3_bucket(profile) -> str:
    """Resolve the S3 bucket name from the runtime profile."""
    return (profile.aws and profile.aws.s3_bucket) or ""


def _s3_region(profile) -> str:
    """Resolve the S3 region from the runtime profile (default us-east-1)."""
    return (profile.aws and profile.aws.s3_region) or "us-east-1"


def _r2_account_id(profile) -> str:
    """Resolve the Cloudflare R2 account ID from the runtime profile."""
    return (profile.cloudflare and profile.cloudflare.r2_account_id) or ""


def _r2_bucket(profile) -> str:
    """Resolve the Cloudflare R2 bucket name from the runtime profile."""
    return (profile.cloudflare and profile.cloudflare.r2_bucket) or ""


def _bucket_list_url(profile) -> str:
    """Build the unauthenticated bucket-listing URL for the active backend.

    Resolves bucket/account/region from the runtime ``profile`` fixture
    rather than collection-time module constants, because runtime profile
    assembly can enrich or override these values.  Using stale globals would
    point probes at the wrong bucket/host.
    """
    if _is_r2(profile):
        return f"https://{_r2_account_id(profile)}.r2.cloudflarestorage.com/{_r2_bucket(profile)}"
    return f"https://{_s3_bucket(profile)}.s3.{_s3_region(profile)}.amazonaws.com"


def _parse_presigned(url: str) -> dict:
    """Extract key fields from an AWS-flavoured presigned URL.

    Returns a dict with:
        key        — object key path (leading slash stripped)
        expires    — X-Amz-Expires value as int (0 if absent)
        credential — full X-Amz-Credential string
        algorithm  — X-Amz-Algorithm string
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {
        "key": parsed.path.lstrip("/"),
        "expires": int(params.get("X-Amz-Expires", [0])[0]),
        "credential": params.get("X-Amz-Credential", [""])[0],
        "algorithm": params.get("X-Amz-Algorithm", [""])[0],
    }


def _has_storage_config(profile) -> bool:
    """Return True when at least one of S3 bucket or R2 bucket is configured.

    Reads from the runtime ``profile`` fixture so enriched/overridden config
    from profile assembly is honoured (collection-time globals may be stale
    and wrongly skip a configured target as "not configured").
    """
    if _is_r2(profile):
        return bool(_r2_account_id(profile) and _r2_bucket(profile))
    return bool(_s3_bucket(profile))


def _has_presigned_endpoint(profile) -> bool:
    """Return True when a presigned URL issuer endpoint is configured."""
    ep = (profile.aws and profile.aws.presigned_url_endpoint) or ""
    return bool(ep)


def _presigned_endpoint(profile) -> str:
    """Resolve the presigned-URL issuer endpoint from the runtime profile.

    Resolved at call time (not from a collection-time constant) so enriched
    or overridden profile values are used as the probe target.
    """
    return ((profile.aws and profile.aws.presigned_url_endpoint) or "").rstrip("/")


# ---------------------------------------------------------------------------
# Import shared helpers after sys.path is set
# ---------------------------------------------------------------------------

from helpers import FakeResponse, is_spa_catchall, send_request  # noqa: E402


def _redact_signed_url(url: str) -> str:
    """Strip signature-bearing query params from a presigned/signed URL.

    Replaces values for ``X-Amz-Signature``, ``X-Amz-Credential``,
    ``token``, ``GoogleAccessId``, and ``Signature`` query params with
    ``[REDACTED]`` so that live bearer-style credentials are never
    persisted in evidence artifacts.
    """
    from urllib.parse import urlencode, urlunparse

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
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

# ---------------------------------------------------------------------------
# Test: bucket enumeration
# ---------------------------------------------------------------------------


@pytest.mark.s3
class TestBucketEnumeration:
    """Test public bucket listing without any credentials.

    A public bucket listing exposes all stored object keys, which is a
    CRITICAL-severity finding.  Both S3 and R2 should return 403 or an
    XML AccessDenied error for unauthenticated listing requests.
    """

    def test_bucket_listing_denied(self, profile, evidence):
        """GET /?list-type=2 with no auth must not return ListBucketResult XML."""
        if not _has_storage_config(profile):
            pytest.skip(
                "No S3 bucket or R2 config in profile — skipping bucket listing test"
            )

        url = _bucket_list_url(profile)
        listing_url = url.rstrip("/") + "/?list-type=2"

        resp = send_request("GET", listing_url)

        body = resp.text or ""
        listing_exposed = (
            resp.status_code == 200
            and "<ListBucketResult" in body
        )

        if listing_exposed:
            evidence.capture(resp, label="bucket_listing_public")
            pytest.fail(
                f"Bucket listing returned HTTP 200 with ListBucketResult XML. "
                f"Storage backend: {'R2' if _is_r2(profile) else 'S3'}. "
                f"URL: {listing_url}. "
                "Public bucket enumeration is a CRITICAL-severity finding — "
                "all stored object keys are visible to unauthenticated attackers."
            )

        # 403 or XML AccessDenied are the expected responses.
        # 404 is also acceptable (bucket does not resolve publicly).
        # 301 is S3 PermanentRedirect for non-authoritative regional endpoints.
        _ACCEPTABLE = {301, 400, 403, 404}
        if resp.status_code not in _ACCEPTABLE:
            evidence.capture(resp, label="bucket_listing_unexpected_status")

        assert not listing_exposed, (
            f"CRITICAL: Bucket is publicly listable — "
            f"GET /?list-type=2 returned {resp.status_code} with XML listing"
        )
        if not listing_exposed:
            assert resp.status_code in _ACCEPTABLE, (
                f"Unexpected status code {resp.status_code} from bucket listing probe "
                f"(expected one of {_ACCEPTABLE})"
            )


# ---------------------------------------------------------------------------
# Test: presigned URL expiry
# ---------------------------------------------------------------------------


@pytest.mark.s3
class TestPresignedUrlReuse:
    """Test presigned URL expiry window and unauthenticated reuse behaviour.

    Presigned URLs are expected to work without auth by design — that is not
    a finding.  This class documents the expiry window and flags excessively
    long-lived URLs as a LOW finding.
    """

    def test_presigned_url_positive_control(self, profile, user_a_client, evidence):
        """Verify the presigned URL endpoint responds and returns a signed URL.

        This is a positive control: if the endpoint does not work (404, 401,
        SPA catch-all), the dependent IDOR and path injection tests are
        automatically skipped via pytest.skip() here.
        """
        if not _has_presigned_endpoint(profile):
            pytest.skip(
                "aws.presigned_url_endpoint not configured — "
                "skipping all presigned URL tests"
            )

        endpoint = _presigned_endpoint(profile)
        # Use user_a's own sentinel upload ID as the resource identifier.
        from helpers import USER_A_UPLOAD_ID  # noqa: PLC0415

        resp = user_a_client.get(
            endpoint,
            params={"upload_id": USER_A_UPLOAD_ID},
        )

        if is_spa_catchall(resp):
            evidence.capture(resp, label="presigned_positive_control_spa_catchall")
            pytest.skip(
                f"Presigned URL endpoint {endpoint} returned an SPA catch-all "
                "(200 + text/html). The endpoint may not exist at this path. "
                "Skipping presigned URL IDOR and path injection probes."
            )

        if resp.status_code in (401, 403):
            evidence.capture(resp, label="presigned_positive_control_auth_fail")
            pytest.skip(
                f"Presigned URL endpoint returned HTTP {resp.status_code}. "
                "Cannot obtain a presigned URL for positive control. "
                "Verify user_a credentials and the endpoint path in the profile."
            )

        if resp.status_code != 200:
            evidence.capture(resp, label="presigned_positive_control_unexpected")
            pytest.skip(
                f"Presigned URL endpoint returned unexpected HTTP {resp.status_code}. "
                "Skipping dependent presigned URL tests."
            )

        # Try to extract a presigned URL from the response body.
        try:
            body = resp.json()
        except Exception:
            body = {}

        presigned_url = (
            body.get("url")
            or body.get("presigned_url")
            or body.get("signed_url")
            or ""
        )

        if not presigned_url:
            evidence.capture(resp, label="presigned_positive_control_no_url")
            pytest.skip(
                "Could not extract a presigned URL from the endpoint response. "
                "Expected a JSON body with 'url', 'presigned_url', or 'signed_url' key. "
                "Skipping dependent presigned URL tests."
            )

        # Validate the URL contains S3-style signing parameters.
        parsed = _parse_presigned(presigned_url)
        if not parsed["algorithm"]:
            safe = FakeResponse(
                status_code=resp.status_code,
                url=str(getattr(getattr(resp, "request", None), "url", endpoint)),
                body=_redact_signed_url(resp.text or ""),
                method="GET",
            )
            evidence.capture(safe, label="presigned_positive_control_not_s3")
            pytest.skip(
                "Returned URL does not contain X-Amz-Algorithm — "
                "may not be an S3/R2 presigned URL. Skipping dependent tests."
            )

        # Validate the key path contains user_a's upload ID as expected.
        assert USER_A_UPLOAD_ID in parsed["key"], (
            f"Presigned URL key '{parsed['key']}' does not reference "
            f"user_a's upload ID ({USER_A_UPLOAD_ID})"
        )

    def test_presigned_url_expiry(self, profile, user_a_client, evidence):
        """Flag presigned URLs with an expiry window exceeding 3600 seconds (1 hour).

        A URL that remains valid for an extended period increases the window
        during which a leaked URL can be replayed.  Expiry > 3600 s is a
        LOW-severity finding.
        """
        if not _has_presigned_endpoint(profile):
            pytest.skip("aws.presigned_url_endpoint not configured")

        from helpers import USER_A_UPLOAD_ID  # noqa: PLC0415

        endpoint = _presigned_endpoint(profile)
        resp = user_a_client.get(
            endpoint,
            params={"upload_id": USER_A_UPLOAD_ID},
        )

        if resp.status_code != 200 or is_spa_catchall(resp):
            pytest.skip(
                f"Presigned URL endpoint returned {resp.status_code} or SPA "
                "catch-all; cannot test expiry."
            )

        try:
            body = resp.json()
        except Exception:
            body = {}

        presigned_url = (
            body.get("url")
            or body.get("presigned_url")
            or body.get("signed_url")
            or ""
        )

        if not presigned_url:
            pytest.skip("No presigned URL in response body")

        parsed = _parse_presigned(presigned_url)
        expires = parsed["expires"]

        # Log expiry as informational evidence regardless of outcome.
        fake = FakeResponse(
            status_code=0,
            url=_redact_signed_url(presigned_url),
            body=f"X-Amz-Expires={expires}s (threshold: 3600s)",
            method="GET",
        )
        evidence.capture(fake, label="presigned_url_expiry_window")

        if expires > 3600:
            pytest.fail(
                f"Presigned URL X-Amz-Expires={expires}s exceeds the recommended "
                "1-hour maximum (3600 s). A leaked URL remains replayable for "
                f"{expires // 3600}h {(expires % 3600) // 60}m. "
                "This is a LOW-severity finding. "
                "Recommendation: reduce the presigned URL lifetime to ≤3600 s."
            )

    def test_presigned_url_reuse_from_fresh_session(
        self, profile, user_a_client, evidence
    ):
        """Document: presigned URLs work from unauthenticated sessions by design.

        Presigned URLs embed credentials and a signature in the URL itself so
        they can be shared with third parties without requiring the recipient
        to authenticate.  Unauthenticated replay within the expiry window is
        expected behaviour, not a vulnerability.

        This test obtains a URL as user_a and replays it from a fresh httpx
        session with no auth headers.  The expiry window is logged as evidence
        for the pentest report.
        """
        if not _has_presigned_endpoint(profile):
            pytest.skip("aws.presigned_url_endpoint not configured")

        from helpers import USER_A_UPLOAD_ID  # noqa: PLC0415

        endpoint = _presigned_endpoint(profile)
        resp = user_a_client.get(
            endpoint,
            params={"upload_id": USER_A_UPLOAD_ID},
        )

        if resp.status_code != 200 or is_spa_catchall(resp):
            pytest.skip(
                f"Presigned URL endpoint returned {resp.status_code} or SPA catch-all"
            )

        try:
            body = resp.json()
        except Exception:
            body = {}

        presigned_url = (
            body.get("url")
            or body.get("presigned_url")
            or body.get("signed_url")
            or ""
        )

        if not presigned_url:
            pytest.skip("No presigned URL in response body")

        parsed = _parse_presigned(presigned_url)
        expires = parsed["expires"]

        # Replay from a completely fresh session (no auth headers).
        replay_resp = send_request("GET", presigned_url)

        # Log replay evidence with presigned URL params redacted.
        safe_replay = FakeResponse(
            status_code=replay_resp.status_code,
            url=_redact_signed_url(str(getattr(getattr(replay_resp, "request", None), "url", presigned_url))),
            body=replay_resp.text or "",
            method="GET",
        )
        evidence.capture(safe_replay, label="presigned_url_unauthenticated_replay")

        design_note = FakeResponse(
            status_code=0,
            url=_redact_signed_url(presigned_url),
            body=(
                f"Design note: presigned URL replay returned HTTP "
                f"{replay_resp.status_code}. "
                f"Expiry window: {expires}s. "
                "Unauthenticated replay within the expiry window is expected "
                "behaviour for presigned URLs — not a vulnerability. "
                "Finding: review expiry window size (see test_presigned_url_expiry)."
            ),
            method="GET",
        )
        evidence.capture(design_note, label="presigned_url_reuse_design_note")

        # This test never fails — it is a documentation + evidence-gathering step.
        # The expiry window length is evaluated separately in test_presigned_url_expiry.


# ---------------------------------------------------------------------------
# Test: presigned URL IDOR
# ---------------------------------------------------------------------------


@pytest.mark.s3
class TestPresignedUrlIDOR:
    """Test IDOR via the presigned URL issuer endpoint.

    The endpoint should validate that the authenticated user owns the resource
    identified by the request parameter.  If user_b can obtain a presigned URL
    for user_a's resource, the key path in the returned URL will reference
    user_a's object — this is a HIGH-severity IDOR finding.
    """

    def test_presigned_url_idor(
        self, profile, user_a_client, user_b_client, evidence
    ):
        """User B must not receive a presigned URL that scopes to User A's resource.

        Steps:
        1. As user_a, obtain a presigned URL for user_a's resource and extract
           the expected key path prefix.
        2. As user_b, request a presigned URL using user_a's resource ID.
        3. If the returned URL's key path references user_a's resource, this
           is a HIGH-severity IDOR.
        """
        if not _has_presigned_endpoint(profile):
            pytest.skip("aws.presigned_url_endpoint not configured")

        from helpers import USER_A_UPLOAD_ID  # noqa: PLC0415

        endpoint = _presigned_endpoint(profile)

        # Step 1: establish user_a's expected key prefix via positive control.
        resp_a = user_a_client.get(
            endpoint,
            params={"upload_id": USER_A_UPLOAD_ID},
        )

        if resp_a.status_code != 200 or is_spa_catchall(resp_a):
            pytest.skip(
                "Positive control for user_a failed — "
                "cannot run IDOR test without a baseline presigned URL"
            )

        try:
            body_a = resp_a.json()
        except Exception:
            body_a = {}

        url_a = (
            body_a.get("url")
            or body_a.get("presigned_url")
            or body_a.get("signed_url")
            or ""
        )

        if not url_a:
            pytest.skip("No presigned URL in user_a positive-control response")

        key_a = _parse_presigned(url_a)["key"]

        # Step 2: as user_b, request a presigned URL for user_a's resource ID.
        resp_b = user_b_client.get(
            endpoint,
            params={"upload_id": USER_A_UPLOAD_ID},
        )
        safe_b = FakeResponse(
            status_code=resp_b.status_code,
            url=_redact_signed_url(str(getattr(getattr(resp_b, "request", None), "url", endpoint))),
            body=resp_b.text or "",
            method="GET",
        )
        evidence.capture(safe_b, label="presigned_idor_user_b_for_user_a_resource")

        # If user_b is denied outright — this is the correct behaviour.
        if resp_b.status_code in (400, 401, 403, 404):
            return  # Access correctly denied.

        if resp_b.status_code != 200 or is_spa_catchall(resp_b):
            # Unexpected status; not a clear denial but also not confirmed IDOR.
            return

        try:
            body_b = resp_b.json()
        except Exception:
            body_b = {}

        url_b = (
            body_b.get("url")
            or body_b.get("presigned_url")
            or body_b.get("signed_url")
            or ""
        )

        if not url_b:
            # 200 but no URL in body; inconclusive.
            return

        key_b = _parse_presigned(url_b)["key"]

        # Step 3: check whether user_b's returned key references user_a's object.
        #
        # We extract the owner prefix from each key (the path segment(s) before
        # the upload_id) and compare them.  A secure implementation re-scopes
        # the key under user_b's own prefix (e.g. "user_b/<upload_id>"), so
        # the upload_id may legitimately appear in key_b — that alone is NOT
        # an IDOR.  The vulnerability exists only when user_b receives a key
        # whose owner prefix matches user_a's prefix (same owner scope) or
        # when the full keys are identical.
        #
        # If the upload_id is not present in the key at all, fall back to
        # exact key comparison (the endpoint may use a different key scheme).

        def _owner_prefix(key: str, marker: str) -> str:
            """Return the key path before the marker (upload_id), or '' if absent."""
            idx = key.find(marker)
            return key[:idx] if idx > 0 else ""

        prefix_a = _owner_prefix(key_a, USER_A_UPLOAD_ID)
        prefix_b = _owner_prefix(key_b, USER_A_UPLOAD_ID)

        if prefix_a and prefix_b:
            # Both keys contain the upload_id — compare owner prefixes.
            same_owner_scope = prefix_a == prefix_b
        else:
            # Upload_id not found in one/both keys; fall back to full key match.
            same_owner_scope = False

        key_paths_match = key_a and key_b and key_a == key_b

        if same_owner_scope or key_paths_match:
            pytest.fail(
                f"IDOR via presigned URL issuer — HIGH severity. "
                f"User B requested a presigned URL for user_a's resource ID "
                f"({USER_A_UPLOAD_ID}) and received a URL whose key path "
                f"shares user_a's owner scope. "
                f"User A key: '{key_a}' (prefix: '{prefix_a}'). "
                f"User B received key: '{key_b}' (prefix: '{prefix_b}'). "
                "The presigned URL endpoint does not enforce resource ownership. "
                "Recommendation: validate that the authenticated user owns the "
                "resource before issuing a presigned URL."
            )


# ---------------------------------------------------------------------------
# Test: path injection
# ---------------------------------------------------------------------------


@pytest.mark.s3
@pytest.mark.write_probe
class TestPathInjection:
    """Test path injection via presigned URL endpoint filename parameter.

    If the endpoint accepts a filename or path parameter and interpolates it
    directly into the S3/R2 object key without sanitisation, an attacker may
    be able to write to or read from arbitrary key paths using ``../`` sequences
    or absolute path prefixes.
    """

    def test_path_injection_presigned(self, profile, user_a_client, evidence):
        """Submit a filename containing ``../`` and inspect the returned key path.

        If the ``../`` sequence is preserved verbatim in the returned presigned
        URL's key, the application may be vulnerable to key-path injection.
        An attacker could potentially read or overwrite objects outside their
        authorised key prefix.

        Severity: MEDIUM (key path injection without auth bypass)
        """
        if not _has_presigned_endpoint(profile):
            pytest.skip("aws.presigned_url_endpoint not configured")

        from helpers import USER_A_UPLOAD_ID  # noqa: PLC0415

        endpoint = _presigned_endpoint(profile)

        # Path traversal payloads to inject via the filename parameter.
        traversal_payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "valid-name/../../../secret",
        ]

        for payload in traversal_payloads:
            resp = user_a_client.get(
                endpoint,
                params={
                    "upload_id": USER_A_UPLOAD_ID,
                    "filename": payload,
                },
            )
            safe_resp = FakeResponse(
                status_code=resp.status_code,
                url=_redact_signed_url(str(getattr(getattr(resp, "request", None), "url", endpoint))),
                body=resp.text or "",
                method="GET",
            )
            evidence.capture(
                safe_resp,
                label=f"path_injection_{payload[:20].replace('/', '_')}",
            )

            if resp.status_code != 200 or is_spa_catchall(resp):
                continue

            try:
                body = resp.json()
            except Exception:
                body = {}

            presigned_url = (
                body.get("url")
                or body.get("presigned_url")
                or body.get("signed_url")
                or ""
            )

            if not presigned_url:
                continue

            key = _parse_presigned(presigned_url)["key"]

            # If explicit traversal sequences appear in the returned key,
            # the application is not sanitising the filename input.
            # Only flag actual path traversal — not benign encoded slashes.
            key_lower = key.lower()
            traversal_preserved = (
                "../" in key
                or "..%2f" in key_lower
                or "%2e%2e/" in key_lower
                or "%2e%2e%2f" in key_lower
                or "etc/passwd" in key
            )

            if traversal_preserved:
                pytest.fail(
                    f"Path injection in presigned URL key — MEDIUM severity. "
                    f"Payload '{payload}' was not sanitised before being "
                    f"interpolated into the S3/R2 object key. "
                    f"Returned key: '{key}'. "
                    "An attacker may be able to target arbitrary key paths. "
                    "Recommendation: sanitise or reject filenames containing "
                    "'../' sequences; use a server-controlled key prefix that "
                    "the client cannot influence."
                )


# ---------------------------------------------------------------------------
# Test: access key type disclosure (informational, read-only)
# ---------------------------------------------------------------------------


@pytest.mark.s3
class TestAccessKeyDisclosure:
    """Informational: classify the AWS Access Key ID from X-Amz-Credential.

    This test only performs a GET and never fails.  It is NOT a write probe
    and must run in default read-only mode so credential-type evidence is
    always collected regardless of PENTEST_MODE.
    """

    def test_access_key_disclosure(self, profile, user_a_client, evidence):
        """Extract and classify the AWS Access Key ID from X-Amz-Credential.

        This test is informational only and never fails.  It logs whether the
        signing credential is a long-term IAM key (AKIA prefix) or a
        short-lived STS session token (ASIA prefix).

        Long-term IAM keys in presigned URLs are higher-risk than STS tokens
        because they do not expire automatically.  This finding should be
        escalated to the client as an informational note if AKIA is observed.
        """
        if not _has_presigned_endpoint(profile):
            pytest.skip("aws.presigned_url_endpoint not configured")

        from helpers import USER_A_UPLOAD_ID  # noqa: PLC0415

        endpoint = _presigned_endpoint(profile)
        resp = user_a_client.get(
            endpoint,
            params={"upload_id": USER_A_UPLOAD_ID},
        )

        if resp.status_code != 200 or is_spa_catchall(resp):
            pytest.skip(
                f"Presigned URL endpoint returned {resp.status_code}; "
                "cannot inspect credential type"
            )

        try:
            body = resp.json()
        except Exception:
            body = {}

        presigned_url = (
            body.get("url")
            or body.get("presigned_url")
            or body.get("signed_url")
            or ""
        )

        if not presigned_url:
            pytest.skip("No presigned URL in response body")

        parsed = _parse_presigned(presigned_url)
        credential = parsed["credential"]

        if not credential:
            pytest.skip("X-Amz-Credential not present in presigned URL")

        # Credential format: <AccessKeyId>/<date>/<region>/<service>/aws4_request
        access_key_id = credential.split("/")[0] if "/" in credential else credential
        key_prefix = access_key_id[:4].upper()

        if key_prefix == "AKIA":
            key_type = "long-term IAM key (AKIA)"
            severity_note = (
                "INFORMATIONAL: Long-term IAM key used for presigned URL signing. "
                "Rotating this key requires code/config changes. "
                "Consider switching to an IAM role with STS for short-lived tokens."
            )
        elif key_prefix == "ASIA":
            key_type = "short-lived STS session token (ASIA)"
            severity_note = (
                "INFORMATIONAL: STS session token used — good practice. "
                "Ensure the session duration is appropriately short."
            )
        else:
            key_type = f"unknown prefix '{key_prefix}'"
            severity_note = "INFORMATIONAL: Unrecognised Access Key ID prefix."

        note = FakeResponse(
            status_code=0,
            url=_redact_signed_url(presigned_url),
            body=(
                f"Access Key ID prefix: {key_prefix} ({key_type}). "
                f"Full Access Key ID (first 8 chars): {access_key_id[:8]}... "
                f"{severity_note}"
            ),
            method="GET",
        )
        evidence.capture(note, label="access_key_id_disclosure")

        # Informational only — this test always passes.
