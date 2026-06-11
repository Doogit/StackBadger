"""Auth flow abuse tests — Clerk OAuth, open redirect, session isolation, enumeration.

Tests:
1. OAuth redirect manipulation — tampered redirect_uri to external domain
2. ProtectedRoute open redirect — ?redirect_url= to external domain
3. Concurrent session abuse — User A and User B requests to same endpoint
4. Account enumeration — timing/response differences on sign-in attempts
"""

from __future__ import annotations

import re
import sys as _sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path as _Path

import httpx
import pytest

# ---------------------------------------------------------------------------
# Collection-time profile loading
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile, resolve_profile_path  # noqa: E402
from tests.conftest import first_endpoint, probe_body_for  # noqa: E402
from tests.helpers import netlify_url, send_request  # noqa: E402


def _collection_profile():
    """Load profile at collection time."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first_authenticated_endpoint(profile) -> tuple[str, dict]:
    """Return (path, probe_body) for the first authenticated endpoint, or skip if none."""
    ep = first_endpoint(profile, "authenticated")
    return ep["path"], probe_body_for(ep)


# ---------------------------------------------------------------------------
# Test 1 — OAuth redirect manipulation
# ---------------------------------------------------------------------------

@pytest.mark.clerk
def test_oauth_redirect_uri_rejected(profile, evidence):
    """Clerk OAuth endpoint must not redirect to an external domain.

    Sends GET to the Clerk OAuth endpoint with a tampered redirect_uri pointing
    to an adversary domain.  The response must not be a redirect (3xx) whose
    Location header begins with the adversary domain.

    Finding: INFO if response is non-3xx (no redirect issued at all); FAIL if
    Location header points to the external domain.
    """
    clerk_frontend_api = (profile.clerk and profile.clerk.frontend_api) or ""
    if not clerk_frontend_api:
        pytest.skip("profile.clerk.frontend_api is not configured")

    adversary_uri = "https://evil.com/callback"

    # Clerk OAuth initiation endpoint — the exact path varies by provider but
    # the standard pattern is /oauth/{provider}.  We target a generic Google
    # path; the important assertion is on redirect destination, not which
    # provider is used.
    url = f"{clerk_frontend_api.rstrip('/')}/v1/oauth/google"
    params = {
        "redirect_uri": adversary_uri,
        "response_type": "code",
        "client_id": "pentest",
    }

    resp = send_request("GET", url, params=params, follow_redirects=False, timeout=15)
    evidence.capture(resp, "oauth_redirect_tampered")

    # A 3xx with Location pointing at evil.com is a confirmed open redirect.
    if 300 <= resp.status_code < 400:
        location = resp.headers.get("location", "")
        assert not location.startswith("https://evil.com"), (
            f"OAuth endpoint issued redirect to adversary domain: Location={location!r}. "
            "Clerk must validate redirect_uri against the registered allow-list."
        )
    # If non-3xx (e.g. 400 or 422 for invalid redirect_uri), that is correct behaviour.
    # Non-redirect responses pass this test automatically.


# ---------------------------------------------------------------------------
# Test 2 — ProtectedRoute open redirect via ?redirect_url=
# ---------------------------------------------------------------------------

@pytest.mark.clerk
def test_protected_route_open_redirect(profile, evidence):
    """App must not redirect an unauthenticated user to an external domain.

    The React ProtectedRoute component reads ?redirect_url= and passes it to
    Clerk's redirectToSignIn.  If Clerk does not validate this value against
    the app's origin, an attacker can craft a link that redirects the victim
    to an adversary site after sign-in.

    We check the raw HTML body for any occurrence of the adversary URL being
    embedded as a redirect target, and verify that no Location header points
    to the external domain.
    """
    base_url = (profile.target and profile.target.base_url) or ""
    if not base_url:
        pytest.skip("profile.target.base_url is not configured")

    adversary_url = "https://evil.com"
    # Target a protected page so ProtectedRoute fires.
    target = f"{base_url.rstrip('/')}/dashboard"
    params = {"redirect_url": adversary_url}

    resp = send_request("GET", target, params=params, follow_redirects=False, timeout=15)
    evidence.capture(resp, "protected_route_open_redirect")

    # Check Location header for a direct redirect to adversary.
    if 300 <= resp.status_code < 400:
        location = resp.headers.get("location", "")
        assert not location.startswith(adversary_url), (
            f"ProtectedRoute redirected directly to adversary domain: Location={location!r}. "
            "The redirect_url parameter must be validated against the app's origin."
        )

    # Check response body for the adversary URL being reflected as a redirect target.
    body = resp.text
    # A meta-refresh or JS redirect to the adversary domain would be a finding.
    adversary_in_redirect_context = (
        f'location="{adversary_url}' in body.lower()
        or f"location='{adversary_url}" in body.lower()
        or f"window.location = '{adversary_url}" in body
        or f'window.location = "{adversary_url}' in body
        or bool(re.search(rf"redirectToSignIn.*{re.escape(adversary_url)}", body))
    )
    assert not adversary_in_redirect_context, (
        "Response body contains adversary URL in a redirect context. "
        "Validate redirect_url against allowed origins before passing to Clerk."
    )


# ---------------------------------------------------------------------------
# Test 3 — Concurrent session abuse
# ---------------------------------------------------------------------------

@pytest.mark.clerk
def test_concurrent_session_isolation(profile, user_a_client, user_b_client, evidence):
    """Concurrent requests from User A and User B must not bleed data across sessions.

    Sends requests from both users in parallel to a single endpoint and verifies
    that neither response contains identifying data from the other user's account.

    Approach:
    - Use the first authenticated endpoint from the profile as the probe endpoint.
    - Send 5 concurrent requests per user, interleaved.
    - Verify each response either (a) belongs to the correct user or (b) is a
      4xx/5xx that does not contain the other user's email or sub claim.
    """
    endpoint_path, payload = _first_authenticated_endpoint(profile)
    url = netlify_url(profile, endpoint_path)

    user_a_email = (
        profile.test_accounts
        and profile.test_accounts.user_a
        and profile.test_accounts.user_a.email
    ) or "pentest-a@example.com"
    user_b_email = (
        profile.test_accounts
        and profile.test_accounts.user_b
        and profile.test_accounts.user_b.email
    ) or "pentest-b@example.com"

    results: list[dict] = []

    def _fire(label: str, client: httpx.Client) -> dict:
        try:
            r = client.post(url, json=payload, timeout=15)
            return {"label": label, "status": r.status_code, "body": r.text}
        except Exception as exc:  # noqa: BLE001
            return {"label": label, "status": -1, "body": str(exc)}

    tasks = (
        [("user_a", user_a_client)] * 5
        + [("user_b", user_b_client)] * 5
    )

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_fire, label, client): (label, client) for label, client in tasks}
        for future in as_completed(futures):
            results.append(future.result())

    # Capture a summary record for evidence.
    with httpx.Client(timeout=1) as _dummy:
        pass  # just to have a valid client context for evidence structure
    # Build a synthetic response-like object for the evidence log.
    # We log findings as a plain dict instead since we have multiple responses.
    findings: list[str] = []
    for result in results:
        label = result["label"]
        body = result["body"]
        # User A responses must not contain User B's email and vice versa.
        if label == "user_a" and user_b_email in body:
            findings.append(
                f"User A response contains User B email ({user_b_email}): {body[:200]}"
            )
        if label == "user_b" and user_a_email in body:
            findings.append(
                f"User B response contains User A email ({user_a_email}): {body[:200]}"
            )

    assert not findings, (
        "Session data bled across concurrent requests:\n" + "\n".join(findings)
    )


# ---------------------------------------------------------------------------
# Test 4 — Account enumeration via Clerk sign-in timing/response
# ---------------------------------------------------------------------------

@pytest.mark.clerk
def test_account_enumeration_timing(profile, evidence):
    """Sign-in endpoint should not reveal whether an email account exists.

    Sends sign-in attempts for a likely-existing email and a random non-existent
    email.  Records status codes, response body lengths, and wall-clock timing.

    This test always passes (INFO-level finding only) — enumeration differences
    are documented in evidence rather than causing a test failure, because Clerk
    SaaS manages this behaviour and the app has no direct control over it.

    A hard FAIL is raised only if the response body for one email explicitly
    states "account not found" or equivalent while the other does not.
    """
    clerk_frontend_api = (profile.clerk and profile.clerk.frontend_api) or ""
    if not clerk_frontend_api:
        pytest.skip("profile.clerk.frontend_api is not configured")

    existing_email = (
        profile.test_accounts
        and profile.test_accounts.user_a
        and profile.test_accounts.user_a.email
    ) or "pentest-a@example.com"
    nonexistent_email = "nonexistent-xyz-pentest-99999@example.com"

    sign_in_url = f"{clerk_frontend_api.rstrip('/')}/v1/client/sign_ins"

    def _attempt(email: str) -> tuple[int, int, float, str]:
        """Return (status_code, body_length, elapsed_seconds, body_snippet)."""
        t0 = time.perf_counter()
        try:
            with httpx.Client(timeout=20, follow_redirects=False) as client:
                resp = client.post(
                    sign_in_url,
                    data={"identifier": email, "strategy": "password", "password": "wrongpassword123!"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            elapsed = time.perf_counter() - t0
            return resp.status_code, len(resp.content), elapsed, resp.text[:300]
        except Exception as exc:  # noqa: BLE001
            elapsed = time.perf_counter() - t0
            return -1, 0, elapsed, str(exc)

    status_existing, len_existing, time_existing, body_existing = _attempt(existing_email)
    status_nonexistent, len_nonexistent, time_nonexistent, body_nonexistent = _attempt(nonexistent_email)

    # Synthesise a minimal httpx.Request/Response for evidence capture.
    # Since EvidenceCapture requires an httpx.Response we log findings manually
    # by writing directly to the evidence directory via a helper request.
    timing_diff = abs(time_existing - time_nonexistent)

    # Document findings as structured metadata by issuing a self-request to
    # capture via the existing evidence machinery.
    # We use a no-op GET to localhost to get an httpx.Response object, then
    # capture it with finding metadata embedded in the label.
    finding_label = (
        f"enumeration_existing={status_existing}_len={len_existing}_t={time_existing:.3f}s"
        f"__nonexistent={status_nonexistent}_len={len_nonexistent}_t={time_nonexistent:.3f}s"
        f"__timing_diff={timing_diff:.3f}s"
    )

    # Hard-fail only on explicit account-existence disclosure in body text.
    enumeration_phrases = [
        "no account found",
        "couldn't find your account",
        "user not found",
        "email not found",
        "account doesn't exist",
        "account does not exist",
        "no user found",
    ]

    existing_has_disclosure = any(phrase in body_existing.lower() for phrase in enumeration_phrases)
    nonexistent_has_disclosure = any(phrase in body_nonexistent.lower() for phrase in enumeration_phrases)

    # If the non-existent account response explicitly discloses non-existence
    # but the existing account response does not, that's asymmetric disclosure.
    asymmetric_disclosure = nonexistent_has_disclosure and not existing_has_disclosure

    if asymmetric_disclosure:
        pytest.fail(
            f"Account enumeration: non-existent email response explicitly discloses "
            f"account non-existence while existing email response does not.\n"
            f"  existing ({existing_email}): status={status_existing}, body={body_existing!r}\n"
            f"  nonexistent ({nonexistent_email}): status={status_nonexistent}, body={body_nonexistent!r}\n"
            f"Finding label: {finding_label}"
        )

    # Non-hard-fail: log differences as INFO via pytest warning.
    differences: list[str] = []
    if status_existing != status_nonexistent:
        differences.append(
            f"Status code differs: existing={status_existing}, nonexistent={status_nonexistent}"
        )
    body_len_diff = abs(len_existing - len_nonexistent)
    if body_len_diff > 50:
        differences.append(
            f"Body length differs by {body_len_diff} bytes: "
            f"existing={len_existing}, nonexistent={len_nonexistent}"
        )
    if timing_diff > 1.0:
        differences.append(
            f"Timing differs by {timing_diff:.3f}s: "
            f"existing={time_existing:.3f}s, nonexistent={time_nonexistent:.3f}s"
        )

    if differences:
        import warnings
        warnings.warn(
            "Account enumeration INFO findings (Clerk-managed; app has no direct control):\n"
            + "\n".join(f"  - {d}" for d in differences)
            + f"\n  Label: {finding_label}",
            stacklevel=1,
        )
