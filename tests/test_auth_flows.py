"""Auth flow abuse tests — Clerk OAuth, open redirect, session isolation, enumeration.

Tests:
1. OAuth redirect manipulation — tampered redirect_uri to external domain
2. ProtectedRoute open redirect — ?redirect_url= to external domain
3. Concurrent session abuse — User A and User B requests to same endpoint
4. Account enumeration — timing/response differences on sign-in attempts
5. Registration-time weak-password rejection (ASVS 6.2.2, CWE-521): provider-
   dispatched signup with a weak password must be rejected, not accepted.
6. Enumeration-safe sign-in responses (ASVS 6.3.8, CWE-204): provider-dispatched
   sign-in must not reveal whether an account exists.

The §P2-D authentication-delta probes (5 and 6) dispatch on ``stack.auth`` so they
work across all four supported auth providers (clerk, supabase-auth, firebase,
nextauth), skip-with-reason where a control is not observable for the active
provider, and factor their decision logic into pure classifiers that are unit-
tested offline (so they execute even on placeholder-host example profiles).
"""

from __future__ import annotations

import re
import sys as _sys
import time
import uuid as _uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path as _Path
from urllib.parse import urlencode

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
from tests.helpers import FakeResponse, auth_provider, netlify_url, safe_text, send_request  # noqa: E402


def _collection_profile():
    """Load profile at collection time."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()


# ---------------------------------------------------------------------------
# Shared enumeration phrase list (single source of truth)
# ---------------------------------------------------------------------------

# Phrases that, when present in a sign-in response body, explicitly disclose
# that an account does NOT exist. Both the timing probe (test 4) and the
# generalized response-shape probe (test 6) read this one list so they stay in
# sync. Kept identical to the timing probe's original local list so refactoring
# it to module scope does not change that test's behavior. A uniform message
# like "invalid login credentials" (GoTrue) is deliberately NOT here: it is the
# SAFE answer because it is returned for both existing and non-existent emails.
_ENUMERATION_PHRASES: tuple[str, ...] = (
    "no account found",
    "couldn't find your account",
    "user not found",
    "email not found",
    "account doesn't exist",
    "account does not exist",
    "no user found",
    # Provider structured error codes that name non-existence. Firebase Identity
    # Toolkit returns EMAIL_NOT_FOUND (and the legacy USER_NOT_FOUND) for an unknown
    # account while returning INVALID_PASSWORD / INVALID_LOGIN_CREDENTIALS for a
    # wrong password, so the underscore forms are matched too (lower-cased). A
    # config that returns INVALID_LOGIN_CREDENTIALS for both is the SAFE answer and
    # carries none of these phrases.
    "email_not_found",
    "user_not_found",
)

# Deliberately weak passwords that any sane registration policy must reject
# (ASVS 6.2.2 / CWE-521). Short, common, all-numeric, or single-character-class.
_WEAK_PASSWORDS: tuple[str, ...] = (
    "password",
    "12345678",
)


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

    sign_in_url = _clerk_signin_url(clerk_frontend_api)

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
    # The phrase list is the shared module-level _ENUMERATION_PHRASES (single
    # source of truth, reused by the generalized response-shape probe below).
    enumeration_phrases = _ENUMERATION_PHRASES

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


# ===========================================================================
# §P2-D Authentication-delta probes (provider-dispatched, stack-agnostic)
# ===========================================================================
#
# Two black-box-observable edges of provider-managed authentication:
#   - Test 5: registration-time weak-password rejection (ASVS 6.2.2, CWE-521).
#   - Test 6: enumeration-safe sign-in responses (ASVS 6.3.8, CWE-204).
#
# Both dispatch on ``auth_provider(profile)`` (== ``profile.stack.auth``) so they
# generalize across clerk, supabase-auth, firebase, and nextauth, and skip with a
# precise reason wherever the active provider does not expose the control. Their
# decision logic lives in PURE classifiers (``_weak_password_outcome`` /
# ``_enumeration_outcome``) that are unit-tested offline at the bottom of this
# file, so the requirement gets real executed coverage even on placeholder-host
# example profiles (where the live legs auto-skip via the ``profile`` fixture).


# ---------------------------------------------------------------------------
# Pure helpers (no profile, no network), unit-tested offline below
# ---------------------------------------------------------------------------

def _throwaway_email(tag: str) -> str:
    """Return a random, reserved-domain throwaway email for a registration probe.

    Uses ``uuid4`` entropy for the local part so the probe never collides with a
    real account, and a reserved ``example.com`` domain so a delivered-mail side
    effect is impossible. ``tag`` namespaces the local part per probe.
    """
    return f"pentest-{tag}-{_uuid.uuid4().hex}@example.com"


# Body signals that a 4xx rejection was specifically a PASSWORD-POLICY refusal
# (rather than e.g. an invalid-email or rate-limit 4xx). Lower-cased substring
# match. Kept broad enough to catch Clerk ("passwords must be"), GoTrue/Supabase
# ("password should be at least"), and Firebase ("WEAK_PASSWORD") phrasings.
_WEAK_PASSWORD_SIGNALS: tuple[str, ...] = (
    "password",
    "weak_password",
    "pwned",
    "too short",
    "at least",
    "minimum",
    "strength",
    "data breach",
    "compromised",
)


def _weak_password_outcome(status: int, body: str) -> str:
    """Classify a registration attempt with a weak password (pure).

    Returns one of:
      - ``"accepted"``: the signup succeeded (2xx). This is the FINDING: a weak
        password was accepted at registration.
      - ``"rejected"``: a 4xx that carries a password-policy signal in the body, so
        the control is present (pass).
      - ``"inconclusive"``: anything else (a 4xx with no policy signal, a 429
        rate-limit, a 5xx, a transport sentinel). The result proves neither
        acceptance nor a policy rejection, so the caller skips rather than passing
        or failing.
    """
    if status // 100 == 2:
        return "accepted"
    body_l = (body or "").lower()
    if 400 <= status < 500 and any(sig in body_l for sig in _WEAK_PASSWORD_SIGNALS):
        return "rejected"
    return "inconclusive"


# Throttle/server-error codes: a status difference that involves one of these was
# not a like-for-like comparison, so it proves nothing (inconclusive) rather than
# being a deterministic existence oracle.
_ENUM_TRANSIENT_CODES = frozenset({429, 500, 502, 503, 504})


def _enumeration_outcome(
    existing_status: int,
    existing_body: str,
    nonexistent_status: int,
    nonexistent_body: str,
) -> str:
    """Classify a pair of wrong-password sign-in attempts (pure).

    Compares the response for a likely-EXISTING email against the response for a
    clearly NON-EXISTENT one. Reuses :data:`_ENUMERATION_PHRASES` for the
    account-existence disclosure check.

    Returns one of:
      - ``"disclosure"``: the responses let an attacker distinguish a real account
        (the FINDING, CWE-204). This covers two cases. First, asymmetric explicit
        disclosure: exactly one leg names account non-existence via a phrase from
        ``_ENUMERATION_PHRASES``. Second, a deterministic status-code split between
        two non-transient codes (e.g. 404 for an unknown email vs 401 for a wrong
        password), which is itself an existence oracle even when both bodies are
        generic.
      - ``"safe"``: the two responses are indistinguishable. Either both legs share
        a status and a disclosure state (e.g. GoTrue returns "invalid login
        credentials" with the same status for both), so nothing differential leaks.
      - ``"inconclusive"``: no like-for-like comparison was possible. This happens
        on a transport sentinel (a negative status) on either leg, or when a
        status-code difference involves a throttle or server-error code from
        ``_ENUM_TRANSIENT_CODES`` (429/5xx), which is noise rather than an oracle.
    """
    if existing_status < 0 or nonexistent_status < 0:
        return "inconclusive"
    existing_discloses = any(p in (existing_body or "").lower() for p in _ENUMERATION_PHRASES)
    nonexistent_discloses = any(p in (nonexistent_body or "").lower() for p in _ENUMERATION_PHRASES)
    # Asymmetric explicit disclosure: one leg names non-existence, the other does not.
    if existing_discloses != nonexistent_discloses:
        return "disclosure"
    if existing_status != nonexistent_status:
        # A status difference involving a throttle or 5xx was not a like-for-like
        # comparison, so it is inconclusive rather than an oracle.
        if existing_status in _ENUM_TRANSIENT_CODES or nonexistent_status in _ENUM_TRANSIENT_CODES:
            return "inconclusive"
        # A deterministic status-code split (e.g. 404 for unknown vs 401 for a wrong
        # password) is itself an enumeration oracle even when both bodies are generic.
        return "disclosure"
    # Same status and same disclosure state: uniform responses, nothing differential leaks.
    return "safe"


# ---------------------------------------------------------------------------
# Provider endpoint builders (pure), unit-tested offline below
# ---------------------------------------------------------------------------

def _supabase_signup_url(project_url: str) -> str:
    """Build the GoTrue signup URL from a Supabase project URL (pure)."""
    return f"{project_url.rstrip('/')}/auth/v1/signup"


def _supabase_signin_url(project_url: str) -> str:
    """Build the GoTrue password-grant sign-in URL (pure)."""
    return f"{project_url.rstrip('/')}/auth/v1/token?grant_type=password"


def _firebase_signup_url(api_key: str) -> str:
    """Build the Identity Toolkit signUp URL from a Firebase API key (pure)."""
    return (
        "https://identitytoolkit.googleapis.com/v1/accounts:signUp"
        f"?key={api_key}"
    )


def _firebase_signin_url(api_key: str) -> str:
    """Build the Identity Toolkit signInWithPassword URL (pure)."""
    return (
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
        f"?key={api_key}"
    )


def _clerk_signup_url(frontend_api: str) -> str:
    """Build the Clerk FAPI sign-up URL from the frontend API host (pure)."""
    return f"{frontend_api.rstrip('/')}/v1/client/sign_ups"


def _clerk_signin_url(frontend_api: str) -> str:
    """Build the Clerk FAPI sign-in URL from the frontend API host (pure)."""
    return f"{frontend_api.rstrip('/')}/v1/client/sign_ins"


def _send_signin(url: str, **send_kwargs) -> tuple[int, str]:
    """Send one sign-in attempt; return (status, body) with a transport sentinel.

    A transport failure yields ``(-1, "<error>")`` so :func:`_enumeration_outcome`
    classifies it as inconclusive rather than the caller erroring.
    """
    try:
        resp = send_request("POST", url, timeout=20, **send_kwargs)
    except httpx.HTTPError as exc:  # noqa: BLE001
        return -1, f"<transport error: {type(exc).__name__}>"
    return resp.status_code, safe_text(resp)


# Standard Auth.js endpoint paths (mirrors the auth/nextauth.py adapter
# defaults); a profile may override them in its ``nextauth`` block.
_NEXTAUTH_DEFAULT_CSRF_PATH = "/api/auth/csrf"
_NEXTAUTH_DEFAULT_SIGNIN_PATH = "/api/auth/signin"
_NEXTAUTH_DEFAULT_CALLBACK_PATH = "/api/auth/callback/credentials"


def _nextauth_signin_attempt(
    base_url: str,
    csrf_path: str,
    signin_path: str,
    callback_path: str,
    email: str,
    password: str,
) -> tuple[int, str]:
    """Run the Auth.js credentials sign-in flow and return (status, body).

    Auth.js gates the credentials callback behind a CSRF token, so a bare POST of
    email/password never reaches the provider's authorize() callback and would
    compare two identical CSRF failures (a misleading "safe"). This mirrors the
    repo's NextAuth adapter (auth/nextauth.py):
      1. GET the csrf endpoint for a token (the same client stores the csrf cookie).
      2. GET the sign-in page and discover the real credential field names via the
         adapter's own parser, so an app whose form uses username/pass or any other
         custom field shape is still exercised rather than always posting
         email/password. Falls back to email/password when discovery fails.
      3. POST the callback with csrfToken, callbackUrl, the discovered field names,
         and json=true so the response is a JSON body rather than a redirect.

    A transport failure or a missing csrf token yields a transport sentinel so
    _enumeration_outcome treats the attempt as inconclusive rather than erroring.
    """
    # Reuse the adapter's HTML form-field parser (single source of truth for the
    # credential field-name discovery the real sign-in flow performs).
    from auth.nextauth import _discover_field_names

    base = base_url.rstrip("/")
    try:
        with httpx.Client(
            timeout=15.0, max_redirects=5, follow_redirects=True
        ) as client:
            csrf = client.get(f"{base}{csrf_path}", timeout=10.0)
            token = ""
            if csrf.status_code == 200:
                try:
                    token = (csrf.json() or {}).get("csrfToken", "")
                except Exception:  # noqa: BLE001
                    token = ""
            if not token:
                return -1, "<no csrf token; the credentials callback is unreachable>"

            # Discover the credential form field names (fallback: email/password).
            fields = {"email_field": "email", "password_field": "password"}
            try:
                page = client.get(
                    f"{base}{signin_path}",
                    headers={"Accept": "text/html"},
                    timeout=10.0,
                )
                if page.status_code == 200:
                    fields = _discover_field_names(safe_text(page), callback_path)
            except httpx.HTTPError:
                pass  # keep the email/password fallback

            resp = client.post(
                f"{base}{callback_path}",
                data={
                    "csrfToken": token,
                    "callbackUrl": base,
                    fields["email_field"]: email,
                    fields["password_field"]: password,
                    "json": "true",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15.0,
            )
            return resp.status_code, safe_text(resp)
    except httpx.HTTPError as exc:  # noqa: BLE001
        return -1, f"<transport error: {type(exc).__name__}>"


# ---------------------------------------------------------------------------
# Test 5: Registration-time weak-password rejection (ASVS 6.2.2, CWE-521)
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
@pytest.mark.asvs_extended
@pytest.mark.asvs("6.2.2")
@pytest.mark.cwe("521")
def test_registration_rejects_weak_password(profile, evidence):
    """Provider registration must reject a deliberately weak password.

    Dispatches on ``stack.auth`` to the active provider's signup endpoint and POSTs
    a throwaway email plus a weak password from ``_WEAK_PASSWORDS``. A 4xx with a
    password-policy signal is correct (the control exists). A 2xx accept is the
    finding (ASVS 6.2.2 / CWE-521: a weak password was accepted at registration).

    It tries each password in ``_WEAK_PASSWORDS`` only until it gets a definitive
    answer. The first password almost always yields one, so a single signup request
    is sent in the common case. A later password is a fallback that fires only when
    an earlier attempt was inconclusive (an unrelated 4xx, rate limit, or transient
    error), which keeps throwaway-account creation minimal. Each attempt uses a
    fresh throwaway email.

    Safety: this MUTATES (it attempts to create an account), so it carries
    ``write_probe`` + ``asvs_extended`` and runs only under ``--full``/``--branch``
    + ``SCAN_SCOPE=asvs``. The email is a random ``uuid4`` local part on the
    reserved ``example.com`` domain, so it cannot collide with a real account and no
    mail can be delivered. On a real target a 2xx accept does leave a throwaway
    account behind (noted in the failure message), so run it against a branch or
    staging target. NextAuth is skipped: it is a session layer with no provider
    signup endpoint to probe.
    """
    provider = auth_provider(profile)

    if provider == "supabase-auth":
        project_url = (profile.supabase and profile.supabase.project_url) or ""
        anon_key = (profile.supabase and profile.supabase.anon_key) or ""
        if not project_url:
            pytest.skip(
                "supabase-auth: profile.supabase.project_url is not configured, "
                "so the GoTrue /auth/v1/signup endpoint cannot be derived"
            )
        if not anon_key:
            pytest.skip(
                "supabase-auth: profile.supabase.anon_key is not configured; "
                "GoTrue rejects /auth/v1/signup without the apikey header"
            )
        url = _supabase_signup_url(project_url)
        headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
            "Content-Type": "application/json",
        }

        def _build_send_kwargs(email: str, password: str) -> dict:
            return {
                "headers": headers,
                "json_body": {"email": email, "password": password},
            }

    elif provider == "firebase":
        api_key = (profile.firebase and profile.firebase.api_key) or ""
        if not api_key:
            pytest.skip(
                "firebase: profile.firebase.api_key is not configured, so the "
                "Identity Toolkit accounts:signUp endpoint cannot be derived"
            )
        url = _firebase_signup_url(api_key)

        def _build_send_kwargs(email: str, password: str) -> dict:
            return {
                "json_body": {
                    "email": email,
                    "password": password,
                    "returnSecureToken": True,
                }
            }

    elif provider == "clerk":
        frontend_api = (profile.clerk and profile.clerk.frontend_api) or ""
        if not frontend_api:
            pytest.skip(
                "clerk: profile.clerk.frontend_api is not configured, so the "
                "Clerk FAPI /v1/client/sign_ups endpoint cannot be derived"
            )
        url = _clerk_signup_url(frontend_api)

        def _build_send_kwargs(email: str, password: str) -> dict:
            # Clerk FAPI consumes form-encoded fields, not JSON.
            return {
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "content": urlencode(
                    {"email_address": email, "password": password}
                ).encode(),
            }

    elif provider == "nextauth":
        pytest.skip(
            "nextauth: NextAuth/Auth.js is a session layer and does not manage "
            "registration. There is no provider signup endpoint to probe; "
            "registration is app-specific, so weak-password policy at sign-up "
            "(ASVS 6.2.2) is not observable for this stack."
        )

    else:
        pytest.skip(
            f"Unsupported or unset stack.auth '{provider or '(empty)'}' for the "
            "registration weak-password probe (expected one of: clerk, "
            "supabase-auth, firebase, nextauth)"
        )

    # Try each weak password until one gives a definitive answer. A "rejected"
    # passes immediately; an "accepted" is the finding. Keep going while a result
    # is inconclusive; if every password is inconclusive, skip with that reason.
    last_inconclusive = ""
    for weak_password in _WEAK_PASSWORDS:
        email = _throwaway_email("pwpol")
        try:
            resp = send_request(
                "POST", url, timeout=20, **_build_send_kwargs(email, weak_password)
            )
        except httpx.HTTPError as exc:
            last_inconclusive = (
                f"{provider}: signup request to derive a weak-password result could "
                f"not be sent ({type(exc).__name__}: {exc}); result inconclusive"
            )
            continue

        outcome = _weak_password_outcome(resp.status_code, safe_text(resp))

        if outcome == "rejected":
            return  # provider enforces a password policy at registration (pass)

        if outcome == "inconclusive":
            last_inconclusive = (
                f"{provider}: weak-password signup returned {resp.status_code} with "
                "no password-policy signal in the body (neither a clean 2xx accept "
                "nor a policy 4xx). Likely an unrelated 4xx (invalid email or "
                "duplicate), a rate limit, or a transient error, so the result is "
                "inconclusive."
            )
            continue

        # outcome == "accepted": the weak password was accepted at registration.
        # Persist HEADERS/STATUS only via a sanitized FakeResponse. A signup 2xx
        # body can carry a session/access token and the throwaway email (PII),
        # neither of which may touch evidence.
        evidence.capture(
            FakeResponse(
                resp.status_code,
                url,
                f"[body omitted] {provider} signup accepted a weak password "
                f"(status {resp.status_code}); a throwaway account was created on "
                "the target.",
                "POST",
            ),
            label=f"{provider}_weak_password_accepted",
        )
        pytest.fail(
            f"MEDIUM: {provider} accepted a weak password ({weak_password!r}) at "
            f"registration (status {resp.status_code}). The provider does not "
            "enforce a minimum password strength at sign-up (ASVS 6.2.2, CWE-521), "
            "so users can register trivially guessable credentials. Enforce a "
            "password policy (length and breach/dictionary checks) at the "
            "registration endpoint. Note: this created a throwaway account on the "
            "target, so delete it."
        )

    # Every weak password was inconclusive: no definitive accept or reject.
    pytest.skip(last_inconclusive)


# ---------------------------------------------------------------------------
# Test 6: Enumeration-safe sign-in responses (ASVS 6.3.8, CWE-204)
# ---------------------------------------------------------------------------

@pytest.mark.asvs_extended
@pytest.mark.asvs("6.3.8")
@pytest.mark.cwe("204")
def test_signin_response_is_enumeration_safe(profile, evidence):
    """Sign-in responses must not reveal whether an email account exists.

    Dispatches on ``stack.auth`` to the active provider's sign-in endpoint and
    sends exactly two wrong-password attempts: one for a likely-EXISTING email
    (``profile.test_accounts.user_a.email``) and one for a clearly NON-EXISTENT
    email. It compares status code and body shape via the pure
    :func:`_enumeration_outcome` classifier and FAILS only on a clear
    account-existence disclosure asymmetry (CWE-204).

    READ-ONLY: both attempts are failed sign-ins, not mutations, so this carries no
    ``write_probe`` marker. It is capped at two attempts (one per email) to avoid
    tripping account lockout. This overlaps slightly with the Clerk-only timing
    probe (test 4) but is response-shape-focused and provider-dispatched.
    """
    provider = auth_provider(profile)
    existing_email = (
        profile.test_accounts
        and profile.test_accounts.user_a
        and profile.test_accounts.user_a.email
    ) or ""
    if not existing_email:
        pytest.skip(
            "A known-existing account is required to establish the enumeration "
            "baseline, but profile.test_accounts.user_a.email is not set. Without a "
            "real existing email, both legs would probe non-existent accounts and "
            "the classifier would report a false pass. Configure "
            "profile.test_accounts.user_a.email to enable this probe."
        )
    # Derive the non-existent email from the SAME domain as the existing account so
    # the two legs differ ONLY in the local part (account existence). A hardcoded
    # @example.com here would introduce a domain confound: a provider that validates
    # or rejects a reserved domain differently from the real one could return a
    # different status for that reason alone, which the status-split branch of
    # _enumeration_outcome would misread as an existence oracle (false positive).
    _existing_domain = existing_email.split("@", 1)[1] if "@" in existing_email else "example.com"
    nonexistent_email = f"nonexistent-{_uuid.uuid4().hex}@{_existing_domain}"
    wrong_password = "wrong-password-pentest-enum-99999!"

    if provider == "clerk":
        frontend_api = (profile.clerk and profile.clerk.frontend_api) or ""
        if not frontend_api:
            pytest.skip(
                "clerk: profile.clerk.frontend_api is not configured, so the "
                "Clerk FAPI /v1/client/sign_ins endpoint cannot be derived"
            )
        url = _clerk_signin_url(frontend_api)

        def _attempt(email: str) -> tuple[int, str]:
            return _send_signin(
                url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                content=urlencode(
                    {
                        "identifier": email,
                        "strategy": "password",
                        "password": wrong_password,
                    }
                ).encode(),
            )

    elif provider == "supabase-auth":
        project_url = (profile.supabase and profile.supabase.project_url) or ""
        anon_key = (profile.supabase and profile.supabase.anon_key) or ""
        if not project_url:
            pytest.skip(
                "supabase-auth: profile.supabase.project_url is not configured, "
                "so the GoTrue token endpoint cannot be derived"
            )
        if not anon_key:
            pytest.skip(
                "supabase-auth: profile.supabase.anon_key is not configured; "
                "GoTrue rejects the token endpoint without the apikey header"
            )
        url = _supabase_signin_url(project_url)
        headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
            "Content-Type": "application/json",
        }

        def _attempt(email: str) -> tuple[int, str]:
            return _send_signin(
                url,
                headers=headers,
                json_body={"email": email, "password": wrong_password},
            )

    elif provider == "firebase":
        api_key = (profile.firebase and profile.firebase.api_key) or ""
        if not api_key:
            pytest.skip(
                "firebase: profile.firebase.api_key is not configured, so the "
                "Identity Toolkit accounts:signInWithPassword endpoint cannot be "
                "derived"
            )
        url = _firebase_signin_url(api_key)

        def _attempt(email: str) -> tuple[int, str]:
            return _send_signin(
                url,
                json_body={
                    "email": email,
                    "password": wrong_password,
                    "returnSecureToken": True,
                },
            )

    elif provider == "nextauth":
        # Auth.js signs in through a CSRF-protected credentials callback, not a
        # bare POST. Run the csrf then callback flow (mirrors auth/nextauth.py) so
        # each attempt actually reaches the provider's authorize() callback; a
        # bare email/password POST would be rejected for a missing CSRF token, so
        # both legs would fail identically and report a false "safe".
        base_url = (profile.target and profile.target.base_url) or ""
        if not base_url:
            pytest.skip(
                "nextauth: profile.target.base_url is required to derive the "
                "Auth.js credentials sign-in flow"
            )
        nextauth_cfg = profile.nextauth or None
        csrf_path = (
            (nextauth_cfg and getattr(nextauth_cfg, "csrf_path", None))
            or _NEXTAUTH_DEFAULT_CSRF_PATH
        )
        signin_path = (
            (nextauth_cfg and getattr(nextauth_cfg, "signin_path", None))
            or _NEXTAUTH_DEFAULT_SIGNIN_PATH
        )
        callback_path = (
            (nextauth_cfg and getattr(nextauth_cfg, "callback_path", None))
            or _NEXTAUTH_DEFAULT_CALLBACK_PATH
        )
        # The callback is the endpoint the two attempts compare, so expose it as
        # `url` for the shared evidence/failure path below (every other provider
        # branch sets `url`; without this the disclosure path raises NameError).
        url = f"{base_url.rstrip('/')}{callback_path}"

        def _attempt(email: str) -> tuple[int, str]:
            return _nextauth_signin_attempt(
                base_url, csrf_path, signin_path, callback_path, email, wrong_password
            )

    else:
        pytest.skip(
            f"Unsupported or unset stack.auth '{provider or '(empty)'}' for the "
            "sign-in enumeration probe (expected one of: clerk, supabase-auth, "
            "firebase, nextauth)"
        )

    existing_status, existing_body = _attempt(existing_email)
    nonexistent_status, nonexistent_body = _attempt(nonexistent_email)

    outcome = _enumeration_outcome(
        existing_status, existing_body, nonexistent_status, nonexistent_body
    )

    if outcome == "safe":
        return  # provider answers uniformly; existence cannot be inferred (pass)
    if outcome == "inconclusive":
        pytest.skip(
            f"{provider}: a sign-in attempt could not be completed (transport "
            f"error on the existing={existing_status} / "
            f"nonexistent={nonexistent_status} leg), so the enumeration-safety "
            "comparison is inconclusive."
        )

    # outcome == "disclosure": the two responses let an attacker tell a real
    # account from a fake one. Persist STATUS only (bodies may echo the probed
    # emails / provider text) via a sanitized FakeResponse.
    evidence.capture(
        FakeResponse(
            nonexistent_status,
            url,
            f"[body omitted] {provider} sign-in responses disclose account "
            f"existence: existing-email status={existing_status}, "
            f"nonexistent-email status={nonexistent_status} (one response "
            "explicitly states the account does not exist while the other does "
            "not).",
            "POST",
        ),
        label=f"{provider}_signin_enumeration_disclosure",
    )
    pytest.fail(
        f"MEDIUM: {provider} sign-in responses disclose whether an account exists "
        f"(ASVS 6.3.8, CWE-204). A wrong-password attempt for an existing email "
        f"(status {existing_status}) and for a non-existent email "
        f"(status {nonexistent_status}) differ in a way that names account "
        "non-existence, letting an attacker enumerate valid accounts. Return an "
        "identical generic error (and matching status) for both the "
        "account-not-found and wrong-password cases."
    )


# ===========================================================================
# Offline unit tests: pure helpers (no profile, no network)
# ===========================================================================

@pytest.mark.parametrize(
    "status,body,expected",
    [
        # 2xx accept is always the finding, regardless of body.
        (200, "", "accepted"),
        (201, '{"access_token":"x"}', "accepted"),
        # 4xx WITH a password-policy signal -> rejected (control present).
        (400, "Password should be at least 6 characters", "rejected"),
        (422, '{"error":"WEAK_PASSWORD : Password ..."}', "rejected"),
        (400, "passwords must be 8 characters or more", "rejected"),
        (400, "that password has been found in a data breach", "rejected"),
        (422, "password is too short", "rejected"),
        # 4xx with NO policy signal -> inconclusive (unrelated 4xx, not a pass).
        (400, "Invalid email address", "inconclusive"),
        (409, "user already registered", "inconclusive"),
        (429, "rate limit exceeded", "inconclusive"),
        # 5xx and transport sentinels -> inconclusive.
        (500, "internal error", "inconclusive"),
        (-1, "<transport error>", "inconclusive"),
    ],
)
def test_weak_password_outcome(status, body, expected):
    assert _weak_password_outcome(status, body) == expected


@pytest.mark.parametrize(
    "es,eb,ns,nb,expected",
    [
        # Uniform message, matching status -> safe (GoTrue-style).
        (400, "invalid login credentials", 400, "invalid login credentials", "safe"),
        (401, "Unauthorized", 401, "Unauthorized", "safe"),
        # Asymmetric phrase disclosure (both orderings) -> disclosure.
        (401, "wrong password", 404, "no account found for that email", "disclosure"),
        (404, "user not found", 401, "wrong password", "disclosure"),
        # Same status, only one leg discloses by phrase -> disclosure.
        (400, "incorrect password", 400, "account does not exist", "disclosure"),
        # Deterministic status-code split with generic bodies -> disclosure
        # (the status split is itself an oracle even when no body discloses).
        (401, "invalid credentials", 404, "not found", "disclosure"),
        # Status difference involving 429 -> inconclusive (throttle, not an oracle).
        (429, "slow down", 401, "invalid credentials", "inconclusive"),
        (401, "invalid credentials", 429, "slow down", "inconclusive"),
        # Status difference involving a 5xx -> inconclusive.
        (500, "internal error", 401, "invalid credentials", "inconclusive"),
        (401, "invalid credentials", 503, "service unavailable", "inconclusive"),
        # Symmetric disclosure, SAME status -> safe (both legs name non-existence).
        (404, "user not found", 404, "user not found", "safe"),
        # Symmetric disclosure, DIFFERENT non-transient status -> disclosure
        # (the status split distinguishes the accounts).
        (401, "user not found", 404, "user not found", "disclosure"),
        # An explicit phrase outranks the transient guard: a 429 leg that still
        # names non-existence is asymmetric disclosure (checked before the status
        # branch), so it is a real body-level oracle, not throttle noise.
        (429, "user not found", 401, "wrong password", "disclosure"),
        # Firebase structured codes (both HTTP 400): EMAIL_NOT_FOUND for the unknown
        # account vs INVALID_PASSWORD for the known one -> asymmetric -> disclosure.
        (400, "INVALID_PASSWORD", 400, "EMAIL_NOT_FOUND", "disclosure"),
        # Firebase enumeration-safe config: INVALID_LOGIN_CREDENTIALS for both -> safe.
        (400, "INVALID_LOGIN_CREDENTIALS", 400, "INVALID_LOGIN_CREDENTIALS", "safe"),
        # Transport sentinel on either leg -> inconclusive.
        (-1, "<err>", 401, "Unauthorized", "inconclusive"),
        (401, "Unauthorized", -1, "<err>", "inconclusive"),
    ],
)
def test_enumeration_outcome(es, eb, ns, nb, expected):
    assert _enumeration_outcome(es, eb, ns, nb) == expected


@pytest.mark.parametrize(
    "builder,arg,expected",
    [
        (_supabase_signup_url, "https://proj.supabase.co", "https://proj.supabase.co/auth/v1/signup"),
        # Trailing slash is normalised.
        (_supabase_signup_url, "https://proj.supabase.co/", "https://proj.supabase.co/auth/v1/signup"),
        (
            _supabase_signin_url,
            "https://proj.supabase.co",
            "https://proj.supabase.co/auth/v1/token?grant_type=password",
        ),
        (
            _firebase_signup_url,
            "AIzaTESTKEY",
            "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaTESTKEY",
        ),
        (
            _firebase_signin_url,
            "AIzaTESTKEY",
            "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaTESTKEY",
        ),
        (_clerk_signup_url, "https://clerk.example.com", "https://clerk.example.com/v1/client/sign_ups"),
        (_clerk_signin_url, "https://clerk.example.com/", "https://clerk.example.com/v1/client/sign_ins"),
    ],
)
def test_provider_url_builders(builder, arg, expected):
    assert builder(arg) == expected


def test_throwaway_email_is_random_and_reserved():
    """Throwaway emails are unique per call and on the reserved example.com domain."""
    a = _throwaway_email("pwpol")
    b = _throwaway_email("pwpol")
    assert a != b
    assert a.startswith("pentest-pwpol-") and a.endswith("@example.com")
