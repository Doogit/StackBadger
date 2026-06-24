"""Session-management probes — replay-after-logout, re-auth gate, fresh-token-on-auth.

ASVS 5.0: V7.4.1 (session invalidation on logout), V7.2.4 (new token issued on
authentication), V7.5.1 (re-authentication before a sensitive change).
CWE-613 (insufficient session expiration), CWE-384 (session fixation).

Cross-provider by design
------------------------
Every probe dispatches on ``profile.stack.auth`` and runs against whichever of
the four supported auth providers the active profile declares:

    clerk · firebase · supabase-auth · nextauth

The token-rotation / logout-invalidation controls are largely *provider-managed*
(token issuance and session revocation are the IdP's job, not the app's). We
test them **where they are observable over the wire** and record a Track-C
provider attestation (skip-with-reason) where they are not — Firebase, for
example, exposes no client-REST token-revocation endpoint, so replay-after-
logout cannot be observed black-box there.

Safety
------
These probes must NEVER use the shared ``auth_adapter`` / ``user_a_client``
fixtures to log out: the harness deliberately excludes ``/logout`` /
``/signout`` / token-rotation paths from enumeration (see ``exclusions.py``)
precisely because hitting them destroys the session the rest of the suite is
authenticated with. Instead each probe builds its OWN throwaway adapter
instance, signs in independently, and revokes *that* session — the shared
fixtures are never touched.

Logout and sensitive-change probes send state-changing requests, so they carry
``@pytest.mark.write_probe`` (read-only mode skips them) in addition to
``@pytest.mark.asvs_extended`` (the heavy pre-audit scope). All probes are
dual-tagged ``asvs(...)`` + ``cwe(...)`` for the coverage ledger.
"""

from __future__ import annotations

import sys as _sys
import time
from pathlib import Path as _Path

import httpx
import pytest

# ---------------------------------------------------------------------------
# Package-root import shim (mirrors the other test modules)
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from auth import create_adapter  # noqa: E402
from auth.base import AuthConfigError  # noqa: E402
from conftest import endpoints_for_category, probe_body_for  # noqa: E402
from helpers import FakeResponse, auth_provider as _auth_provider, netlify_url, safe_text as _safe_text  # noqa: E402

# Auth providers whose post-logout session invalidation is observable over the
# wire by a black-box prober. Firebase is intentionally absent: revoking a
# Firebase session requires the Admin SDK (``revokeRefreshTokens``), which has
# no client-REST equivalent, so logout-invalidation is a Track-C attestation
# there rather than a probe (the explicit firebase skip in
# test_session_invalidated_after_logout records that, and its absence here means
# an accidental removal of that skip falls through to the unsupported-provider
# skip rather than into a provider branch that cannot handle it).
_REVOCATION_OBSERVABLE = ("clerk", "supabase-auth", "nextauth")

# Path keywords that mark an authenticated endpoint as a *sensitive account
# change* (password / email / MFA / account-security mutation) for the V7.5.1
# re-authentication probe. Matched case-insensitively against the endpoint path.
# Irreversible-destruction keywords (delete-account, deactivate) are deliberately
# EXCLUDED: this probe submits the change with a valid session to observe whether
# re-auth is enforced, so auto-targeting an account-destroying endpoint could wipe
# the shared test account on a target that does not gate it. /delete-account is
# additionally in DEFAULT_EXCLUDE_PATHS; we keep recoverable sensitive changes only.
_SENSITIVE_CHANGE_KEYWORDS = (
    "password",
    "change-email",
    "update-email",
    "email-change",
    "mfa",
    "2fa",
    "two-factor",
)


# ---------------------------------------------------------------------------
# Provider-agnostic throwaway session
# ---------------------------------------------------------------------------

def _fresh_adapter(profile):
    """Build a throwaway adapter and sign in user_a, or skip if unavailable.

    This is a SECOND adapter instance, independent of the shared ``auth_adapter``
    fixture, so revoking its session never poisons the rest of the suite.
    """
    try:
        adapter = create_adapter(profile)
    except AuthConfigError as exc:
        pytest.skip(f"Session probe: auth adapter unavailable ({exc})")
    # Force sign-in for user_a so the session state is populated. Any failure
    # must close the adapter's httpx clients before propagating/skipping so a
    # transient sign-in error (timeout, JSON decode, provider config) cannot
    # leak the per-account clients — this runs twice for the rotation probe.
    try:
        adapter.get_headers("user_a")
    except AuthConfigError as exc:
        _safe_close(adapter)
        pytest.skip(f"Session probe: user_a sign-in unavailable ({exc})")
    except NotImplementedError:
        # NextAuth is cookie-based — get_headers() works, get_token() does not.
        # get_headers() above already triggered sign-in, so this path is only
        # reached if a provider raises unexpectedly; treat as not-runnable.
        _safe_close(adapter)
        pytest.skip("Session probe: provider does not expose a usable credential")
    except Exception:
        _safe_close(adapter)
        raise
    return adapter


def _safe_close(adapter) -> None:
    close = getattr(adapter, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001
            pass


def _request_or_skip(fn, what: str):
    """Run a live request thunk, converting a transport error into a clean skip.

    A logout/replay probe that hits a DNS/timeout failure should skip (the
    control is indeterminate), not surface a noisy test error.
    """
    try:
        return fn()
    except httpx.HTTPError as exc:
        pytest.skip(f"Session probe: {what} failed (network error: {type(exc).__name__})")


def _session_state(adapter, account: str = "user_a"):
    """Return the adapter's private per-account session object, or None.

    Reading ``adapter._sessions`` is an established pattern in this harness
    (``conftest._adapter_has_account`` does the same); it is the only way to
    reach the raw refresh token / session id needed to drive a revoke.
    """
    sessions = getattr(adapter, "_sessions", None)
    if not sessions:
        return None
    return sessions.get(account)


# ---------------------------------------------------------------------------
# Provider revoke + replay implementations
# ---------------------------------------------------------------------------

def _supabase_logout_then_replay(adapter, evidence) -> tuple[bool, str]:
    """Supabase GoTrue: log out, then replay the OLD refresh token.

    A correctly-invalidated session rejects the old refresh token (invalid
    grant). Returns ``(still_valid, detail)`` — ``still_valid=True`` means the
    revoked session can still mint tokens, i.e. a real V7.4.1 finding.
    """
    state = _session_state(adapter)
    project_url = getattr(adapter, "_project_url", "")
    anon_key = getattr(adapter, "_anon_key", "")
    http = getattr(adapter, "_http", None)
    if not (state and project_url and anon_key and http is not None):
        pytest.skip("Supabase session probe: adapter internals unavailable")
    access_token = getattr(state, "access_token", None)
    refresh_token = getattr(state, "refresh_token", None)
    if not (access_token and refresh_token):
        pytest.skip("Supabase session probe: no access/refresh token captured")

    gotrue_headers = {"apikey": anon_key, "Authorization": f"Bearer {access_token}"}

    # 1. Log out — revokes the refresh token / session server-side.
    logout_resp = _request_or_skip(
        lambda: http.post(
            f"{project_url}/auth/v1/logout", headers=gotrue_headers, timeout=15.0
        ),
        "Supabase logout",
    )
    evidence.capture(
        FakeResponse(logout_resp.status_code, f"{project_url}/auth/v1/logout",
                     "[logout — body omitted]", "POST"),
        "supabase_logout",
    )
    # If logout itself failed, the replay result is meaningless — a still-valid
    # refresh token would reflect a failed logout, not a missing control.
    if logout_resp.status_code not in (200, 204):
        pytest.skip(
            f"Supabase logout returned HTTP {logout_resp.status_code}; cannot "
            "determine replay validity (logout did not complete)."
        )

    # 2. Replay the OLD refresh token. A revoked session must reject it.
    replay = _request_or_skip(
        lambda: http.post(
            f"{project_url}/auth/v1/token?grant_type=refresh_token",
            headers={"apikey": anon_key, "Authorization": f"Bearer {anon_key}",
                     "Content-Type": "application/json"},
            json={"refresh_token": refresh_token},
            timeout=15.0,
        ),
        "Supabase refresh replay",
    )
    # Never persist the token-bearing refresh response body to evidence.
    evidence.capture(
        FakeResponse(replay.status_code,
                     f"{project_url}/auth/v1/token?grant_type=refresh_token",
                     "[refresh replay — token body omitted]", "POST"),
        "supabase_refresh_replay_after_logout",
    )
    still_valid = replay.status_code == 200 and "access_token" in replay.text
    return still_valid, (
        f"refresh-grant replay after logout returned HTTP {replay.status_code}"
    )


def _clerk_logout_then_replay(adapter, evidence) -> tuple[bool, str]:
    """Clerk FAPI: remove the session, then replay it by minting a token."""
    state = _session_state(adapter)
    fapi_host = getattr(adapter, "_fapi_host", "")
    if not (state and fapi_host):
        pytest.skip("Clerk session probe: adapter internals unavailable")
    session_id = getattr(state, "session_id", None)
    http = getattr(state, "http", None)
    if not (session_id and http is not None):
        pytest.skip("Clerk session probe: no session id captured")

    base_headers = {}
    origin = getattr(adapter, "_target_origin", None)
    if origin:
        base_headers["Origin"] = origin

    # 1. Sign out — remove this session from the client.
    remove_resp = _request_or_skip(
        lambda: http.post(
            f"{fapi_host}/v1/client/sessions/{session_id}/remove",
            headers=base_headers, timeout=15.0,
        ),
        "Clerk session remove",
    )
    evidence.capture(
        FakeResponse(remove_resp.status_code,
                     f"{fapi_host}/v1/client/sessions/{session_id}/remove",
                     "[session remove — body omitted]", "POST"),
        "clerk_session_remove",
    )

    # 2. Replay: attempt to mint a fresh token for the removed session.
    mint = _request_or_skip(
        lambda: http.post(
            f"{fapi_host}/v1/client/sessions/{session_id}/tokens",
            headers=base_headers, timeout=15.0,
        ),
        "Clerk token mint replay",
    )
    evidence.capture(
        FakeResponse(mint.status_code,
                     f"{fapi_host}/v1/client/sessions/{session_id}/tokens",
                     "[token mint replay — token body omitted]", "POST"),
        "clerk_token_mint_after_remove",
    )
    still_valid = mint.status_code == 200 and "jwt" in mint.text
    return still_valid, (
        f"token mint for removed session returned HTTP {mint.status_code}"
    )


def _nextauth_logout_then_replay(adapter, evidence) -> tuple[bool, str]:
    """NextAuth: sign out, then replay the session cookie against /session."""
    state = _session_state(adapter)
    base_url = getattr(adapter, "_base_url", "")
    if not (state and base_url):
        pytest.skip("NextAuth session probe: adapter internals unavailable")
    http = getattr(state, "http_client", None)
    csrf_token = getattr(state, "csrf_token", None)
    session_path = getattr(adapter, "_session_path", "/api/auth/session")
    if http is None:
        pytest.skip("NextAuth session probe: no session client captured")

    # 1. Sign out via the Auth.js signout callback (CSRF-protected form POST).
    signout_resp = _request_or_skip(
        lambda: http.post(
            f"{base_url}/api/auth/signout",
            data={"csrfToken": csrf_token or "", "callbackUrl": base_url, "json": "true"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15.0,
            follow_redirects=True,
        ),
        "NextAuth signout",
    )
    evidence.capture(
        FakeResponse(signout_resp.status_code, f"{base_url}/api/auth/signout",
                     "[signout — body omitted]", "POST"),
        "nextauth_signout",
    )

    # 2. Replay: the same client (cookie jar) must now report a userless session.
    replay = _request_or_skip(
        lambda: http.get(f"{base_url}{session_path}", timeout=15.0),
        "NextAuth session replay",
    )
    body = _safe_text(replay)
    evidence.capture(
        FakeResponse(replay.status_code, f"{base_url}{session_path}",
                     "[session replay — body omitted]", "GET"),
        "nextauth_session_replay_after_signout",
    )
    has_user = replay.status_code == 200 and '"user"' in body
    return has_user, (
        f"session endpoint after signout returned HTTP {replay.status_code}"
        + (" with a user object" if has_user else " (userless)")
    )


# ---------------------------------------------------------------------------
# V7.4.1 — session invalidation on logout (replay-after-logout)
# ---------------------------------------------------------------------------

@pytest.mark.asvs_extended
@pytest.mark.asvs("7.4.1")
@pytest.mark.cwe("613")
@pytest.mark.write_probe
def test_session_invalidated_after_logout(profile, evidence):
    """A logged-out session must not be replayable.

    Establishes a throwaway session, logs it out, then replays the revoked
    credential against the provider's own session/token endpoint. The session
    must be rejected; if it still works the app/IdP leaks a usable session past
    logout (CWE-613).

    Provider observability:
      - supabase-auth: replay the revoked refresh token → must be rejected.
      - clerk: mint a token for the removed session → must fail.
      - nextauth: session endpoint after signout → must be userless.
      - firebase: no client-REST revocation → Track-C attestation (skip).
    """
    provider = _auth_provider(profile)
    if provider == "firebase":
        pytest.skip(
            "Track-C attestation: Firebase exposes no client-REST token "
            "revocation (revokeRefreshTokens is Admin-SDK only); logout "
            "invalidation is verified by provider attestation, not black-box."
        )
    if provider not in _REVOCATION_OBSERVABLE:
        pytest.skip(f"Session-logout probe does not support stack.auth='{provider}'")

    adapter = _fresh_adapter(profile)
    try:
        if provider == "supabase-auth":
            still_valid, detail = _supabase_logout_then_replay(adapter, evidence)
        elif provider == "clerk":
            still_valid, detail = _clerk_logout_then_replay(adapter, evidence)
        elif provider == "nextauth":
            still_valid, detail = _nextauth_logout_then_replay(adapter, evidence)
        else:  # pragma: no cover - guarded above
            pytest.skip(f"Unsupported provider '{provider}'")
    finally:
        _safe_close(adapter)

    assert not still_valid, (
        f"Session survived logout ({provider}): {detail}. The session was "
        "revoked but the credential is still accepted — logout must invalidate "
        "the session server-side (ASVS V7.4.1, CWE-613)."
    )


# ---------------------------------------------------------------------------
# V7.2.4 — a new session token is issued on authentication
# ---------------------------------------------------------------------------

# No @write_probe: a sign-in establishes auth state at the IdP, not a mutation
# of target application data. The harness treats sign-in as test infrastructure
# (the shared auth_adapter signs in for every authenticated test without a
# write-probe gate); the write_probe gate is reserved for INSERT/UPDATE/DELETE/
# upload of app data and for the session-destroying logout/sensitive-change
# probes below. Marking this would over-gate a read-only-safe rotation check.
@pytest.mark.asvs_extended
@pytest.mark.asvs("7.2.4")
@pytest.mark.cwe("384")
def test_new_token_issued_on_authentication(profile, evidence):
    """Authenticating must mint a fresh session credential each time.

    Two independent sign-ins of the same account must yield distinct session
    credentials. A static, reused credential across logins is a session-
    fixation risk (CWE-384): an attacker who fixes a victim's pre-auth token
    would retain a valid post-auth session.

    Firebase id-tokens embed a per-issue ``iat`` and are unique per sign-in;
    NextAuth mints a fresh opaque session cookie; Clerk/Supabase issue a fresh
    JWT. Where a provider deterministically reuses a credential this fails.
    """
    provider = _auth_provider(profile)
    cred_one = _capture_credential(profile)
    # A second, fully independent sign-in.
    cred_two = _capture_credential(profile)

    evidence.capture(
        FakeResponse(0, f"auth://{provider}/issue",
                     "[two sign-in credentials compared — values omitted]", "POST"),
        "fresh_token_on_auth",
    )

    assert cred_one and cred_two, "Could not capture two session credentials"

    # If the adapter actually SERVED a static pre-obtained JWT from the env-var
    # fallback (FAPI/GoTrue unreachable or rate-limited), both sign-ins return
    # the same bytes — a harness artifact, not a target session-fixation flaw.
    # Skip only when the captured credential IS that env JWT (not merely when the
    # env var happens to be set): with a live sign-in path, a genuine token-reuse
    # fixation bug must still fail the assertion below even if the fallback var
    # is also exported.
    if cred_one == cred_two and _is_static_env_jwt_credential(cred_one):
        pytest.skip(
            "Identical credentials served from the static PENTEST_USER_A_JWT env "
            "fallback (the IdP sign-in path was unavailable); cannot observe "
            "per-authentication token rotation. Not a finding."
        )

    assert cred_one != cred_two, (
        f"Two independent {provider} sign-ins returned an IDENTICAL session "
        "credential. A fresh session token must be issued on each "
        "authentication (ASVS V7.2.4, CWE-384) — a static credential enables "
        "session fixation."
    )


def _is_static_env_jwt_credential(cred: str) -> bool:
    """True when *cred* is the static PENTEST_USER_A_JWT fallback (actually used).

    The adapter falls back to this pre-obtained JWT only when live sign-in is
    unavailable. Matching the credential to the env value (not just its presence)
    distinguishes 'fallback in effect' from a real reused-token fixation finding.
    """
    import os
    env_jwt = os.environ.get("PENTEST_USER_A_JWT")
    return bool(env_jwt) and cred == f"Bearer {env_jwt}"


def _capture_credential(profile) -> str:
    """Sign in on a throwaway adapter and return its comparable session credential."""
    adapter = _fresh_adapter(profile)
    try:
        return _credential_for_comparison(adapter, "user_a")
    finally:
        _safe_close(adapter)


def _credential_for_comparison(adapter, account: str = "user_a") -> str:
    """Return the per-SESSION credential used to detect token rotation.

    Bearer providers: the ``Authorization`` header (a per-session JWT).

    Cookie providers (NextAuth/Auth.js): ONLY the session cookie, NOT the full
    ``Cookie`` header. ``get_headers()`` exports every scoped cookie (CSRF,
    callback, and other auxiliary cookies) which rotate on each sign-in even when
    the *session* cookie is reused — comparing the whole header would make two
    sign-ins look different despite a reused session, masking a V7.2.4 fixation
    bug (false negative). We read the session cookie from the adapter state and
    compare only that.
    """
    headers = adapter.get_headers(account)
    if getattr(adapter, "auth_type", "bearer") == "cookie":
        state = _session_state(adapter, account)
        name = getattr(state, "session_cookie_name", None)
        value = getattr(state, "session_cookie_value", None)
        if name and value:
            return f"{name}={value}"
    # Bearer token, or a cookie provider whose session cookie is unavailable.
    return headers.get("Authorization") or headers.get("Cookie") or ""


class _FakeSessionState:
    def __init__(self, value: str) -> None:
        self.session_cookie_name = "next-auth.session-token"
        self.session_cookie_value = value


class _FakeCookieAdapter:
    """Minimal cookie-auth adapter whose Cookie header carries a rotating CSRF
    cookie alongside the session cookie (mirrors NextAuthAdapter.get_headers)."""

    auth_type = "cookie"

    def __init__(self, session_value: str, csrf_value: str) -> None:
        self._sessions = {"user_a": _FakeSessionState(session_value)}
        self._csrf = csrf_value

    def get_headers(self, account: str) -> dict:
        st = self._sessions[account]
        return {
            "Cookie": (
                f"next-auth.csrf-token={self._csrf}; "
                f"{st.session_cookie_name}={st.session_cookie_value}"
            )
        }


def test_cookie_rotation_compares_only_session_cookie():
    """V7.2.4 fixation must be detected for cookie auth even when auxiliary
    cookies rotate.

    Offline regression for the false negative where comparing the whole Cookie
    header (CSRF/callback cookies rotate per sign-in) hid a reused session
    cookie. _credential_for_comparison must compare ONLY the session cookie.
    """
    # Same session cookie reused across two sign-ins; the CSRF cookie rotates.
    a = _FakeCookieAdapter("REUSED-SESSION", "csrf-AAA")
    b = _FakeCookieAdapter("REUSED-SESSION", "csrf-BBB")

    # Full Cookie headers differ — the old whole-header comparison would PASS
    # and miss the fixation.
    assert a.get_headers("user_a")["Cookie"] != b.get_headers("user_a")["Cookie"]

    # The session-only credential is identical, so the probe correctly flags the
    # reused session (cred_one == cred_two -> the V7.2.4 assertion fires).
    cred_a = _credential_for_comparison(a)
    cred_b = _credential_for_comparison(b)
    assert cred_a == cred_b == "next-auth.session-token=REUSED-SESSION"

    # A genuinely rotated session still yields a distinct credential (no false
    # positive when the session cookie actually changes).
    c = _FakeCookieAdapter("FRESH-SESSION", "csrf-CCC")
    assert _credential_for_comparison(c) != cred_a


# ---------------------------------------------------------------------------
# V7.5.1 — re-authentication required before a sensitive account change
# ---------------------------------------------------------------------------

@pytest.mark.asvs_extended
@pytest.mark.asvs("7.5.1")
@pytest.mark.cwe("384")
@pytest.mark.write_probe
def test_reauth_required_for_sensitive_change(profile, user_a_client, evidence):
    """A sensitive account change must require recent re-authentication.

    Locates a sensitive-change endpoint from the profile (password / email /
    MFA / account-security mutation, by ``sensitive_change: true`` flag or path
    keyword) and submits it with an ordinary, non-recently-re-authenticated
    session. The app should challenge for re-auth (401/403, or a step-up
    response) rather than silently applying the change.

    Derived entirely from the profile — no hardcoded endpoint names. Skips when
    the profile declares no sensitive-change endpoint.
    """
    endpoint = _find_sensitive_change_endpoint(profile)
    if endpoint is None:
        pytest.skip(
            "No sensitive-change endpoint in profile (flag an authenticated "
            "endpoint with 'sensitive_change: true' or use a recognised path "
            "keyword to enable the V7.5.1 re-auth probe)."
        )

    path = endpoint["path"]
    body = probe_body_for(endpoint)
    method = (endpoint.get("method") or "POST").upper()
    url = netlify_url(profile, path)

    resp = _request_or_skip(
        lambda: user_a_client.request(method, url, json=body, timeout=15),
        f"sensitive-change request to {path}",
    )
    # A sensitive-change response may echo a confirmation token or PII, so never
    # persist its body — capture a sanitized record only (mirrors the module's
    # no-secret-in-evidence invariant).
    evidence.capture(
        FakeResponse(resp.status_code, url, "[body omitted]", method),
        "sensitive_change_without_reauth",
    )

    status = resp.status_code

    # A status/header challenge is reliable proof the change was NOT applied and
    # re-auth was demanded. Body-text markers are NOT trusted for the applied
    # decision: a 2xx that already APPLIED the change could coincidentally carry
    # a step-up phrase (a generic UI string), which would otherwise silently
    # suppress a real V7.5.1 finding.
    if status in (401, 403) or _header_signals_step_up(resp):
        return  # re-auth enforced — control present.

    # A 400/422 likely means the synthetic probe body was rejected by input
    # validation BEFORE any re-auth check ran — proves nothing about re-auth, so
    # treat it as inconclusive (skip), never a pass.
    if status in (400, 422):
        pytest.skip(
            f"Sensitive-change probe at {path} returned HTTP {status} (likely "
            "input-validation rejection of the synthetic body); cannot determine "
            "whether re-auth is enforced. Supply a valid probe_body to make this "
            "conclusive."
        )

    # A 2xx that carries a body step-up phrase but NO status/header challenge is
    # ambiguous — it could be a client-rendered re-auth prompt OR an applied
    # change whose body merely mentions re-auth. Skip as inconclusive rather than
    # risk a false negative (silently passing an applied change) or a false
    # positive (failing a genuine 200 step-up prompt).
    if 200 <= status < 300 and _body_signals_step_up(resp):
        pytest.skip(
            f"Sensitive-change probe at {path} returned HTTP {status} with a "
            "step-up phrase in the body but no status/header challenge; cannot "
            "distinguish an applied change from a client-rendered re-auth prompt. "
            "Verify re-auth enforcement manually."
        )

    # A plain 2xx with no challenge of any kind means the change was applied
    # without re-authentication — the finding.
    applied = 200 <= status < 300
    assert not applied, (
        f"Sensitive change at {path} was applied (HTTP {status}) without "
        "requiring re-authentication. Sensitive account changes "
        "(password/email/MFA) must re-verify the user's identity (ASVS "
        "V7.5.1, CWE-384)."
    )


def _find_sensitive_change_endpoint(profile):
    """First authenticated endpoint flagged sensitive, or matching a keyword."""
    eps = endpoints_for_category(profile, "authenticated")
    # Explicit profile flag wins.
    for ep in eps:
        if ep.get("sensitive_change") is True:
            return ep
    # Fall back to a path-keyword heuristic.
    for ep in eps:
        path = (ep.get("path") or "").lower()
        if any(kw in path for kw in _SENSITIVE_CHANGE_KEYWORDS):
            return ep
    return None


_STEP_UP_BODY_MARKERS = (
    "reauth", "re-auth", "re-authenticate", "step-up", "step up",
    "verify your identity", "confirm your password", "recent login",
    "requires recent authentication", "password_confirmation_required",
)


def _header_signals_step_up(resp) -> bool:
    """True when a WWW-Authenticate header demands re-auth / step-up.

    Header/status signals are authoritative for the 'applied' decision; body
    text is not (see _body_signals_step_up).
    """
    www_auth = resp.headers.get("www-authenticate", "").lower()
    return "reauth" in www_auth or "step" in www_auth


def _body_signals_step_up(resp) -> bool:
    """True when the response BODY mentions a re-authentication / step-up prompt.

    Advisory only: a body marker on a 2xx is ambiguous (an applied change may
    also mention re-auth), so callers treat it as inconclusive, not proof.
    """
    body = _safe_text(resp).lower()
    return any(m in body for m in _STEP_UP_BODY_MARKERS)
