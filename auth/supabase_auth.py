"""Supabase GoTrue auth adapter for the pentest harness.

Token lifecycle
---------------
1. On first call for an account, signs in via GoTrue:
   ``POST <project_url>/auth/v1/token?grant_type=password``
   Headers: ``apikey: <anon_key>``, ``Authorization: Bearer <anon_key>``
   Body (JSON): ``{"email": ..., "password": ...}``
2. Decodes the returned ``access_token`` JWT (without signature verification)
   to read ``exp`` and the ``aal`` (assurance level) claim.
3. If the token is expired or within REFRESH_WINDOW_SECONDS of expiry,
   refreshes via:
   ``POST <project_url>/auth/v1/token?grant_type=refresh_token``
   Body (JSON): ``{"refresh_token": ...}``
   Note: refresh tokens may be single-use when rotation is enabled.

Hard-stop conditions
---------------------
- **CAPTCHA**: 400 + "captcha verification process failed" in the body →
  raises ``CaptchaEnforcedError``.  The target requires CAPTCHA which headless
  callers cannot solve.
- **MFA (AAL2)**: access_token has ``aal: "aal1"`` but target requires AAL2 →
  the adapter emits a finding and marks AAL2-gated tests as skipped.

PostgREST header requirement
------------------------------
``get_headers()`` returns BOTH ``Authorization: Bearer <token>`` AND
``apikey: <anon_key>``.  PostgREST requires the ``apikey`` header to identify
the project; omitting it causes 401 errors even with a valid JWT.

Environment variables
---------------------
- ``SUPABASE_PROJECT_URL``     — Project base URL, e.g. https://xyzxyz.supabase.co
- ``SUPABASE_ANON_KEY``        — Supabase anon/public key (JWT)
- ``PENTEST_USER_A_EMAIL``     — email for user_a
- ``PENTEST_USER_A_PASSWORD``  — password for user_a
- ``PENTEST_USER_B_EMAIL``     — email for user_b (optional)
- ``PENTEST_USER_B_PASSWORD``  — password for user_b (optional)
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx
import jwt as pyjwt

from .base import AbstractAuthAdapter, AuthConfigError, CaptchaEnforcedError

logger = logging.getLogger(__name__)

# Number of seconds before ``exp`` at which a refresh is triggered.
REFRESH_WINDOW_SECONDS = 10

# Retry config for network-level failures on refresh.
_MAX_RETRIES = 3

# Transient non-5xx statuses on the refresh grant. These do NOT mean the
# refresh token is invalid — they are rate-limit / timeout responses that
# should be retried with backoff (same path as 5xx), not treated as a
# rejected token. Mapping them to RefreshTokenRejected would discard a
# still-valid token and force avoidable password sign-ins (and more
# throttling) during long test runs.
_TRANSIENT_REFRESH_STATUSES = frozenset({408, 429})

# Substrings (case-insensitive) in a 400/401 refresh-grant body that
# unambiguously indicate the refresh token itself is invalid/expired.
_INVALID_GRANT_MARKERS = (
    "invalid_grant",
    "refresh_token_not_found",
    "invalid refresh token",
    "refresh token not found",
    "already used",
    "token has expired",
)


class RefreshTokenRejected(RuntimeError):
    """Raised only when GoTrue explicitly rejects the refresh token itself.

    Signals that the refresh token is invalid/expired (e.g. rotated and
    superseded). Raised for HTTP 400/401 refresh-grant responses whose body
    indicates an invalid grant, or — conservatively — any 400/401 on the
    refresh grant. The caller should discard the token and fall back to a
    full sign-in.

    Distinct from a plain RuntimeError raised on 5xx, network, or transient
    non-5xx (408/429) retry exhaustion, where the token may still be valid
    and falling back to sign-in would be wrong (and would cause avoidable
    re-auth and more throttling).
    """


# ---------------------------------------------------------------------------
# Session dataclass
# ---------------------------------------------------------------------------

@dataclass
class _SupabaseSession:
    """Per-account session state maintained by the Supabase adapter."""

    email: str
    password: str = field(repr=False)
    access_token: Optional[str] = None
    refresh_token: Optional[str] = field(default=None, repr=False)
    token_exp: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __str__(self) -> str:
        return (
            f"_SupabaseSession(email={self.email!r}, "
            f"password='***', "
            f"access_token={'<set>' if self.access_token else None}, "
            f"refresh_token={'<set>' if self.refresh_token else None}, "
            f"token_exp={self.token_exp})"
        )

    def __repr__(self) -> str:
        return self.__str__()


# ---------------------------------------------------------------------------
# Adapter implementation
# ---------------------------------------------------------------------------

class SupabaseAuthAdapter(AbstractAuthAdapter):
    """Supabase GoTrue implementation of :class:`AbstractAuthAdapter`.

    Args:
        project_url: Supabase project base URL, e.g.
            ``https://xyzxyz.supabase.co``.
            Must include scheme; must NOT have a trailing slash.
        anon_key: Supabase anon/public key (the ``apikey`` JWT).
            Used both as the API key header and in the initial Authorization
            header for GoTrue requests.
        accounts: Mapping of account name to credentials dict, e.g.::

                {
                    "user_a": {"email": "a@example.com", "password": "s3cr3t"},
                    "user_b": {"email": "b@example.com", "password": "s3cr3t"},
                }
    """

    def __init__(
        self,
        project_url: str,
        anon_key: str,
        accounts: dict[str, dict],
    ) -> None:
        self._project_url = project_url.rstrip("/")
        self._anon_key = anon_key
        self._http = httpx.Client()

        self._sessions: dict[str, _SupabaseSession] = {
            name: _SupabaseSession(
                email=creds["email"],
                password=creds["password"],
            )
            for name, creds in accounts.items()
        }

    # ------------------------------------------------------------------
    # AbstractAuthAdapter implementation
    # ------------------------------------------------------------------

    def get_token(self, account_name: str) -> str:
        """Return a valid access_token JWT, signing in or refreshing as needed."""
        self._validate_account(account_name)
        session = self._sessions[account_name]
        with session.lock:
            if session.access_token is None or self.is_expired(account_name):
                if session.refresh_token is None:
                    self._sign_in(account_name)
                else:
                    try:
                        self._refresh_token(account_name)
                    except RefreshTokenRejected:
                        # Token invalid/rotated — discard and re-sign-in.
                        # 5xx / network exhaustion raises plain RuntimeError
                        # which propagates (token may still be valid).
                        session.refresh_token = None
                        self._sign_in(account_name)
            if session.access_token is None:
                raise RuntimeError(
                    f"Authentication for '{account_name}' failed — access_token is None"
                )
            return session.access_token

    def get_headers(self, account_name: str) -> dict:
        """Return auth headers ready for httpx — both Authorization AND apikey.

        PostgREST requires the ``apikey`` header in addition to the standard
        ``Authorization: Bearer`` header.  Omitting either causes 401 errors.

        Returns:
            Dict with both ``Authorization`` and ``apikey`` keys.
        """
        token = self.get_token(account_name)
        return {
            "Authorization": f"Bearer {token}",
            "apikey": self._anon_key,
        }

    def is_expired(self, account_name: str) -> bool:
        """Return True if the token is missing, expired, or within the refresh window."""
        self._validate_account(account_name)
        session = self._sessions[account_name]
        if session.access_token is None:
            return True
        remaining = session.token_exp - time.time()
        return remaining <= REFRESH_WINDOW_SECONDS

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the shared httpx client."""
        try:
            self._http.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> "SupabaseAuthAdapter":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_account(self, account_name: str) -> None:
        if account_name not in self._sessions:
            raise ValueError(
                f"Unknown account '{account_name}'. "
                f"Valid options: {sorted(self._sessions)}"
            )

    def _gotrue_headers(self) -> dict[str, str]:
        """Headers required on every GoTrue request."""
        return {
            "apikey": self._anon_key,
            "Authorization": f"Bearer {self._anon_key}",
            "Content-Type": "application/json",
        }

    def _sign_in(self, account_name: str) -> None:
        """Sign in via GoTrue password grant and populate the session."""
        session = self._sessions[account_name]
        url = f"{self._project_url}/auth/v1/token?grant_type=password"
        payload = {
            "email": session.email,
            "password": session.password,
        }

        try:
            resp = self._http.post(
                url,
                json=payload,
                headers=self._gotrue_headers(),
                timeout=20.0,
            )
        except httpx.HTTPError:
            raise RuntimeError(
                f"Supabase GoTrue sign-in request failed for '{account_name}' "
                f"({session.email}): network error"
            ) from None

        # CAPTCHA detection: 400 + captcha error in body.
        if resp.status_code == 400:
            body_text = self._safe_response_text(resp)
            if "captcha" in body_text.lower():
                raise CaptchaEnforcedError(
                    f"CAPTCHA verification is enforced for '{account_name}' "
                    f"({session.email}). The Supabase project requires CAPTCHA "
                    "which headless pentest callers cannot complete. "
                    "Disable CAPTCHA for the test project or supply a "
                    "pre-obtained token."
                )
            raise AuthConfigError(
                f"Supabase sign-in failed for '{account_name}' ({session.email}): "
                f"HTTP 400 — {body_text[:300]}"
            )

        if resp.status_code != 200:
            body_text = self._safe_response_text(resp)
            raise AuthConfigError(
                f"Supabase sign-in failed for '{account_name}' ({session.email}): "
                f"HTTP {resp.status_code} — {body_text[:300]}"
            )

        data = resp.json()

        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")

        if not access_token:
            raise RuntimeError(
                f"Supabase sign-in for '{account_name}' succeeded (HTTP 200) "
                "but access_token was not found in response."
            )

        # MFA / AAL detection: check the aal claim in the JWT.
        self._check_aal(account_name, access_token)

        session.access_token = access_token
        session.refresh_token = refresh_token
        session.token_exp = self._decode_exp(access_token)

    def _refresh_token(self, account_name: str) -> None:
        """Refresh the access token via GoTrue refresh_token grant."""
        session = self._sessions[account_name]
        url = f"{self._project_url}/auth/v1/token?grant_type=refresh_token"
        payload = {"refresh_token": session.refresh_token}

        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = self._http.post(
                    url,
                    json=payload,
                    headers=self._gotrue_headers(),
                    timeout=15.0,
                )
            except httpx.HTTPError:
                last_error = True
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise RuntimeError(
                    f"Supabase token refresh failed for '{account_name}': "
                    f"network error after {_MAX_RETRIES} attempts"
                ) from None

            if resp.status_code == 200:
                break

            # 5xx and transient non-5xx (408 timeout, 429 rate limit) share
            # the same retry-with-backoff path. The refresh token may still
            # be valid, so on exhaustion we raise a plain RuntimeError (which
            # get_token() propagates — NO sign-in fallback).
            if (
                resp.status_code >= 500
                or resp.status_code in _TRANSIENT_REFRESH_STATUSES
            ):
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(2 ** (attempt + 1))
                    continue
                # Last attempt — fall through to for-else.
                continue

            # Remaining non-2xx, non-5xx, non-transient statuses.
            body_text = self._safe_response_text(resp)
            if resp.status_code in (400, 401) and self._is_invalid_grant(body_text):
                # Explicit invalid/expired/rotated refresh token. Raise the
                # distinct type so get_token() discards it and re-signs-in.
                raise RefreshTokenRejected(
                    f"Supabase token refresh failed for '{account_name}': "
                    f"HTTP {resp.status_code} (invalid grant) — "
                    f"{body_text[:200]}"
                )

            # Conservative fallback: a 400/401 on a refresh grant is almost
            # always the token, even when the body is unparseable or lacks a
            # recognized marker. Treat as token-rejected.
            if resp.status_code in (400, 401):
                raise RefreshTokenRejected(
                    f"Supabase token refresh failed for '{account_name}': "
                    f"HTTP {resp.status_code} — {body_text[:200]}"
                )

            # Anything else (e.g. 403, 404) is unexpected and not a clear
            # token rejection. Raise a plain RuntimeError so get_token()
            # propagates it without discarding a possibly-valid token.
            raise RuntimeError(
                f"Supabase token refresh failed for '{account_name}': "
                f"unexpected HTTP {resp.status_code} — {body_text[:200]}"
            )
        else:
            raise RuntimeError(
                f"Supabase token refresh failed after {_MAX_RETRIES} attempts "
                f"for '{account_name}'."
            )

        data = resp.json()
        new_access_token = data.get("access_token")
        if not new_access_token:
            raise RuntimeError(
                f"Supabase token refresh response missing 'access_token' field "
                f"for '{account_name}'. Keys present: {list(data.keys())}"
            )

        # Supabase may rotate the refresh token — update if a new one is present.
        new_refresh_token = data.get("refresh_token")
        if new_refresh_token:
            session.refresh_token = new_refresh_token

        session.access_token = new_access_token
        session.token_exp = self._decode_exp(new_access_token)

    def _check_aal(self, account_name: str, access_token: str) -> None:
        """Decode the access_token and emit a finding if AAL is insufficient.

        If the token carries ``aal: "aal1"`` the account does not have a second
        factor verified.  We emit a log-level finding so that callers can mark
        AAL2-gated tests as skipped.  This is not raised as an exception because
        aal1 accounts can still be used against non-MFA-required endpoints.
        """
        try:
            payload = pyjwt.decode(
                access_token,
                options={"verify_signature": False},
                algorithms=["HS256", "ES256", "RS256"],
            )
        except pyjwt.DecodeError:
            # If we cannot decode, silently skip the AAL check.
            return

        aal = payload.get("aal")
        if aal == "aal1":
            logger.warning(
                "FINDING [supabase-auth/mfa-aal1]: Account '%s' authenticated at "
                "AAL1 (single-factor). Tests requiring AAL2 (MFA-verified) will be "
                "skipped. To reach AAL2, enroll a TOTP factor and complete "
                "verification before the pentest session.",
                account_name,
            )

    @staticmethod
    def _decode_exp(token: str) -> int:
        """Decode JWT without verification and return the ``exp`` claim.

        Supports HS256 and ES256 (GoTrue uses HS256; custom JWTs may use ES256).

        Raises:
            RuntimeError: If ``exp`` is missing or the token cannot be decoded.
        """
        try:
            payload = pyjwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=["HS256", "ES256", "RS256"],
            )
        except pyjwt.DecodeError as exc:
            raise RuntimeError(f"Could not decode JWT: {exc}") from exc

        exp = payload.get("exp")
        if exp is None:
            raise RuntimeError("JWT payload is missing the 'exp' claim.")
        return int(exp)

    @staticmethod
    def _is_invalid_grant(body_text: str) -> bool:
        """Return True if a 400/401 refresh-grant body indicates a bad token.

        GoTrue signals an invalid/expired/rotated refresh token via fields
        such as ``error`` (``invalid_grant``), ``error_code``, or ``msg``.
        We check the parsed JSON values first, then fall back to a raw
        substring scan so we still classify correctly when the body is
        non-JSON. Returns False when no recognized marker is present (the
        caller applies a conservative 400/401 fallback separately).
        """
        haystack = body_text.lower()

        try:
            parsed = json.loads(body_text)
        except (ValueError, TypeError):
            parsed = None

        if isinstance(parsed, dict):
            for key in ("error", "error_code", "error_description", "msg", "message"):
                value = parsed.get(key)
                if isinstance(value, str):
                    haystack += " " + value.lower()

        return any(marker in haystack for marker in _INVALID_GRANT_MARKERS)

    @staticmethod
    def _safe_response_text(resp: httpx.Response) -> str:
        """Extract response text, guarding against encoding issues."""
        try:
            return resp.text
        except Exception:  # noqa: BLE001
            return "<unreadable response body>"
