"""Clerk auth adapter for the pentest harness — FAPI-based sign-in.

Token lifecycle
---------------
1. On first call for an account, signs in via the Clerk Frontend API (FAPI):
   ``POST https://<fapi_host>/v1/client/sign_ins``
   Body (form-encoded): ``identifier=<email>&strategy=password&password=<password>``
2. Decodes the returned JWT (without signature verification) to read ``exp``.
3. If the token is expired or within REFRESH_WINDOW_SECONDS of expiry, refreshes
   via FAPI: ``POST https://<fapi_host>/v1/client/sessions/<session_id>/tokens``
4. On any FAPI failure, falls back to ``PENTEST_USER_A_JWT`` / ``PENTEST_USER_B_JWT``
   env vars and logs a warning.

No ``CLERK_SECRET_KEY`` is required at runtime. The secret key name appears
below only in a fallback warning string and in comments — it is intentionally
absent from production code paths.

Dev vs production instances
----------------------------
- Dev:  FAPI host contains ``.clerk.accounts.dev``. The fresh JWT is read from
        ``response.json()["client"]["sessions"][0]["last_active_token"]["jwt"]``.
        The ``__client`` cookie is also set but the JSON path is more reliable.
- Prod: JWT is read from the same JSON path. The ``__client`` cookie in the
        ``Set-Cookie`` header serves as the session credential for subsequent
        refresh calls and is stored in the per-account ``httpx.Client`` cookie jar.

Environment variables (optional — only used as FAPI fallback)
---------------------------------------------------------------
- ``PENTEST_USER_A_JWT``  — fallback initial JWT for user_a
- ``PENTEST_USER_B_JWT``  — fallback initial JWT for user_b
"""

from __future__ import annotations

import logging
import os
import time
import warnings
from dataclasses import dataclass, field
from typing import Optional

import httpx
import jwt as pyjwt

from .base import AbstractAuthAdapter, AuthConfigError

logger = logging.getLogger(__name__)

# Number of seconds before ``exp`` at which a refresh is triggered.
REFRESH_WINDOW_SECONDS = 10

# Mapping from logical account name to env var prefix (fallback only).
_ACCOUNT_ENV_PREFIX: dict[str, str] = {
    "user_a": "PENTEST_USER_A",
    "user_b": "PENTEST_USER_B",
}

# JSON path used to extract the JWT from a FAPI sign-in or token-refresh response.
# Path: response["client"]["sessions"][0]["last_active_token"]["jwt"]
_FAPI_JWT_PATH = ("client", "sessions", 0, "last_active_token", "jwt")


class ClerkConfigError(AuthConfigError):
    """Raised when required Clerk configuration is missing or FAPI is unreachable."""


@dataclass
class _AccountSession:
    """Per-account session state maintained by the adapter."""

    email: str
    password: str
    session_id: Optional[str] = None
    client_token: Optional[str] = None   # __client cookie value (prod) or equivalent
    jwt: Optional[str] = None
    jwt_exp: int = 0
    # Each account gets its own httpx.Client so cookie jars are isolated.
    http: httpx.Client = field(default_factory=httpx.Client)

    def close(self) -> None:
        try:
            self.http.close()
        except Exception:  # noqa: BLE001
            pass


def _extract_jwt_from_fapi_body(data: dict) -> Optional[str]:
    """Walk ``_FAPI_JWT_PATH`` in *data* and return the JWT string, or None."""
    obj = data
    for key in _FAPI_JWT_PATH:
        if isinstance(obj, dict):
            obj = obj.get(key)
        elif isinstance(obj, list):
            try:
                obj = obj[key]
            except (IndexError, TypeError):
                return None
        else:
            return None
    return obj if isinstance(obj, str) else None


class ClerkAuthAdapter(AbstractAuthAdapter):
    """Clerk implementation of :class:`AbstractAuthAdapter` using FAPI sign-in.

    Args:
        fapi_host: Clerk Frontend API host, e.g.
            ``https://clerk.example.com`` or
            ``https://your-app.clerk.accounts.dev``.
            Must include the scheme; must NOT have a trailing slash.
        accounts: Mapping of account name to credentials dict, e.g.::

                {
                    "user_a": {"email": "a@example.com", "password": "s3cr3t"},
                    "user_b": {"email": "b@example.com", "password": "s3cr3t"},
                }

        target_origin: If provided, sent as the ``Origin`` header on all FAPI
            requests.  Clerk validates ``Origin`` on some endpoints in
            production; pass the app's base URL (e.g.
            ``https://example.com``).
    """

    def __init__(
        self,
        fapi_host: str,
        accounts: dict[str, dict],
        target_origin: Optional[str] = None,
    ) -> None:
        self._fapi_host = fapi_host.rstrip("/")
        self._target_origin = target_origin
        self._is_dev = ".clerk.accounts.dev" in fapi_host

        # Validate provided account names.
        for name in accounts:
            if name not in _ACCOUNT_ENV_PREFIX:
                raise ValueError(
                    f"Unknown account '{name}'. "
                    f"Valid options: {sorted(_ACCOUNT_ENV_PREFIX)}"
                )

        self._sessions: dict[str, _AccountSession] = {
            name: _AccountSession(
                email=creds["email"],
                password=creds["password"],
            )
            for name, creds in accounts.items()
        }

    # ------------------------------------------------------------------
    # AbstractAuthAdapter implementation
    # ------------------------------------------------------------------

    def get_token(self, account_name: str) -> str:
        """Return a valid Bearer token, refreshing if near-expiry."""
        self._validate_account(account_name)
        session = self._sessions[account_name]
        if session.jwt is None or self.is_expired(account_name):
            if session.session_id is None:
                self._sign_in(account_name)
            else:
                self._refresh_token(account_name)
        assert session.jwt is not None  # guaranteed by _sign_in / _refresh_token
        return session.jwt

    def get_headers(self, account_name: str) -> dict:
        """Return ``{"Authorization": "Bearer <token>"}`` ready for httpx."""
        token = self.get_token(account_name)
        return {"Authorization": f"Bearer {token}"}

    def is_expired(self, account_name: str) -> bool:
        """Return True if the token is missing, expired, or within the refresh window."""
        self._validate_account(account_name)
        session = self._sessions[account_name]
        if session.jwt is None:
            return True
        remaining = session.jwt_exp - time.time()
        return remaining <= REFRESH_WINDOW_SECONDS

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close all per-account httpx clients."""
        for session in self._sessions.values():
            session.close()

    def __enter__(self) -> "ClerkAuthAdapter":
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

    def _base_headers(self) -> dict[str, str]:
        """Headers included on every FAPI request."""
        headers: dict[str, str] = {}
        if self._target_origin:
            headers["Origin"] = self._target_origin
        return headers

    def _sign_in(self, account_name: str) -> None:
        """Sign in via FAPI and populate the session with JWT + session_id."""
        session = self._sessions[account_name]
        url = f"{self._fapi_host}/v1/client/sign_ins"
        payload = {
            "identifier": session.email,
            "strategy": "password",
            "password": session.password,
        }
        headers = self._base_headers()

        try:
            resp = session.http.post(
                url,
                data=payload,
                headers=headers,
                timeout=20.0,
            )
        except httpx.TransportError as exc:
            logger.warning(
                "FAPI unreachable for '%s' (%s): %s. Trying env-var fallback.",
                account_name,
                session.email,
                exc,
            )
            self._apply_fallback_jwt(account_name)
            return

        if resp.status_code in (403, 429):
            logger.warning(
                "FAPI returned %s for '%s' — possible bot detection. "
                "Trying env-var JWT fallback.",
                resp.status_code,
                account_name,
            )
            self._apply_fallback_jwt(account_name)
            return

        if resp.status_code != 200:
            # Attempt to surface a clear error for wrong password etc.
            self._raise_sign_in_error(account_name, session.email, resp)

        data = resp.json()

        # Check for MFA requirement before attempting to extract JWT.
        response_status = data.get("response", {}).get("status") or data.get("status")
        if response_status == "needs_second_factor":
            raise ClerkConfigError(
                f"MFA (second factor) is required for '{account_name}' ({session.email}). "
                "Disable MFA on this test account in the Clerk dashboard, or use "
                "TOTP/SMS to complete sign-in manually and export a JWT via "
                "PENTEST_USER_A_JWT / PENTEST_USER_B_JWT env vars."
            )

        jwt_value = _extract_jwt_from_fapi_body(data)
        if not jwt_value:
            raise RuntimeError(
                f"FAPI sign-in for '{account_name}' succeeded (HTTP 200) but JWT "
                f"was not found at the expected path. Response: {resp.text[:400]}"
            )

        # Extract session_id.
        session_id = self._extract_session_id(data)
        if not session_id:
            raise RuntimeError(
                f"FAPI sign-in for '{account_name}' succeeded but session_id "
                f"could not be resolved. Response: {resp.text[:400]}"
            )

        session.session_id = session_id
        self._store_jwt(session, jwt_value)

    def _refresh_token(self, account_name: str) -> None:
        """Refresh the session token via FAPI and update the session cache."""
        session = self._sessions[account_name]
        if not session.session_id:
            # No session yet — fall back to full sign-in.
            self._sign_in(account_name)
            return

        url = f"{self._fapi_host}/v1/client/sessions/{session.session_id}/tokens"
        headers = self._base_headers()
        max_retries = 3

        for attempt in range(max_retries):
            try:
                resp = session.http.post(url, headers=headers, timeout=15.0)
                if resp.status_code == 200:
                    break
                elif resp.status_code in (403, 429):
                    # Rate-limited or bot-detected during refresh — try env fallback.
                    logger.warning(
                        "FAPI token refresh returned %s for '%s' — trying env-var fallback.",
                        resp.status_code,
                        account_name,
                    )
                    self._apply_fallback_jwt(account_name)
                    return
                elif resp.status_code >= 500 and attempt < max_retries - 1:
                    time.sleep(2 ** (attempt + 1))
                    continue
                else:
                    raise RuntimeError(
                        f"FAPI token refresh failed for '{account_name}': "
                        f"HTTP {resp.status_code} — {resp.text[:200]}"
                    )
            except httpx.TransportError as exc:
                if attempt < max_retries - 1:
                    time.sleep(2 ** (attempt + 1))
                    continue
                # Transport failure — try env fallback before raising.
                logger.warning(
                    "FAPI token refresh unreachable for '%s': %s. Trying env-var fallback.",
                    account_name,
                    exc,
                )
                self._apply_fallback_jwt(account_name)
                return
        else:
            raise RuntimeError(
                f"FAPI token refresh failed after {max_retries} attempts "
                f"for '{account_name}'."
            )

        data = resp.json()
        jwt_value = _extract_jwt_from_fapi_body(data)
        if not jwt_value:
            # Some Clerk versions return the JWT directly in {"jwt": "..."}.
            jwt_value = data.get("jwt")
        if not jwt_value:
            raise RuntimeError(
                f"FAPI token refresh response missing JWT for '{account_name}': "
                f"{resp.text[:200]}"
            )
        self._store_jwt(session, jwt_value)

    def _store_jwt(self, session: _AccountSession, jwt_value: str) -> None:
        """Decode ``jwt_value``, store it on *session*, and update expiry."""
        exp = self._decode_exp(jwt_value)
        session.jwt = jwt_value
        session.jwt_exp = exp

    @staticmethod
    def _extract_session_id(data: dict) -> Optional[str]:
        """Extract session_id from a FAPI sign-in response."""
        # Top-level ``created_session_id`` field (common pattern).
        sid = data.get("created_session_id")
        if sid:
            return str(sid)
        # Nested under ``response``.
        response_obj = data.get("response") or {}
        sid = response_obj.get("created_session_id")
        if sid:
            return str(sid)
        # Nested in client.sessions[0].id.
        try:
            return str(data["client"]["sessions"][0]["id"])
        except (KeyError, IndexError, TypeError):
            pass
        return None

    def _raise_sign_in_error(
        self, account_name: str, email: str, resp: httpx.Response
    ) -> None:
        """Parse the FAPI error response and raise a descriptive exception."""
        try:
            data = resp.json()
            errors = data.get("errors") or []
            if errors:
                codes = [e.get("code", "") for e in errors]
                messages = [e.get("long_message") or e.get("message", "") for e in errors]
                error_summary = "; ".join(
                    f"{c}: {m}" for c, m in zip(codes, messages) if c or m
                )
                if any("password" in c or "invalid" in c for c in codes):
                    raise ClerkConfigError(
                        f"FAPI sign-in failed for '{account_name}' ({email}): "
                        f"wrong password or invalid credentials. "
                        f"Clerk error(s): {error_summary}"
                    )
                raise ClerkConfigError(
                    f"FAPI sign-in failed for '{account_name}' ({email}): "
                    f"{error_summary} (HTTP {resp.status_code})"
                )
        except (ValueError, KeyError):
            pass

        raise ClerkConfigError(
            f"FAPI sign-in failed for '{account_name}' ({email}): "
            f"HTTP {resp.status_code} — {resp.text[:300]}"
        )

    def _apply_fallback_jwt(self, account_name: str) -> None:
        """Load JWT from env var fallback when FAPI is unavailable."""
        prefix = _ACCOUNT_ENV_PREFIX[account_name]
        jwt_env_var = f"{prefix}_JWT"
        raw_token = os.environ.get(jwt_env_var)
        if not raw_token:
            raise ClerkConfigError(
                f"FAPI is unreachable and env var '{jwt_env_var}' is not set. "
                "Either ensure FAPI is accessible or export a pre-obtained JWT "
                f"via {jwt_env_var}. "
                "Note: CLERK_SECRET_KEY is not required by this adapter."
            )
        warnings.warn(
            f"Using env-var JWT fallback for '{account_name}' ({jwt_env_var}). "
            "FAPI sign-in was unavailable.",
            stacklevel=3,
        )
        session = self._sessions[account_name]
        exp = self._decode_exp(raw_token)
        session.jwt = raw_token
        session.jwt_exp = exp

    @staticmethod
    def _decode_exp(token: str) -> int:
        """Decode JWT without verification and return the ``exp`` claim.

        Raises:
            RuntimeError: If ``exp`` is missing or the token cannot be decoded.
        """
        try:
            payload = pyjwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=["RS256", "HS256"],
            )
        except pyjwt.DecodeError as exc:
            raise RuntimeError(f"Could not decode JWT: {exc}") from exc

        exp = payload.get("exp")
        if exp is None:
            raise RuntimeError("JWT payload is missing the 'exp' claim.")
        return int(exp)
