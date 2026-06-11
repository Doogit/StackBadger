"""Firebase auth adapter for the pentest harness — Identity Toolkit REST API.

Token lifecycle
---------------
1. On first call for an account, signs in via Firebase Identity Toolkit:
   ``POST https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<API_KEY>``
   Body (JSON): ``{"email": ..., "password": ..., "returnSecureToken": true}``
2. Decodes the returned ``idToken`` JWT (without signature verification) to read ``exp``.
3. If the token is expired or within REFRESH_WINDOW_SECONDS of expiry, refreshes
   via the Secure Token API:
   ``POST https://securetoken.googleapis.com/v1/token?key=<API_KEY>``
   Form-encoded body: ``grant_type=refresh_token&refresh_token=<token>``
4. Firebase refresh tokens are NOT single-use — the original is cached and reused.

Hard-stop conditions
---------------------
- **MFA**: If the sign-in response contains ``mfaPendingCredential``, the adapter
  raises ``MFARequiredError``.  Firebase MFA cannot be completed via REST alone.
- **App Check**: If the sign-in/refresh returns HTTP 403 with "App attestation
  failed" in the body, the adapter raises ``AppCheckEnforcedError``.  The target
  enforces App Check which blocks headless API callers.

Environment variables
---------------------
- ``FIREBASE_API_KEY``      — Firebase Web API key (fallback if not in profile)
- ``PENTEST_USER_A_EMAIL``  — email for user_a
- ``PENTEST_USER_A_PASSWORD`` — password for user_a
- ``PENTEST_USER_B_EMAIL``  — email for user_b (optional)
- ``PENTEST_USER_B_PASSWORD`` — password for user_b (optional)
- ``PENTEST_USER_A_JWT``   — pre-obtained JWT fallback for user_a (when MFA/App Check blocks REST)
- ``PENTEST_USER_B_JWT``   — pre-obtained JWT fallback for user_b (optional)
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

# Firebase REST endpoints.
_IDENTITY_TOOLKIT_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
_SECURE_TOKEN_URL = "https://securetoken.googleapis.com/v1/token"

# Retry config for refresh calls.
_MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class MFARequiredError(AuthConfigError):
    """Raised when Firebase sign-in returns an MFA pending credential.

    Firebase MFA (multi-factor authentication) requires a second factor
    verification step that cannot be completed via the REST API alone.
    The test account must have MFA disabled, or the operator must supply
    a pre-obtained JWT via env vars.
    """


class AppCheckEnforcedError(AuthConfigError):
    """Raised when Firebase App Check blocks the authentication request.

    App Check enforcement means the target requires device attestation
    (SafetyNet / reCAPTCHA Enterprise / etc.) which headless pentest
    callers cannot provide.  The target's Firebase project must allow
    unenforced access for the test API key, or the operator must supply
    a pre-obtained JWT.
    """


# ---------------------------------------------------------------------------
# Session dataclass
# ---------------------------------------------------------------------------

@dataclass
class _FirebaseSession:
    """Per-account session state maintained by the Firebase adapter."""

    email: str
    password: str = field(repr=False)
    id_token: Optional[str] = None
    refresh_token: Optional[str] = field(default=None, repr=False)
    token_exp: int = 0

    def __str__(self) -> str:
        return (
            f"_FirebaseSession(email={self.email!r}, "
            f"password='***', "
            f"id_token={'<set>' if self.id_token else None}, "
            f"refresh_token={'<set>' if self.refresh_token else None}, "
            f"token_exp={self.token_exp})"
        )

    def __repr__(self) -> str:
        return self.__str__()


# ---------------------------------------------------------------------------
# Adapter implementation
# ---------------------------------------------------------------------------

class FirebaseAuthAdapter(AbstractAuthAdapter):
    """Firebase implementation of :class:`AbstractAuthAdapter` using Identity Toolkit.

    Args:
        api_key: Firebase Web API key (from profile.firebase.api_key or
            env var FIREBASE_API_KEY).
        accounts: Mapping of account name to credentials dict, e.g.::

                {
                    "user_a": {"email": "a@example.com", "password": "s3cr3t"},
                    "user_b": {"email": "b@example.com", "password": "s3cr3t"},
                }

        target_origin: If provided, sent as the ``Origin`` header on all
            requests.
    """

    def __init__(
        self,
        api_key: str,
        accounts: dict[str, dict],
        target_origin: str | None = None,
    ) -> None:
        self._api_key = api_key
        self._target_origin = target_origin
        self._http = httpx.Client()

        self._sessions: dict[str, _FirebaseSession] = {
            name: _FirebaseSession(
                email=creds["email"],
                password=creds["password"],
            )
            for name, creds in accounts.items()
        }

    # ------------------------------------------------------------------
    # AbstractAuthAdapter implementation
    # ------------------------------------------------------------------

    def get_token(self, account_name: str) -> str:
        """Return a valid idToken JWT, signing in or refreshing as needed.

        Falls back to ``PENTEST_USER_{NAME}_JWT`` env var when sign-in/refresh
        is unavailable (MFA enabled, App Check enforced).
        """
        self._validate_account(account_name)
        session = self._sessions[account_name]
        if session.id_token is None or self.is_expired(account_name):
            if session.refresh_token is None:
                try:
                    self._sign_in(account_name)
                except (MFARequiredError, AppCheckEnforcedError) as exc:
                    self._apply_fallback_jwt(account_name, blocking_error=exc)
            else:
                try:
                    self._refresh_token(account_name)
                except AppCheckEnforcedError as exc:
                    self._apply_fallback_jwt(account_name, blocking_error=exc)
        assert session.id_token is not None
        return session.id_token

    def get_headers(self, account_name: str) -> dict:
        """Return ``{"Authorization": "Bearer <idToken>"}`` ready for httpx."""
        token = self.get_token(account_name)
        return {"Authorization": f"Bearer {token}"}

    def is_expired(self, account_name: str) -> bool:
        """Return True if the token is missing, expired, or within the refresh window."""
        self._validate_account(account_name)
        session = self._sessions[account_name]
        if session.id_token is None:
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

    def __enter__(self) -> "FirebaseAuthAdapter":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    # Account name -> env var prefix mapping.
    _ACCOUNT_ENV_PREFIX: dict[str, str] = {
        "user_a": "PENTEST_USER_A",
        "user_b": "PENTEST_USER_B",
    }

    def _apply_fallback_jwt(
        self,
        account_name: str,
        blocking_error: AuthConfigError | None = None,
    ) -> None:
        """Load JWT from env var fallback when REST auth is blocked (MFA/App Check).

        When the fallback env var is not set, re-raise the original blocking
        error (``MFARequiredError`` / ``AppCheckEnforcedError``) so callers see
        the specific cause rather than a generic config error.
        """
        prefix = self._ACCOUNT_ENV_PREFIX.get(account_name, f"PENTEST_{account_name.upper()}")
        jwt_env_var = f"{prefix}_JWT"
        raw_token = os.environ.get(jwt_env_var)
        if not raw_token:
            if blocking_error is not None:
                raise blocking_error
            raise AuthConfigError(
                f"Firebase REST auth is blocked for '{account_name}' and env var "
                f"'{jwt_env_var}' is not set. Either disable MFA/App Check on this "
                f"test account or export a pre-obtained JWT via {jwt_env_var}."
            )
        warnings.warn(
            f"Using env-var JWT fallback for '{account_name}' ({jwt_env_var}). "
            "Firebase REST sign-in was blocked by MFA or App Check.",
            stacklevel=3,
        )
        session = self._sessions[account_name]
        session.id_token = raw_token
        session.token_exp = self._decode_exp(raw_token)

    def _validate_account(self, account_name: str) -> None:
        if account_name not in self._sessions:
            raise ValueError(
                f"Unknown account '{account_name}'. "
                f"Valid options: {sorted(self._sessions)}"
            )

    def _base_headers(self) -> dict[str, str]:
        """Headers included on every request."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._target_origin:
            headers["Origin"] = self._target_origin
        return headers

    def _sign_in(self, account_name: str) -> None:
        """Sign in via Identity Toolkit and populate the session."""
        session = self._sessions[account_name]
        url = f"{_IDENTITY_TOOLKIT_URL}?key={self._api_key}"
        payload = {
            "email": session.email,
            "password": session.password,
            "returnSecureToken": True,
        }

        try:
            resp = self._http.post(
                url,
                json=payload,
                headers=self._base_headers(),
                timeout=20.0,
            )
        except httpx.HTTPError:
            raise RuntimeError(
                f"Firebase sign-in request failed for '{account_name}' "
                f"({session.email}): network error"
            ) from None

        # App Check detection: 403 + attestation failure.
        if resp.status_code == 403:
            _app_check_detected = False
            try:
                _err_data = resp.json()
                _err_obj = _err_data.get("error", {})
                _err_msg = (
                    _err_obj.get("message", "")
                    if isinstance(_err_obj, dict)
                    else str(_err_obj)
                )
                if "APP_CHECK" in _err_msg.upper() or "app attestation" in _err_msg.lower():
                    _app_check_detected = True
            except (ValueError, AttributeError):
                pass
            if not _app_check_detected:
                body_text = self._safe_response_text(resp)
                if "app attestation" in body_text.lower():
                    _app_check_detected = True
            if _app_check_detected:
                raise AppCheckEnforcedError(
                    f"Firebase App Check is enforced for '{account_name}' "
                    f"({session.email}). The target requires device attestation "
                    "which headless pentest callers cannot provide. "
                    "Disable App Check enforcement for this API key or supply "
                    "a pre-obtained JWT."
                )

        if resp.status_code != 200:
            try:
                _err_data = resp.json()
                _err_obj = _err_data.get("error", {})
                _err_msg = (
                    _err_obj.get("message", "")
                    if isinstance(_err_obj, dict)
                    else str(_err_obj)
                )
            except (ValueError, AttributeError):
                _err_msg = ""
            detail = _err_msg or f"HTTP {resp.status_code}"
            raise AuthConfigError(
                f"Firebase sign-in failed for '{account_name}' ({session.email}): "
                f"{detail}"
            )

        data = resp.json()

        # MFA detection: mfaPendingCredential in response.
        if data.get("mfaPendingCredential"):
            raise MFARequiredError(
                f"MFA is required for '{account_name}' ({session.email}). "
                "Firebase MFA cannot be completed via the REST API alone. "
                "Disable MFA on this test account in the Firebase console, "
                "or supply a pre-obtained JWT via env vars."
            )

        id_token = data.get("idToken")
        refresh_token = data.get("refreshToken")
        if not id_token:
            raise RuntimeError(
                f"Firebase sign-in for '{account_name}' succeeded (HTTP 200) "
                f"but idToken was not found in response."
            )

        session.id_token = id_token
        session.refresh_token = refresh_token or None
        session.token_exp = self._decode_exp(id_token)

    def _refresh_token(self, account_name: str) -> None:
        """Refresh the id token via the Secure Token API."""
        session = self._sessions[account_name]
        url = f"{_SECURE_TOKEN_URL}?key={self._api_key}"
        form_data = {
            "grant_type": "refresh_token",
            "refresh_token": session.refresh_token,
        }
        headers: dict[str, str] = {}
        if self._target_origin:
            headers["Origin"] = self._target_origin

        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = self._http.post(
                    url,
                    data=form_data,
                    headers=headers,
                    timeout=15.0,
                )
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise RuntimeError(
                    f"Firebase token refresh failed for '{account_name}': "
                    f"network error after {_MAX_RETRIES} attempts"
                ) from None

            # App Check detection on refresh.
            if resp.status_code == 403:
                _app_check_detected = False
                try:
                    _err_data = resp.json()
                    _err_obj = _err_data.get("error", {})
                    _err_msg = (
                        _err_obj.get("message", "")
                        if isinstance(_err_obj, dict)
                        else str(_err_obj)
                    )
                    if "APP_CHECK" in _err_msg.upper() or "app attestation" in _err_msg.lower():
                        _app_check_detected = True
                except (ValueError, AttributeError):
                    pass
                if not _app_check_detected:
                    body_text = self._safe_response_text(resp)
                    if "app attestation" in body_text.lower():
                        _app_check_detected = True
                if _app_check_detected:
                    raise AppCheckEnforcedError(
                        f"Firebase App Check blocked token refresh for "
                        f"'{account_name}' ({session.email})."
                    )

            if resp.status_code == 200:
                break

            if resp.status_code >= 500:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(2 ** (attempt + 1))
                    continue
                # Last attempt — fall through to for-else.
                continue

            # Non-5xx, non-200 error — fail immediately.
            try:
                _err_data = resp.json()
                _err_obj = _err_data.get("error", {})
                _err_msg = (
                    _err_obj.get("message", "")
                    if isinstance(_err_obj, dict)
                    else str(_err_obj)
                )
            except (ValueError, AttributeError):
                _err_msg = ""
            detail = _err_msg or f"HTTP {resp.status_code}"
            raise RuntimeError(
                f"Firebase token refresh failed for '{account_name}': {detail}"
            )
        else:
            raise RuntimeError(
                f"Firebase token refresh failed after {_MAX_RETRIES} attempts "
                f"for '{account_name}'."
            )

        data = resp.json()

        # Firebase Secure Token API returns ``id_token``, NOT ``access_token``.
        new_id_token = data.get("id_token")
        if not new_id_token:
            raise RuntimeError(
                f"Firebase token refresh response missing 'id_token' field "
                f"for '{account_name}'. Keys present: {list(data.keys())}"
            )

        session.id_token = new_id_token
        # Firebase may rotate the refresh token. Store the new one when
        # present; fall back to the existing token when absent.
        new_refresh_token = data.get("refresh_token")
        if new_refresh_token:
            session.refresh_token = new_refresh_token
        session.token_exp = self._decode_exp(new_id_token)

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
                algorithms=["RS256", "ES256"],
            )
        except pyjwt.DecodeError as exc:
            raise RuntimeError(f"Could not decode JWT: {exc}") from exc

        exp = payload.get("exp")
        if exp is None:
            raise RuntimeError("JWT payload is missing the 'exp' claim.")
        return int(exp)

    @staticmethod
    def _safe_response_text(resp: httpx.Response) -> str:
        """Extract response text, guarding against encoding issues.

        Prevents raw credentials or tokens from leaking via httpx exception
        messages by returning only the response body text.
        """
        try:
            return resp.text
        except Exception:  # noqa: BLE001
            return "<unreadable response body>"
