"""Unit tests for the Firebase Identity Toolkit auth adapter.

All network calls are mocked via monkeypatching on httpx.Client.post —
no real HTTP requests are made.

Test coverage
-------------
Happy paths:
  - Sign in with valid email+password: idToken and refreshToken extracted.
  - get_headers returns Bearer authorization header.
  - Token refresh returns new id_token (NOT access_token).
  - Cached token returned when not near expiry.
  - Refresh triggered when token is within 10s of expiry.

Error paths:
  - MFA pending credential: MFARequiredError raised.
  - App Check enforced (403 + attestation): AppCheckEnforcedError raised.
  - Refresh retry on 500: retries 3x then raises.

Edge cases:
  - _FirebaseSession.__repr__ and __str__ do not contain password or refresh_token.
  - Adapter factory returns FirebaseAuthAdapter for firebase profile.
  - Refresh reads ``id_token`` field, not ``access_token``.
"""

from __future__ import annotations

import base64
import json
import sys
import time
import unittest.mock as mock
from pathlib import Path
from types import SimpleNamespace

import pytest

# ---------------------------------------------------------------------------
# Ensure the StackBadger package root is importable.
# ---------------------------------------------------------------------------
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

import httpx

from auth.firebase import (
    AppCheckEnforcedError,
    FirebaseAuthAdapter,
    MFARequiredError,
    REFRESH_WINDOW_SECONDS,
    _FirebaseSession,
)
from auth.base import AuthConfigError


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _make_jwt(sub: str = "firebase_user_001", exp_offset: int = 60) -> str:
    """Build a minimal unsigned JWT with ``sub`` and ``exp`` claims.

    The token is not cryptographically signed — it uses the ``none`` algorithm,
    which pyjwt decodes with ``verify_signature=False``.
    """
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    exp = int(time.time()) + exp_offset
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": sub, "exp": exp}).encode()
    ).rstrip(b"=").decode()

    sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


def _make_expired_jwt(sub: str = "firebase_user_001") -> str:
    """Build a JWT that expired 120 seconds ago."""
    return _make_jwt(sub=sub, exp_offset=-120)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _sign_in_response(id_token: str, refresh_token: str = "rt_abc123") -> dict:
    """Minimal Firebase Identity Toolkit sign-in response."""
    return {
        "idToken": id_token,
        "refreshToken": refresh_token,
        "expiresIn": "3600",
        "localId": "uid_test_123",
        "email": "a@example.com",
        "registered": True,
    }


def _refresh_response(id_token: str) -> dict:
    """Minimal Firebase Secure Token API refresh response.

    Note: the field is ``id_token``, NOT ``access_token``.
    """
    return {
        "id_token": id_token,
        "refresh_token": "rt_abc123",
        "expires_in": "3600",
        "token_type": "Bearer",
        "user_id": "uid_test_123",
        "project_id": "test-project",
    }


class _MockResponse:
    """Lightweight mock for httpx.Response."""

    def __init__(self, status_code: int, json_body: dict | None = None, text: str | None = None):
        self.status_code = status_code
        self._json_body = json_body or {}
        self.text = text if text is not None else json.dumps(self._json_body)
        self.content = self.text.encode()

    def json(self) -> dict:
        return self._json_body


# ---------------------------------------------------------------------------
# Fixtures / constants
# ---------------------------------------------------------------------------

API_KEY = "AIzaSyTestKey123"

ACCOUNTS = {
    "user_a": {"email": "a@example.com", "password": "pass_a"},
    "user_b": {"email": "b@example.com", "password": "pass_b"},
}


def _make_adapter(
    api_key: str = API_KEY,
    accounts: dict | None = None,
) -> FirebaseAuthAdapter:
    return FirebaseAuthAdapter(
        api_key=api_key,
        accounts=accounts or ACCOUNTS,
        target_origin="https://example.com",
    )


# ---------------------------------------------------------------------------
# Happy path: sign in
# ---------------------------------------------------------------------------

class TestSignIn:
    """Happy-path sign-in via Identity Toolkit."""

    def test_sign_in_success(self, monkeypatch):
        """get_token() signs in and returns the idToken."""
        jwt_val = _make_jwt(sub="user_a_firebase")
        resp = _MockResponse(200, _sign_in_response(jwt_val))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        token = adapter.get_token("user_a")
        assert token == jwt_val

    def test_get_headers_returns_bearer(self, monkeypatch):
        """get_headers() wraps the idToken in a Bearer Authorization header."""
        jwt_val = _make_jwt()
        resp = _MockResponse(200, _sign_in_response(jwt_val))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        headers = adapter.get_headers("user_a")
        assert headers == {"Authorization": f"Bearer {jwt_val}"}

    def test_sign_in_stores_refresh_token(self, monkeypatch):
        """After sign-in, refresh_token is stored on the session."""
        jwt_val = _make_jwt()
        resp = _MockResponse(200, _sign_in_response(jwt_val, refresh_token="rt_stored"))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        adapter.get_token("user_a")
        assert adapter._sessions["user_a"].refresh_token == "rt_stored"


# ---------------------------------------------------------------------------
# Happy path: expiry checks
# ---------------------------------------------------------------------------

class TestExpiry:
    """Token expiry detection."""

    def test_is_expired_false_when_far_from_expiry(self):
        """is_expired() returns False when exp is >10s in the future."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.id_token = _make_jwt(exp_offset=120)
        session.token_exp = int(time.time()) + 120
        assert adapter.is_expired("user_a") is False

    def test_is_expired_true_when_near_expiry(self):
        """is_expired() returns True when exp is <10s in the future."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.id_token = _make_jwt(exp_offset=REFRESH_WINDOW_SECONDS - 1)
        session.token_exp = int(time.time()) + REFRESH_WINDOW_SECONDS - 1
        assert adapter.is_expired("user_a") is True

    def test_is_expired_true_when_no_token(self):
        """is_expired() returns True when no id_token is present."""
        adapter = _make_adapter()
        assert adapter.is_expired("user_a") is True

    def test_near_expiry_triggers_refresh(self, monkeypatch):
        """get_token() refreshes when token is within the refresh window."""
        old_jwt = _make_jwt(exp_offset=5)
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.id_token = old_jwt
        session.refresh_token = "rt_for_refresh"
        session.token_exp = int(time.time()) + 5  # within window

        refresh_resp = _MockResponse(200, _refresh_response(new_jwt))
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: refresh_resp)

        token = adapter.get_token("user_a")
        assert token == new_jwt


# ---------------------------------------------------------------------------
# Happy path: token refresh
# ---------------------------------------------------------------------------

class TestTokenRefresh:
    """Token refresh via Secure Token API."""

    def test_refresh_returns_new_id_token(self, monkeypatch):
        """Refresh 200 with id_token field updates the adapter's cached token."""
        old_jwt = _make_jwt(exp_offset=5)
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.id_token = old_jwt
        session.refresh_token = "rt_existing"
        session.token_exp = int(time.time()) + 5

        refresh_resp = _MockResponse(200, _refresh_response(new_jwt))
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: refresh_resp)

        adapter.get_token("user_a")
        assert session.id_token == new_jwt
        assert session.token_exp > int(time.time()) + 50

    def test_refresh_reads_id_token_not_access_token(self, monkeypatch):
        """The refresh response field is ``id_token``, NOT ``access_token``."""
        new_jwt = _make_jwt(exp_offset=60)
        wrong_jwt = _make_jwt(sub="wrong_token", exp_offset=60)

        # Response has id_token (correct) and access_token (wrong field name).
        body = {
            "id_token": new_jwt,
            "access_token": wrong_jwt,
            "refresh_token": "rt_x",
            "expires_in": "3600",
        }

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.id_token = _make_jwt(exp_offset=5)
        session.refresh_token = "rt_existing"
        session.token_exp = int(time.time()) + 5

        refresh_resp = _MockResponse(200, body)
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: refresh_resp)

        token = adapter.get_token("user_a")
        # Must use id_token, not access_token.
        assert token == new_jwt
        assert token != wrong_jwt

    def test_refresh_stores_rotated_refresh_token(self, monkeypatch):
        """When Firebase rotates the refresh token, the adapter stores it."""
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.id_token = _make_jwt(exp_offset=5)
        session.refresh_token = "rt_original"
        session.token_exp = int(time.time()) + 5

        refresh_resp = _MockResponse(200, _refresh_response(new_jwt))
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: refresh_resp)

        adapter.get_token("user_a")
        # The rotated refresh_token from the response should be stored.
        assert session.refresh_token == "rt_abc123"

    def test_refresh_keeps_existing_when_absent(self, monkeypatch):
        """When the refresh response omits refresh_token, the existing one is kept."""
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.id_token = _make_jwt(exp_offset=5)
        session.refresh_token = "rt_original"
        session.token_exp = int(time.time()) + 5

        # Response without refresh_token field.
        body = {
            "id_token": new_jwt,
            "expires_in": "3600",
            "token_type": "Bearer",
            "user_id": "uid_test_123",
            "project_id": "test-project",
        }
        refresh_resp = _MockResponse(200, body)
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: refresh_resp)

        adapter.get_token("user_a")
        # The original refresh_token should be preserved.
        assert session.refresh_token == "rt_original"


# ---------------------------------------------------------------------------
# Error path: MFA
# ---------------------------------------------------------------------------

class TestMFA:
    """MFA pending credential detection."""

    def test_mfa_pending_credential_raises(self, monkeypatch):
        """Response with mfaPendingCredential raises MFARequiredError."""
        # The env-var JWT fallback must be absent for the MFA error to surface
        # rather than being satisfied by a pre-obtained token.
        monkeypatch.delenv("PENTEST_USER_A_JWT", raising=False)
        mfa_body = {
            "mfaPendingCredential": "pending_cred_abc123",
            "mfaInfo": [{"mfaEnrollmentId": "enroll_123"}],
        }
        resp = _MockResponse(200, mfa_body)

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        with pytest.raises(MFARequiredError) as exc_info:
            adapter.get_token("user_a")

        msg = str(exc_info.value)
        assert "MFA" in msg
        assert "user_a" in msg
        assert "a@example.com" in msg


# ---------------------------------------------------------------------------
# Error path: App Check
# ---------------------------------------------------------------------------

class TestAppCheck:
    """App Check enforcement detection."""

    def test_app_check_enforced_raises(self, monkeypatch):
        """403 + 'App attestation failed' raises AppCheckEnforcedError."""
        # The env-var JWT fallback must be absent for the App Check error to
        # surface rather than being satisfied by a pre-obtained token.
        monkeypatch.delenv("PENTEST_USER_A_JWT", raising=False)
        resp = _MockResponse(
            403,
            json_body={},
            text="App attestation failed: UNAUTHORIZED",
        )

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        with pytest.raises(AppCheckEnforcedError) as exc_info:
            adapter.get_token("user_a")

        msg = str(exc_info.value)
        assert "App Check" in msg
        assert "user_a" in msg

    def test_403_without_attestation_is_generic_error(self, monkeypatch):
        """403 without attestation text raises generic AuthConfigError."""
        resp = _MockResponse(403, json_body={}, text="Forbidden")

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        with pytest.raises(AuthConfigError) as exc_info:
            adapter.get_token("user_a")

        # Should NOT be AppCheckEnforcedError.
        assert not isinstance(exc_info.value, AppCheckEnforcedError)


# ---------------------------------------------------------------------------
# Error path: refresh retry on 500
# ---------------------------------------------------------------------------

class TestRefreshRetry:
    """Retry logic on refresh 5xx responses."""

    def test_refresh_retry_on_500(self, monkeypatch):
        """500 on refresh retries 3x then raises RuntimeError."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.id_token = _make_jwt(exp_offset=5)
        session.refresh_token = "rt_retry"
        session.token_exp = int(time.time()) + 5

        call_count = 0
        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return _MockResponse(500, json_body={}, text="Internal Server Error")

        monkeypatch.setattr(adapter._http, "post", mock_post)
        # Patch time.sleep to avoid actual delays in tests.
        monkeypatch.setattr(time, "sleep", lambda _: None)

        with pytest.raises(RuntimeError, match="failed after 3 attempts"):
            adapter.get_token("user_a")

        assert call_count == 3

    def test_refresh_succeeds_after_transient_500(self, monkeypatch):
        """500 on first attempt, 200 on second — token updated."""
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.id_token = _make_jwt(exp_offset=5)
        session.refresh_token = "rt_retry"
        session.token_exp = int(time.time()) + 5

        call_count = 0
        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _MockResponse(500, json_body={}, text="Internal Server Error")
            return _MockResponse(200, _refresh_response(new_jwt))

        monkeypatch.setattr(adapter._http, "post", mock_post)
        monkeypatch.setattr(time, "sleep", lambda _: None)

        token = adapter.get_token("user_a")
        assert token == new_jwt
        assert call_count == 2


# ---------------------------------------------------------------------------
# Edge case: credential scrubbing
# ---------------------------------------------------------------------------

class TestCredentialScrubbing:
    """_FirebaseSession repr/str do not leak sensitive fields."""

    def test_repr_does_not_contain_password(self):
        """__repr__ of _FirebaseSession redacts password."""
        session = _FirebaseSession(
            email="test@example.com",
            password="super_secret_password",
            refresh_token="rt_secret_token_value",
        )
        repr_str = repr(session)
        assert "super_secret_password" not in repr_str
        assert "rt_secret_token_value" not in repr_str

    def test_str_does_not_contain_password(self):
        """__str__ of _FirebaseSession redacts password."""
        session = _FirebaseSession(
            email="test@example.com",
            password="super_secret_password",
            refresh_token="rt_secret_token_value",
        )
        str_str = str(session)
        assert "super_secret_password" not in str_str
        assert "rt_secret_token_value" not in str_str

    def test_repr_contains_email(self):
        """__repr__ still contains the email for debugging."""
        session = _FirebaseSession(
            email="debug@example.com",
            password="secret",
        )
        assert "debug@example.com" in repr(session)


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------

class TestAdapterFactory:
    """Factory registration in auth/__init__.py."""

    def test_factory_returns_firebase_adapter(self, monkeypatch):
        """create_adapter returns FirebaseAuthAdapter for firebase profile."""
        from auth import create_adapter

        monkeypatch.setenv("FIREBASE_API_KEY", "AIzaSyTest")
        monkeypatch.setenv("PENTEST_USER_A_EMAIL", "a@example.com")
        monkeypatch.setenv("PENTEST_USER_A_PASSWORD", "pass_a")

        # Build a minimal profile object with attribute access.
        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="firebase"),
            firebase=SimpleNamespace(api_key="AIzaSyProfile"),
            target=SimpleNamespace(base_url="https://example.com"),
        )

        adapter = create_adapter(profile)
        assert isinstance(adapter, FirebaseAuthAdapter)
        adapter.close()

    def test_factory_raises_without_api_key(self, monkeypatch):
        """create_adapter raises AuthConfigError when no API key is available."""
        from auth import create_adapter

        monkeypatch.delenv("FIREBASE_API_KEY", raising=False)
        monkeypatch.setenv("PENTEST_USER_A_EMAIL", "a@example.com")
        monkeypatch.setenv("PENTEST_USER_A_PASSWORD", "pass_a")

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="firebase"),
            firebase=None,
            target=SimpleNamespace(base_url="https://example.com"),
        )

        with pytest.raises(AuthConfigError, match="Firebase API key"):
            create_adapter(profile)

    def test_factory_raises_without_credentials(self, monkeypatch):
        """create_adapter raises AuthConfigError when no account credentials."""
        from auth import create_adapter

        monkeypatch.setenv("FIREBASE_API_KEY", "AIzaSyTest")
        monkeypatch.delenv("PENTEST_USER_A_EMAIL", raising=False)
        monkeypatch.delenv("PENTEST_USER_A_PASSWORD", raising=False)
        monkeypatch.delenv("PENTEST_USER_B_EMAIL", raising=False)
        monkeypatch.delenv("PENTEST_USER_B_PASSWORD", raising=False)

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="firebase"),
            firebase=SimpleNamespace(api_key="AIzaSyProfile"),
            target=SimpleNamespace(base_url="https://example.com"),
        )

        with pytest.raises(AuthConfigError, match="No test account credentials"):
            create_adapter(profile)


# ---------------------------------------------------------------------------
# Cleanup: close / context manager
# ---------------------------------------------------------------------------

class TestCleanup:
    """Adapter cleanup and context manager support."""

    def test_close_does_not_raise(self):
        """close() completes without error."""
        adapter = _make_adapter()
        adapter.close()  # should not raise

    def test_context_manager(self):
        """Adapter works as a context manager."""
        with _make_adapter() as adapter:
            assert isinstance(adapter, FirebaseAuthAdapter)
        # After exiting, close() should have been called (no assertion needed;
        # just verify it does not raise).

    def test_unknown_account_raises_value_error(self):
        """get_token() with unknown account name raises ValueError."""
        adapter = _make_adapter()
        with pytest.raises(ValueError, match="Unknown account"):
            adapter.get_token("user_z")
