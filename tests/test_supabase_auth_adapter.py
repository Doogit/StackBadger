"""Unit tests for the Supabase GoTrue auth adapter.

All network calls are mocked via monkeypatching on httpx.Client.post —
no real HTTP requests are made.

Test coverage
-------------
Happy paths:
  - Sign in with valid email+password: access_token and refresh_token extracted.
  - get_headers returns both Authorization AND apikey (PostgREST requirement).
  - Token refresh returns new access_token and updates session.
  - Cached token returned when not near expiry.
  - Refresh triggered when token is within 10s of expiry.

Error paths:
  - CAPTCHA enforced (400 + "captcha"): CaptchaEnforcedError raised.
  - Generic 400 without CAPTCHA: AuthConfigError raised.
  - Config error when project_url is missing.
  - Config error when anon_key is missing.

Edge cases:
  - AAL1 token: adapter emits a warning (no exception).
  - Token expiry detection works for both HS256 and ES256 algorithm headers.
  - _SupabaseSession __repr__ / __str__ do not expose password or refresh_token.
  - Factory returns SupabaseAuthAdapter for "supabase-auth" profile.
"""

from __future__ import annotations

import base64
import json
import logging
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

from auth.supabase_auth import (
    CaptchaEnforcedError,
    REFRESH_WINDOW_SECONDS,
    RefreshTokenRejected,
    SupabaseAuthAdapter,
    _SupabaseSession,
)
from auth.base import AuthConfigError


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _make_jwt(
    sub: str = "supabase_user_001",
    exp_offset: int = 60,
    alg: str = "HS256",
    aal: str | None = None,
) -> str:
    """Build a minimal unsigned JWT with ``sub``, ``exp``, and optional ``aal`` claims.

    The token is not cryptographically signed — pyjwt decodes it with
    ``verify_signature=False``.
    """
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": alg, "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    exp = int(time.time()) + exp_offset
    claims: dict = {"sub": sub, "exp": exp}
    if aal is not None:
        claims["aal"] = aal

    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode()
    ).rstrip(b"=").decode()

    sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


def _make_expired_jwt(sub: str = "supabase_user_001") -> str:
    """Build a JWT that expired 120 seconds ago."""
    return _make_jwt(sub=sub, exp_offset=-120)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _sign_in_response(
    access_token: str,
    refresh_token: str = "rt_supa_abc123",
    expires_in: int = 3600,
) -> dict:
    """Minimal GoTrue password-grant sign-in response."""
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "token_type": "bearer",
        "user": {"id": "uid-test-001", "email": "a@example.com"},
    }


def _refresh_response(access_token: str, refresh_token: str = "rt_supa_new456") -> dict:
    """Minimal GoTrue refresh_token grant response."""
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": 3600,
        "token_type": "bearer",
        "user": {"id": "uid-test-001", "email": "a@example.com"},
    }


class _MockResponse:
    """Lightweight mock for httpx.Response."""

    def __init__(
        self,
        status_code: int,
        json_body: dict | None = None,
        text: str | None = None,
    ):
        self.status_code = status_code
        self._json_body = json_body or {}
        self.text = text if text is not None else json.dumps(self._json_body)
        self.content = self.text.encode()

    def json(self) -> dict:
        return self._json_body


# ---------------------------------------------------------------------------
# Fixtures / constants
# ---------------------------------------------------------------------------

PROJECT_URL = "https://xyzxyz.supabase.co"
ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.fakeanonkey"

ACCOUNTS = {
    "user_a": {"email": "a@example.com", "password": "pass_a"},
    "user_b": {"email": "b@example.com", "password": "pass_b"},
}


def _make_adapter(
    project_url: str = PROJECT_URL,
    anon_key: str = ANON_KEY,
    accounts: dict | None = None,
) -> SupabaseAuthAdapter:
    return SupabaseAuthAdapter(
        project_url=project_url,
        anon_key=anon_key,
        accounts=accounts or ACCOUNTS,
    )


# ---------------------------------------------------------------------------
# Happy path: sign in
# ---------------------------------------------------------------------------

class TestSignIn:
    """Happy-path sign-in via GoTrue password grant."""

    def test_sign_in_success(self, monkeypatch):
        """get_token() signs in and returns the access_token."""
        jwt_val = _make_jwt(sub="user_a_supa")
        resp = _MockResponse(200, _sign_in_response(jwt_val))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        token = adapter.get_token("user_a")
        assert token == jwt_val

    def test_sign_in_stores_refresh_token(self, monkeypatch):
        """After sign-in, refresh_token is stored on the session."""
        jwt_val = _make_jwt()
        resp = _MockResponse(200, _sign_in_response(jwt_val, refresh_token="rt_stored"))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        adapter.get_token("user_a")
        assert adapter._sessions["user_a"].refresh_token == "rt_stored"

    def test_get_headers_has_both_headers(self, monkeypatch):
        """get_headers() includes both Authorization AND apikey."""
        jwt_val = _make_jwt()
        resp = _MockResponse(200, _sign_in_response(jwt_val))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        headers = adapter.get_headers("user_a")
        assert "Authorization" in headers
        assert headers["Authorization"] == f"Bearer {jwt_val}"
        assert "apikey" in headers
        assert headers["apikey"] == ANON_KEY

    def test_get_headers_does_not_omit_apikey(self, monkeypatch):
        """PostgREST requires apikey; verify it is never absent."""
        jwt_val = _make_jwt()
        resp = _MockResponse(200, _sign_in_response(jwt_val))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        headers = adapter.get_headers("user_a")
        # apikey must be present and non-empty.
        assert headers.get("apikey"), "apikey header must be non-empty"


# ---------------------------------------------------------------------------
# Happy path: token expiry detection
# ---------------------------------------------------------------------------

class TestTokenExpiry:
    """Token expiry detection for HS256 and ES256 algorithm headers."""

    def test_is_expired_false_when_far_from_expiry(self):
        """is_expired() returns False when exp is >10s in the future."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.access_token = _make_jwt(exp_offset=120)
        session.token_exp = int(time.time()) + 120
        assert adapter.is_expired("user_a") is False

    def test_is_expired_true_when_near_expiry(self):
        """is_expired() returns True when exp is <10s away."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.access_token = _make_jwt(exp_offset=REFRESH_WINDOW_SECONDS - 1)
        session.token_exp = int(time.time()) + REFRESH_WINDOW_SECONDS - 1
        assert adapter.is_expired("user_a") is True

    def test_is_expired_true_when_no_token(self):
        """is_expired() returns True when access_token is None."""
        adapter = _make_adapter()
        assert adapter.is_expired("user_a") is True

    def test_expiry_detection_hs256(self):
        """_decode_exp works on a JWT with HS256 algorithm header."""
        token = _make_jwt(alg="HS256", exp_offset=120)
        exp = SupabaseAuthAdapter._decode_exp(token)
        assert exp > int(time.time()) + 100

    def test_expiry_detection_es256(self):
        """_decode_exp works on a JWT with ES256 algorithm header."""
        token = _make_jwt(alg="ES256", exp_offset=120)
        exp = SupabaseAuthAdapter._decode_exp(token)
        assert exp > int(time.time()) + 100

    def test_near_expiry_triggers_refresh(self, monkeypatch):
        """get_token() refreshes automatically when within the window."""
        old_jwt = _make_jwt(exp_offset=5)
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.access_token = old_jwt
        session.refresh_token = "rt_for_refresh"
        session.token_exp = int(time.time()) + 5

        refresh_resp = _MockResponse(200, _refresh_response(new_jwt))
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: refresh_resp)

        token = adapter.get_token("user_a")
        assert token == new_jwt


# ---------------------------------------------------------------------------
# Happy path: token refresh
# ---------------------------------------------------------------------------

class TestTokenRefresh:
    """Token refresh via GoTrue refresh_token grant."""

    def test_refresh_returns_new_access_token(self, monkeypatch):
        """Refresh 200 with access_token updates the adapter's cached token."""
        old_jwt = _make_jwt(exp_offset=5)
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.access_token = old_jwt
        session.refresh_token = "rt_existing"
        session.token_exp = int(time.time()) + 5

        refresh_resp = _MockResponse(200, _refresh_response(new_jwt))
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: refresh_resp)

        adapter.get_token("user_a")
        assert session.access_token == new_jwt
        assert session.token_exp > int(time.time()) + 50

    def test_refresh_updates_refresh_token_on_rotation(self, monkeypatch):
        """When the server returns a new refresh_token, the adapter stores it."""
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.access_token = _make_jwt(exp_offset=5)
        session.refresh_token = "rt_old"
        session.token_exp = int(time.time()) + 5

        refresh_resp = _MockResponse(200, _refresh_response(new_jwt, refresh_token="rt_rotated"))
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: refresh_resp)

        adapter.get_token("user_a")
        assert session.refresh_token == "rt_rotated"

    def test_refresh_retry_on_500(self, monkeypatch):
        """500 on refresh retries 3x then raises RuntimeError."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.access_token = _make_jwt(exp_offset=5)
        session.refresh_token = "rt_retry"
        session.token_exp = int(time.time()) + 5

        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return _MockResponse(500, json_body={}, text="Internal Server Error")

        monkeypatch.setattr(adapter._http, "post", mock_post)
        monkeypatch.setattr(time, "sleep", lambda _: None)

        with pytest.raises(RuntimeError, match="failed after 3 attempts"):
            adapter.get_token("user_a")

        assert call_count == 3


# ---------------------------------------------------------------------------
# Refresh error classification: invalid-grant vs transient
# ---------------------------------------------------------------------------

class TestRefreshErrorClassification:
    """Narrowed RefreshTokenRejected: only explicit invalid-grant 400/401.

    Transient non-5xx statuses (408/429) must be retried like 5xx and then
    raise a plain RuntimeError — NOT discard the refresh token.
    """

    def _primed_adapter(self, monkeypatch):
        """Adapter with a near-expiry token and a refresh token set."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.access_token = _make_jwt(exp_offset=5)
        session.refresh_token = "rt_primed"
        session.token_exp = int(time.time()) + 5
        monkeypatch.setattr(time, "sleep", lambda _: None)
        return adapter, session

    def test_400_invalid_grant_rejects_and_falls_back_to_sign_in(self, monkeypatch):
        """400 invalid_grant -> RefreshTokenRejected -> sign-in fallback."""
        adapter, session = self._primed_adapter(monkeypatch)
        new_jwt = _make_jwt(exp_offset=60)

        calls = {"n": 0}

        def mock_post(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                # refresh_token grant -> rejected
                return _MockResponse(
                    400,
                    json_body={"error": "invalid_grant",
                               "error_description": "Invalid Refresh Token"},
                    text='{"error":"invalid_grant",'
                         '"error_description":"Invalid Refresh Token"}',
                )
            # password grant -> success
            return _MockResponse(200, _sign_in_response(new_jwt))

        monkeypatch.setattr(adapter._http, "post", mock_post)

        token = adapter.get_token("user_a")
        assert token == new_jwt
        # Old refresh token was discarded; sign-in supplied a fresh one.
        assert session.refresh_token == "rt_supa_abc123"
        assert calls["n"] == 2

    def test_401_invalid_refresh_token_text_body_rejects(self, monkeypatch):
        """401 with non-JSON 'invalid refresh token' body -> RefreshTokenRejected."""
        adapter, session = self._primed_adapter(monkeypatch)
        new_jwt = _make_jwt(exp_offset=60)

        calls = {"n": 0}

        def mock_post(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return _MockResponse(
                    401, json_body={}, text="invalid refresh token: not found"
                )
            return _MockResponse(200, _sign_in_response(new_jwt))

        monkeypatch.setattr(adapter._http, "post", mock_post)

        token = adapter.get_token("user_a")
        assert token == new_jwt
        assert calls["n"] == 2

    def test_400_unparseable_body_conservative_reject(self, monkeypatch):
        """400 with unparseable body still maps to RefreshTokenRejected."""
        adapter, session = self._primed_adapter(monkeypatch)
        new_jwt = _make_jwt(exp_offset=60)

        calls = {"n": 0}

        def mock_post(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return _MockResponse(400, json_body={}, text="<html>Bad Request</html>")
            return _MockResponse(200, _sign_in_response(new_jwt))

        monkeypatch.setattr(adapter._http, "post", mock_post)

        token = adapter.get_token("user_a")
        assert token == new_jwt
        assert calls["n"] == 2

    def test_429_retried_then_runtime_error_no_sign_in_fallback(self, monkeypatch):
        """429 retries _MAX_RETRIES then plain RuntimeError; token preserved."""
        adapter, session = self._primed_adapter(monkeypatch)

        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return _MockResponse(
                429, json_body={"error": "rate limit exceeded"},
                text='{"error":"rate limit exceeded"}',
            )

        monkeypatch.setattr(adapter._http, "post", mock_post)

        with pytest.raises(RuntimeError) as exc_info:
            adapter.get_token("user_a")

        # Plain RuntimeError, NOT the RefreshTokenRejected subtype.
        assert not isinstance(exc_info.value, RefreshTokenRejected)
        assert "failed after 3 attempts" in str(exc_info.value)
        # Retried exactly _MAX_RETRIES times — no extra password sign-in call.
        assert call_count == 3
        # Refresh token must NOT be nulled (no sign-in fallback occurred).
        assert session.refresh_token == "rt_primed"

    def test_408_retried_then_runtime_error_no_sign_in_fallback(self, monkeypatch):
        """408 behaves like 429: retried, plain RuntimeError, token preserved."""
        adapter, session = self._primed_adapter(monkeypatch)

        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return _MockResponse(408, json_body={}, text="Request Timeout")

        monkeypatch.setattr(adapter._http, "post", mock_post)

        with pytest.raises(RuntimeError) as exc_info:
            adapter.get_token("user_a")

        assert not isinstance(exc_info.value, RefreshTokenRejected)
        assert "failed after 3 attempts" in str(exc_info.value)
        assert call_count == 3
        assert session.refresh_token == "rt_primed"

    def test_403_unexpected_status_runtime_error_token_preserved(self, monkeypatch):
        """403 is not a clear token rejection -> plain RuntimeError, no fallback."""
        adapter, session = self._primed_adapter(monkeypatch)

        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return _MockResponse(403, json_body={}, text="Forbidden")

        monkeypatch.setattr(adapter._http, "post", mock_post)

        with pytest.raises(RuntimeError) as exc_info:
            adapter.get_token("user_a")

        assert not isinstance(exc_info.value, RefreshTokenRejected)
        assert "unexpected HTTP 403" in str(exc_info.value)
        # Single attempt — not retried, not a sign-in fallback.
        assert call_count == 1
        assert session.refresh_token == "rt_primed"

    def test_is_invalid_grant_helper_matches_known_markers(self):
        """_is_invalid_grant detects markers in JSON fields and raw text."""
        f = SupabaseAuthAdapter._is_invalid_grant
        assert f('{"error":"invalid_grant"}') is True
        assert f('{"error_code":"refresh_token_not_found"}') is True
        assert f('{"msg":"Invalid Refresh Token: Already Used"}') is True
        assert f("invalid refresh token") is True
        assert f('{"error":"rate limit exceeded"}') is False
        assert f("Request Timeout") is False
        assert f("<html>Bad Request</html>") is False


# ---------------------------------------------------------------------------
# Error path: CAPTCHA enforcement
# ---------------------------------------------------------------------------

class TestCaptchaEnforcement:
    """CAPTCHA detection on sign-in."""

    def test_captcha_error_400_with_captcha_text(self, monkeypatch):
        """400 + 'captcha' in body raises CaptchaEnforcedError."""
        resp = _MockResponse(
            400,
            json_body={"error": "captcha verification process failed"},
            text='{"error": "captcha verification process failed"}',
        )

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        with pytest.raises(CaptchaEnforcedError) as exc_info:
            adapter.get_token("user_a")

        msg = str(exc_info.value)
        assert "CAPTCHA" in msg
        assert "user_a" in msg

    def test_captcha_error_is_auth_config_error_subclass(self, monkeypatch):
        """CaptchaEnforcedError must be an AuthConfigError subclass."""
        assert issubclass(CaptchaEnforcedError, AuthConfigError)

    def test_400_without_captcha_raises_auth_config_error(self, monkeypatch):
        """400 without 'captcha' raises AuthConfigError (not CaptchaEnforcedError)."""
        resp = _MockResponse(
            400,
            json_body={"error": "invalid login credentials"},
            text='{"error": "invalid login credentials"}',
        )

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        with pytest.raises(AuthConfigError) as exc_info:
            adapter.get_token("user_a")

        assert not isinstance(exc_info.value, CaptchaEnforcedError)


# ---------------------------------------------------------------------------
# MFA / AAL detection
# ---------------------------------------------------------------------------

class TestMFAAAL:
    """MFA assurance level (aal) detection."""

    def test_mfa_aal1_emits_warning(self, monkeypatch, caplog):
        """access_token with aal='aal1' causes the adapter to emit a WARNING."""
        jwt_val = _make_jwt(aal="aal1")
        resp = _MockResponse(200, _sign_in_response(jwt_val))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        with caplog.at_level(logging.WARNING, logger="auth.supabase_auth"):
            adapter.get_token("user_a")

        assert any("aal1" in record.message.lower() or "AAL1" in record.message
                   for record in caplog.records)

    def test_mfa_aal1_does_not_raise(self, monkeypatch):
        """aal1 token does NOT raise — adapter returns the token normally."""
        jwt_val = _make_jwt(aal="aal1")
        resp = _MockResponse(200, _sign_in_response(jwt_val))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        # Should not raise.
        token = adapter.get_token("user_a")
        assert token == jwt_val

    def test_mfa_aal2_no_warning(self, monkeypatch, caplog):
        """access_token with aal='aal2' does not emit an AAL1 warning."""
        jwt_val = _make_jwt(aal="aal2")
        resp = _MockResponse(200, _sign_in_response(jwt_val))

        adapter = _make_adapter()
        monkeypatch.setattr(adapter._http, "post", lambda *a, **kw: resp)

        with caplog.at_level(logging.WARNING, logger="auth.supabase_auth"):
            adapter.get_token("user_a")

        aal1_warnings = [
            r for r in caplog.records
            if "aal1" in r.message.lower() or "AAL1" in r.message
        ]
        assert len(aal1_warnings) == 0


# ---------------------------------------------------------------------------
# Config error: missing project_url
# ---------------------------------------------------------------------------

class TestConfigErrors:
    """AuthConfigError raised for missing configuration."""

    def test_config_error_missing_project_url(self, monkeypatch):
        """create_adapter raises AuthConfigError with clear message when project_url absent."""
        from auth import create_adapter

        monkeypatch.delenv("SUPABASE_PROJECT_URL", raising=False)
        monkeypatch.setenv("SUPABASE_ANON_KEY", "test_anon_key")
        monkeypatch.setenv("PENTEST_USER_A_EMAIL", "a@example.com")
        monkeypatch.setenv("PENTEST_USER_A_PASSWORD", "pass_a")

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="supabase-auth"),
            supabase=None,
            target=SimpleNamespace(base_url="https://example.com"),
        )

        with pytest.raises(AuthConfigError) as exc_info:
            create_adapter(profile)

        assert "project" in str(exc_info.value).lower() or "url" in str(exc_info.value).lower()

    def test_config_error_missing_anon_key(self, monkeypatch):
        """create_adapter raises AuthConfigError when anon_key is absent."""
        from auth import create_adapter

        monkeypatch.setenv("SUPABASE_PROJECT_URL", "https://xyzxyz.supabase.co")
        monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)
        monkeypatch.setenv("PENTEST_USER_A_EMAIL", "a@example.com")
        monkeypatch.setenv("PENTEST_USER_A_PASSWORD", "pass_a")

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="supabase-auth"),
            supabase=None,
            target=SimpleNamespace(base_url="https://example.com"),
        )

        with pytest.raises(AuthConfigError) as exc_info:
            create_adapter(profile)

        assert "anon" in str(exc_info.value).lower() or "key" in str(exc_info.value).lower()

    def test_config_error_missing_credentials(self, monkeypatch):
        """create_adapter raises AuthConfigError when no account credentials."""
        from auth import create_adapter

        monkeypatch.setenv("SUPABASE_PROJECT_URL", "https://xyzxyz.supabase.co")
        monkeypatch.setenv("SUPABASE_ANON_KEY", "test_anon_key")
        monkeypatch.delenv("PENTEST_USER_A_EMAIL", raising=False)
        monkeypatch.delenv("PENTEST_USER_A_PASSWORD", raising=False)
        monkeypatch.delenv("PENTEST_USER_B_EMAIL", raising=False)
        monkeypatch.delenv("PENTEST_USER_B_PASSWORD", raising=False)

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="supabase-auth"),
            supabase=None,
            target=SimpleNamespace(base_url="https://example.com"),
        )

        with pytest.raises(AuthConfigError, match="No test account credentials"):
            create_adapter(profile)


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------

class TestAdapterFactory:
    """Factory registration in auth/__init__.py."""

    def test_factory_returns_supabase_adapter(self, monkeypatch):
        """create_adapter returns SupabaseAuthAdapter for supabase-auth profile."""
        from auth import create_adapter

        monkeypatch.setenv("SUPABASE_PROJECT_URL", "https://xyzxyz.supabase.co")
        monkeypatch.setenv("SUPABASE_ANON_KEY", "test_anon_key")
        monkeypatch.setenv("PENTEST_USER_A_EMAIL", "a@example.com")
        monkeypatch.setenv("PENTEST_USER_A_PASSWORD", "pass_a")

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="supabase-auth"),
            supabase=SimpleNamespace(
                project_url="https://xyzxyz.supabase.co",
                anon_key="test_anon_key",
            ),
            target=SimpleNamespace(base_url="https://example.com"),
        )

        adapter = create_adapter(profile)
        assert isinstance(adapter, SupabaseAuthAdapter)
        adapter.close()

    def test_factory_prefers_env_over_profile(self, monkeypatch):
        """Env vars take precedence over profile values for project_url/anon_key."""
        from auth import create_adapter

        env_url = "https://from-env.supabase.co"
        monkeypatch.setenv("SUPABASE_PROJECT_URL", env_url)
        monkeypatch.setenv("SUPABASE_ANON_KEY", "env_anon_key")
        monkeypatch.setenv("PENTEST_USER_A_EMAIL", "a@example.com")
        monkeypatch.setenv("PENTEST_USER_A_PASSWORD", "pass_a")

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="supabase-auth"),
            supabase=SimpleNamespace(
                project_url="https://from-profile.supabase.co",
                anon_key="profile_anon_key",
            ),
            target=SimpleNamespace(base_url="https://example.com"),
        )

        adapter = create_adapter(profile)
        assert adapter._project_url == env_url
        assert adapter._anon_key == "env_anon_key"
        adapter.close()


# ---------------------------------------------------------------------------
# Credential scrubbing
# ---------------------------------------------------------------------------

class TestCredentialScrubbing:
    """_SupabaseSession repr/str must not expose password or refresh_token."""

    def test_repr_does_not_contain_password(self):
        """__repr__ of _SupabaseSession redacts password."""
        session = _SupabaseSession(
            email="test@example.com",
            password="super_secret_password",
            refresh_token="rt_secret_refresh_value",
        )
        repr_str = repr(session)
        assert "super_secret_password" not in repr_str
        assert "rt_secret_refresh_value" not in repr_str

    def test_str_does_not_contain_password(self):
        """__str__ of _SupabaseSession redacts password."""
        session = _SupabaseSession(
            email="test@example.com",
            password="super_secret_password",
            refresh_token="rt_secret_refresh_value",
        )
        str_val = str(session)
        assert "super_secret_password" not in str_val
        assert "rt_secret_refresh_value" not in str_val

    def test_repr_contains_email_for_debugging(self):
        """__repr__ still shows the email so failing tests are identifiable."""
        session = _SupabaseSession(
            email="debug@example.com",
            password="secret",
        )
        assert "debug@example.com" in repr(session)

    def test_repr_shows_set_for_refresh_token_when_present(self):
        """__repr__ shows '<set>' (not the value) when refresh_token is populated."""
        session = _SupabaseSession(
            email="test@example.com",
            password="secret",
            refresh_token="rt_actual_value",
        )
        repr_str = repr(session)
        assert "<set>" in repr_str
        assert "rt_actual_value" not in repr_str


# ---------------------------------------------------------------------------
# Cleanup: close / context manager
# ---------------------------------------------------------------------------

class TestCleanup:
    """Adapter cleanup and context manager support."""

    def test_close_does_not_raise(self):
        """close() completes without error."""
        adapter = _make_adapter()
        adapter.close()

    def test_context_manager(self):
        """Adapter works as a context manager."""
        with _make_adapter() as adapter:
            assert isinstance(adapter, SupabaseAuthAdapter)

    def test_unknown_account_raises_value_error(self):
        """get_token() with unknown account name raises ValueError."""
        adapter = _make_adapter()
        with pytest.raises(ValueError, match="Unknown account"):
            adapter.get_token("user_z")
