"""Unit tests for the FAPI-based ClerkAuthAdapter.

All network calls are mocked with unittest.mock — no real HTTP requests are made.

Test coverage
-------------
Happy paths:
  - Sign in with valid email+password: session_id and JWT extracted from FAPI response.
  - Token refresh: returns new JWT; cached token returned within window; refresh
    triggered after simulated expiry.
  - Dev instance detected (.clerk.accounts.dev): JWT read from response body (same
    JSON path, but verifying the dev-detection flag is set).

Error paths:
  - Wrong password / invalid credentials: clear error naming the email address.
  - MFA required: clear error with remediation instructions.
  - FAPI unreachable (TransportError): falls back to env-var JWT when set.
  - FAPI unreachable + no env var: ClerkConfigError raised.
  - Bot detection (403): ClerkConfigError with fallback suggestion.
  - Bot detection (429): ClerkConfigError with fallback suggestion.

Edge cases:
  - Two accounts (user_a, user_b) maintain fully independent sessions.
  - Constructed with only fapi_host + accounts dict — no CLERK_SECRET_KEY required.

Integration:
  - Acquired JWT (mocked) contains expected ``sub`` claim readable via pyjwt.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import unittest.mock as mock
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure the StackBadger package root is importable.
# ---------------------------------------------------------------------------
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

import httpx

from auth.clerk import (
    ClerkAuthAdapter,
    ClerkConfigError,
    REFRESH_WINDOW_SECONDS,
    _extract_jwt_from_fapi_body,
)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _make_jwt(sub: str = "user_test_001", exp_offset: int = 60) -> str:
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

    # Fake signature segment — pyjwt skips verification when options says so.
    sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


def _make_expired_jwt(sub: str = "user_test_001") -> str:
    """Build a JWT that expired 120 seconds ago."""
    return _make_jwt(sub=sub, exp_offset=-120)


def _fapi_sign_in_response(jwt_value: str, session_id: str = "sess_abc123") -> dict:
    """Minimal FAPI sign-in response body matching the expected JSON path."""
    return {
        "status": "complete",
        "created_session_id": session_id,
        "client": {
            "sessions": [
                {
                    "id": session_id,
                    "status": "active",
                    "last_active_token": {"jwt": jwt_value},
                }
            ]
        },
    }


def _fapi_refresh_response(jwt_value: str, session_id: str = "sess_abc123") -> dict:
    """Minimal FAPI token-refresh response body."""
    return {
        "client": {
            "sessions": [
                {
                    "id": session_id,
                    "last_active_token": {"jwt": jwt_value},
                }
            ]
        },
    }


def _mock_httpx_response(
    status_code: int,
    json_body: dict | None = None,
    raise_transport_error: bool = False,
) -> mock.MagicMock:
    """Return a mock that mimics an httpx.Response (or raises TransportError)."""
    if raise_transport_error:
        m = mock.MagicMock(spec=httpx.Client)
        m.post.side_effect = httpx.TransportError("connection refused")
        return m

    resp = mock.MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.text = json.dumps(json_body or {})
    resp.content = resp.text.encode()
    return resp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAPI_HOST = "https://test.clerk.accounts.dev"
FAPI_HOST_PROD = "https://clerk.example.com"

ACCOUNTS = {
    "user_a": {"email": "a@example.com", "password": "pass_a"},
    "user_b": {"email": "b@example.com", "password": "pass_b"},
}


def _make_adapter(fapi_host: str = FAPI_HOST, accounts: dict | None = None) -> ClerkAuthAdapter:
    return ClerkAuthAdapter(
        fapi_host=fapi_host,
        accounts=accounts or ACCOUNTS,
        target_origin="https://example.com",
    )


# ---------------------------------------------------------------------------
# Helper to patch the per-account httpx.Client inside the adapter.
# ---------------------------------------------------------------------------

def _patch_session_http(adapter: ClerkAuthAdapter, account_name: str, mock_client: mock.MagicMock) -> None:
    """Replace the httpx.Client on *account_name*'s session with *mock_client*."""
    adapter._sessions[account_name].http = mock_client


# ---------------------------------------------------------------------------
# Happy path: sign in
# ---------------------------------------------------------------------------

class TestSignIn:
    """Happy-path sign-in via FAPI."""

    def test_sign_in_returns_jwt(self):
        """get_token() signs in and returns the JWT from the FAPI response."""
        jwt_val = _make_jwt(sub="user_test_a")
        sign_in_resp = _mock_httpx_response(200, _fapi_sign_in_response(jwt_val))

        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = sign_in_resp
        _patch_session_http(adapter, "user_a", mock_client)

        token = adapter.get_token("user_a")
        assert token == jwt_val

        # Verify the FAPI sign-in endpoint was called with correct args.
        call_args = mock_client.post.call_args
        assert "/v1/client/sign_ins" in call_args[0][0]
        assert call_args[1]["data"]["identifier"] == "a@example.com"
        assert call_args[1]["data"]["strategy"] == "password"
        assert call_args[1]["data"]["password"] == "pass_a"

    def test_sign_in_populates_session_id(self):
        """After sign-in, session_id is stored on the session object."""
        jwt_val = _make_jwt()
        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(
            200, _fapi_sign_in_response(jwt_val, session_id="sess_xyz999")
        )
        _patch_session_http(adapter, "user_a", mock_client)

        adapter.get_token("user_a")
        assert adapter._sessions["user_a"].session_id == "sess_xyz999"

    def test_sign_in_sets_jwt_on_session(self):
        """JWT and exp are stored on the session after successful sign-in."""
        jwt_val = _make_jwt(sub="user_a_sub", exp_offset=60)
        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(
            200, _fapi_sign_in_response(jwt_val)
        )
        _patch_session_http(adapter, "user_a", mock_client)

        adapter.get_token("user_a")
        session = adapter._sessions["user_a"]
        assert session.jwt == jwt_val
        assert session.jwt_exp > time.time()

    def test_get_headers_returns_bearer(self):
        """get_headers() wraps the JWT in a Bearer Authorization header."""
        jwt_val = _make_jwt()
        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(
            200, _fapi_sign_in_response(jwt_val)
        )
        _patch_session_http(adapter, "user_a", mock_client)

        headers = adapter.get_headers("user_a")
        assert headers == {"Authorization": f"Bearer {jwt_val}"}


# ---------------------------------------------------------------------------
# Happy path: token refresh
# ---------------------------------------------------------------------------

class TestTokenRefresh:
    """Token lifecycle and refresh behaviour."""

    def test_cached_token_returned_within_window(self):
        """get_token() returns the cached JWT if expiry is not within window."""
        jwt_val = _make_jwt(exp_offset=120)  # 120s remaining — above REFRESH_WINDOW_SECONDS
        adapter = _make_adapter()
        # Pre-seed the session so sign-in is not needed.
        session = adapter._sessions["user_a"]
        session.session_id = "sess_cached"
        session.jwt = jwt_val
        session.jwt_exp = int(time.time()) + 120

        mock_client = mock.MagicMock(spec=httpx.Client)
        _patch_session_http(adapter, "user_a", mock_client)

        token = adapter.get_token("user_a")
        assert token == jwt_val
        # No HTTP call should have been made.
        mock_client.post.assert_not_called()

    def test_refresh_triggered_after_simulated_expiry(self):
        """get_token() calls FAPI refresh when jwt_exp is within the refresh window."""
        old_jwt = _make_jwt(exp_offset=5)  # 5s remaining — within REFRESH_WINDOW_SECONDS (10)
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.session_id = "sess_expiring"
        session.jwt = old_jwt
        session.jwt_exp = int(time.time()) + 5  # within window

        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(
            200, _fapi_refresh_response(new_jwt, session_id="sess_expiring")
        )
        _patch_session_http(adapter, "user_a", mock_client)

        token = adapter.get_token("user_a")
        assert token == new_jwt

        # Verify the refresh endpoint (not sign-in) was called.
        call_args = mock_client.post.call_args
        assert "/v1/client/sessions/sess_expiring/tokens" in call_args[0][0]

    def test_is_expired_false_for_fresh_token(self):
        """is_expired() returns False when token has more than REFRESH_WINDOW_SECONDS remaining."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.jwt = _make_jwt(exp_offset=120)
        session.jwt_exp = int(time.time()) + 120
        assert adapter.is_expired("user_a") is False

    def test_is_expired_true_within_window(self):
        """is_expired() returns True when remaining time is within REFRESH_WINDOW_SECONDS."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.jwt = _make_jwt(exp_offset=REFRESH_WINDOW_SECONDS - 1)
        session.jwt_exp = int(time.time()) + REFRESH_WINDOW_SECONDS - 1
        assert adapter.is_expired("user_a") is True

    def test_is_expired_true_for_no_jwt(self):
        """is_expired() returns True when no JWT is present."""
        adapter = _make_adapter()
        assert adapter.is_expired("user_a") is True

    def test_refresh_response_updates_jwt(self):
        """After token refresh, session holds the new JWT and updated exp."""
        old_jwt = _make_jwt(exp_offset=5)
        new_jwt = _make_jwt(exp_offset=60)

        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.session_id = "sess_r"
        session.jwt = old_jwt
        session.jwt_exp = int(time.time()) + 5

        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(
            200, _fapi_refresh_response(new_jwt)
        )
        _patch_session_http(adapter, "user_a", mock_client)

        adapter.get_token("user_a")
        assert session.jwt == new_jwt
        assert session.jwt_exp > int(time.time()) + 50


# ---------------------------------------------------------------------------
# Happy path: dev instance detection
# ---------------------------------------------------------------------------

class TestDevInstance:
    """Dev FAPI host (.clerk.accounts.dev) detection."""

    def test_dev_flag_set_for_dev_host(self):
        """Adapter sets _is_dev=True when fapi_host contains .clerk.accounts.dev."""
        adapter = _make_adapter(fapi_host="https://proj-xyz.clerk.accounts.dev")
        assert adapter._is_dev is True

    def test_dev_flag_not_set_for_prod_host(self):
        """Adapter sets _is_dev=False for a production FAPI host."""
        adapter = _make_adapter(fapi_host=FAPI_HOST_PROD)
        assert adapter._is_dev is False

    def test_dev_instance_extracts_jwt_from_response_body(self):
        """Dev instance sign-in reads JWT from the standard JSON path in the body."""
        jwt_val = _make_jwt(sub="dev_user")
        adapter = _make_adapter(fapi_host="https://proj.clerk.accounts.dev")
        assert adapter._is_dev is True  # sanity-check

        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(
            200, _fapi_sign_in_response(jwt_val)
        )
        _patch_session_http(adapter, "user_a", mock_client)

        token = adapter.get_token("user_a")
        assert token == jwt_val


# ---------------------------------------------------------------------------
# Error path: wrong password
# ---------------------------------------------------------------------------

class TestWrongPassword:
    """Clear error message when credentials are rejected."""

    def test_wrong_password_raises_config_error(self):
        """Wrong password returns a ClerkConfigError naming the email."""
        error_body = {
            "errors": [
                {
                    "code": "form_password_incorrect",
                    "message": "Password is incorrect",
                    "long_message": "The password you entered is incorrect. Please try again.",
                }
            ]
        }
        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(422, error_body)
        _patch_session_http(adapter, "user_a", mock_client)

        with pytest.raises(ClerkConfigError) as exc_info:
            adapter.get_token("user_a")

        msg = str(exc_info.value)
        assert "user_a" in msg
        assert "a@example.com" in msg
        # The error must name the problem clearly enough for a pentest operator.
        assert "password" in msg.lower() or "incorrect" in msg.lower() or "invalid" in msg.lower()

    def test_non_password_sign_in_error_includes_email(self):
        """Any non-200 sign-in response includes the account email in the error."""
        error_body = {
            "errors": [
                {
                    "code": "identifier_not_found",
                    "message": "Could not find account",
                    "long_message": "No account found with this identifier.",
                }
            ]
        }
        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(422, error_body)
        _patch_session_http(adapter, "user_a", mock_client)

        with pytest.raises(ClerkConfigError) as exc_info:
            adapter.get_token("user_a")

        assert "a@example.com" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Error path: MFA required
# ---------------------------------------------------------------------------

class TestMfaRequired:
    """Clear error with remediation instructions when MFA is configured."""

    def test_mfa_raises_config_error_with_remediation(self):
        """needs_second_factor status raises ClerkConfigError with remediation text."""
        mfa_body = {
            "status": "complete",
            "response": {"status": "needs_second_factor"},
            "client": {
                "sessions": [
                    {
                        "id": "sess_mfa",
                        "last_active_token": {"jwt": None},
                    }
                ]
            },
        }
        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(200, mfa_body)
        _patch_session_http(adapter, "user_a", mock_client)

        with pytest.raises(ClerkConfigError) as exc_info:
            adapter.get_token("user_a")

        msg = str(exc_info.value)
        # Must name the account and email.
        assert "user_a" in msg
        assert "a@example.com" in msg
        # Must include remediation guidance.
        assert "MFA" in msg or "second factor" in msg.lower()
        assert "dashboard" in msg.lower() or "disable" in msg.lower() or "JWT" in msg or "env" in msg.lower()


# ---------------------------------------------------------------------------
# Error path: FAPI unreachable + env-var fallback
# ---------------------------------------------------------------------------

class TestFapiUnreachable:
    """Fallback to env-var JWT when FAPI is unreachable."""

    def test_unreachable_fapi_falls_back_to_env_jwt(self, monkeypatch):
        """TransportError triggers env-var fallback when PENTEST_USER_A_JWT is set."""
        fallback_jwt = _make_jwt(sub="user_a_fallback", exp_offset=300)
        monkeypatch.setenv("PENTEST_USER_A_JWT", fallback_jwt)

        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.side_effect = httpx.TransportError("connection refused")
        _patch_session_http(adapter, "user_a", mock_client)

        with pytest.warns(UserWarning, match="env-var JWT fallback"):
            token = adapter.get_token("user_a")

        assert token == fallback_jwt

    def test_unreachable_fapi_no_env_var_raises(self, monkeypatch):
        """TransportError with no env-var fallback raises ClerkConfigError."""
        monkeypatch.delenv("PENTEST_USER_A_JWT", raising=False)

        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.side_effect = httpx.TransportError("connection refused")
        _patch_session_http(adapter, "user_a", mock_client)

        with pytest.raises(ClerkConfigError) as exc_info:
            adapter.get_token("user_a")

        msg = str(exc_info.value)
        assert "PENTEST_USER_A_JWT" in msg
        # Must NOT present CLERK_SECRET_KEY as something the user needs to set.
        # It may appear in an informational note saying it's NOT required.
        assert "CLERK_SECRET_KEY" not in msg or "not required" in msg


# ---------------------------------------------------------------------------
# Error path: bot detection (403 / 429)
# ---------------------------------------------------------------------------

class TestBotDetection:
    """403/429 from FAPI falls back to env-var JWT; raises if that's also absent."""

    @pytest.mark.parametrize("status_code", [403, 429])
    def test_bot_detection_falls_back_to_env_jwt(self, status_code: int, monkeypatch):
        """HTTP 403/429 triggers env-var fallback; succeeds if JWT env var is set."""
        jwt_value = _make_jwt(sub="fallback_sub")
        monkeypatch.setenv("PENTEST_USER_A_JWT", jwt_value)

        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(status_code, {})
        _patch_session_http(adapter, "user_a", mock_client)

        token = adapter.get_token("user_a")
        assert token == jwt_value

    @pytest.mark.parametrize("status_code", [403, 429])
    def test_bot_detection_raises_when_no_fallback(self, status_code: int, monkeypatch):
        """HTTP 403/429 with no env-var JWT raises ClerkConfigError."""
        monkeypatch.delenv("PENTEST_USER_A_JWT", raising=False)

        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(status_code, {})
        _patch_session_http(adapter, "user_a", mock_client)

        with pytest.raises(ClerkConfigError) as exc_info:
            adapter.get_token("user_a")

        msg = str(exc_info.value)
        assert "PENTEST_USER_A_JWT" in msg


# ---------------------------------------------------------------------------
# Edge case: independent sessions for user_a and user_b
# ---------------------------------------------------------------------------

class TestIndependentSessions:
    """user_a and user_b maintain fully independent sessions."""

    def test_two_accounts_independent_session_ids(self):
        """Sign-in for user_a does not affect user_b session state."""
        jwt_a = _make_jwt(sub="sub_a")
        jwt_b = _make_jwt(sub="sub_b")

        adapter = _make_adapter()

        # Set up separate mock clients for each account.
        mock_client_a = mock.MagicMock(spec=httpx.Client)
        mock_client_a.post.return_value = _mock_httpx_response(
            200, _fapi_sign_in_response(jwt_a, session_id="sess_a")
        )
        mock_client_b = mock.MagicMock(spec=httpx.Client)
        mock_client_b.post.return_value = _mock_httpx_response(
            200, _fapi_sign_in_response(jwt_b, session_id="sess_b")
        )

        _patch_session_http(adapter, "user_a", mock_client_a)
        _patch_session_http(adapter, "user_b", mock_client_b)

        token_a = adapter.get_token("user_a")
        token_b = adapter.get_token("user_b")

        assert token_a == jwt_a
        assert token_b == jwt_b
        assert token_a != token_b

        assert adapter._sessions["user_a"].session_id == "sess_a"
        assert adapter._sessions["user_b"].session_id == "sess_b"

    def test_two_accounts_cookie_jars_are_isolated(self):
        """Each account's httpx.Client is a distinct object (isolated cookie jar)."""
        adapter = _make_adapter()
        http_a = adapter._sessions["user_a"].http
        http_b = adapter._sessions["user_b"].http
        assert http_a is not http_b

    def test_user_b_failure_does_not_affect_user_a(self):
        """An error for user_b does not corrupt user_a's cached session."""
        jwt_a = _make_jwt(sub="sub_a")
        adapter = _make_adapter()

        # Pre-seed user_a with a valid, non-expiring session.
        session_a = adapter._sessions["user_a"]
        session_a.session_id = "sess_a"
        session_a.jwt = jwt_a
        session_a.jwt_exp = int(time.time()) + 300

        # user_b FAPI call fails.
        mock_client_b = mock.MagicMock(spec=httpx.Client)
        mock_client_b.post.return_value = _mock_httpx_response(
            422,
            {"errors": [{"code": "form_password_incorrect", "message": "bad password", "long_message": "bad"}]}
        )
        _patch_session_http(adapter, "user_b", mock_client_b)

        with pytest.raises(ClerkConfigError):
            adapter.get_token("user_b")

        # user_a session must be untouched.
        assert adapter._sessions["user_a"].jwt == jwt_a
        assert adapter._sessions["user_a"].session_id == "sess_a"


# ---------------------------------------------------------------------------
# Integration: JWT contains expected sub claim
# ---------------------------------------------------------------------------

class TestJwtStructure:
    """Acquired JWT (mocked) is decodable and contains the expected sub claim."""

    def test_acquired_jwt_has_sub_claim(self):
        """JWT returned by get_token() is decodable with pyjwt and has a sub claim."""
        import jwt as pyjwt

        sub_value = "user_clerk_abc123"
        jwt_val = _make_jwt(sub=sub_value)

        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(
            200, _fapi_sign_in_response(jwt_val)
        )
        _patch_session_http(adapter, "user_a", mock_client)

        token = adapter.get_token("user_a")
        payload = pyjwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["RS256", "HS256"],
        )
        assert payload["sub"] == sub_value

    def test_jwt_exp_claim_stored_correctly(self):
        """jwt_exp on the session matches the ``exp`` claim in the JWT."""
        exp_offset = 90
        jwt_val = _make_jwt(exp_offset=exp_offset)

        adapter = _make_adapter()
        mock_client = mock.MagicMock(spec=httpx.Client)
        mock_client.post.return_value = _mock_httpx_response(
            200, _fapi_sign_in_response(jwt_val)
        )
        _patch_session_http(adapter, "user_a", mock_client)

        adapter.get_token("user_a")
        session = adapter._sessions["user_a"]
        # exp should be within a few seconds of now + exp_offset.
        assert abs(session.jwt_exp - (int(time.time()) + exp_offset)) < 5


# ---------------------------------------------------------------------------
# Constructor: no CLERK_SECRET_KEY required
# ---------------------------------------------------------------------------

class TestConstructorRequirements:
    """Adapter can be constructed with only fapi_host and accounts."""

    def test_construction_requires_no_secret_key(self, monkeypatch):
        """ClerkAuthAdapter initialises successfully without CLERK_SECRET_KEY in env."""
        monkeypatch.delenv("CLERK_SECRET_KEY", raising=False)
        # Should not raise.
        adapter = ClerkAuthAdapter(
            fapi_host=FAPI_HOST,
            accounts={"user_a": {"email": "a@example.com", "password": "p"}},
        )
        assert adapter is not None

    def test_unknown_account_name_raises_value_error(self):
        """Providing an unrecognised account name in the constructor raises ValueError."""
        with pytest.raises(ValueError, match="Unknown account"):
            ClerkAuthAdapter(
                fapi_host=FAPI_HOST,
                accounts={"user_z": {"email": "z@example.com", "password": "p"}},
            )

    def test_get_token_unknown_account_raises_value_error(self):
        """get_token() with an unknown account name raises ValueError."""
        adapter = _make_adapter()
        with pytest.raises(ValueError, match="Unknown account"):
            adapter.get_token("user_z")


# ---------------------------------------------------------------------------
# Unit: _extract_jwt_from_fapi_body
# ---------------------------------------------------------------------------

class TestExtractJwtFromFapiBody:
    """Unit tests for the JWT extraction helper."""

    def test_extracts_from_standard_path(self):
        jwt_val = _make_jwt()
        data = _fapi_sign_in_response(jwt_val)
        assert _extract_jwt_from_fapi_body(data) == jwt_val

    def test_returns_none_for_empty_dict(self):
        assert _extract_jwt_from_fapi_body({}) is None

    def test_returns_none_for_missing_sessions(self):
        assert _extract_jwt_from_fapi_body({"client": {}}) is None

    def test_returns_none_when_jwt_is_none(self):
        data = {
            "client": {
                "sessions": [{"last_active_token": {"jwt": None}}]
            }
        }
        assert _extract_jwt_from_fapi_body(data) is None

    def test_returns_none_for_empty_sessions_list(self):
        data = {"client": {"sessions": []}}
        assert _extract_jwt_from_fapi_body(data) is None
