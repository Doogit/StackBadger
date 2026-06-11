"""Unit tests for the NextAuth / Auth.js auth adapter.

All network calls are mocked via monkeypatching on httpx.Client methods --
no real HTTP requests are made.

Test coverage
-------------
Happy paths:
  - CSRF fetch + form POST + session cookie + /api/auth/session verification.
  - Discovered field names from HTML <input> elements.
  - Session roll: /api/auth/session sets new cookie, adapter updates.
  - __Secure- prefix cookies detected for HTTPS targets.
  - v5 cookie preferred over v4 when both present (mid-migration).

Error paths:
  - CSRF fetch returns non-200: clear RuntimeError.
  - Form submit succeeds but no session cookie set: auth failure.
  - CAPTCHA enforcement: 200 + HTML with cf-chl-bypass indicator.

Edge cases:
  - JS-rendered form (no <input>): fallback to email/password with warning.
  - get_token() raises NotImplementedError.
  - Credential scrubbing: password not in repr/str.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from http.cookiejar import Cookie
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import urlparse

import pytest

# ---------------------------------------------------------------------------
# Ensure the StackBadger package root is importable.
# ---------------------------------------------------------------------------
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

import httpx

from auth.nextauth import (
    NextAuthAdapter,
    _NextAuthSession,
    _SESSION_COOKIE_NAMES,
    _discover_field_names,
)
from auth.supabase_auth import CaptchaEnforcedError
from auth.base import AuthConfigError


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL = "https://myapp.example.com"

ACCOUNTS = {
    "user_a": {"email": "a@example.com", "password": "pass_a"},
    "user_b": {"email": "b@example.com", "password": "pass_b"},
}

CSRF_TOKEN = "abc123deadbeef"

SIGNIN_HTML = """
<html><body>
<form method="POST" action="/api/auth/callback/credentials">
  <input type="hidden" name="csrfToken" value="xyz" />
  <input type="email" name="email" />
  <input type="password" name="password" />
  <button type="submit">Sign in</button>
</form>
</body></html>
"""

SIGNIN_HTML_CUSTOM_FIELDS = """
<html><body>
<form method="POST" action="/api/auth/callback/credentials">
  <input type="hidden" name="csrfToken" value="xyz" />
  <input type="text" name="username" />
  <input type="password" name="pass" />
  <button type="submit">Sign in</button>
</form>
</body></html>
"""


# ---------------------------------------------------------------------------
# Mock HTTP response
# ---------------------------------------------------------------------------

class _MockResponse:
    """Lightweight mock for httpx.Response."""

    def __init__(
        self,
        status_code: int,
        json_body: dict | None = None,
        text: str | None = None,
        headers: dict | None = None,
    ):
        self.status_code = status_code
        self._json_body = json_body or {}
        self.text = text if text is not None else json.dumps(self._json_body)
        self.content = self.text.encode()
        self.headers = headers or {"content-type": "application/json"}

    def json(self) -> dict:
        return self._json_body


# ---------------------------------------------------------------------------
# Cookie jar helper
# ---------------------------------------------------------------------------

def _make_cookie_jar(
    cookies: dict | None = None,
    domain: str | None = None,
) -> httpx.Cookies:
    """Create a real httpx.Cookies object pre-loaded with the given cookies.

    Args:
        cookies: Mapping of cookie name -> value.
        domain: Domain to scope each cookie to.  Defaults to the hostname
            extracted from :data:`BASE_URL` so that ``_get_cookie_safe()``
            domain filtering can match the cookies.
    """
    jar = httpx.Cookies()
    _domain = domain or (urlparse(BASE_URL).hostname or "localhost")
    for name, value in (cookies or {}).items():
        jar.set(name, value, domain=_domain)
    return jar


def _scoped_cookie(name: str, value: str, domain: str, path: str = "/") -> Cookie:
    """Build a fully-specified ``http.cookiejar.Cookie`` with explicit domain.

    A leading ``.`` in ``domain`` marks it as a parent-domain (non-host-only)
    cookie; absence marks it host-only. Used to reproduce the
    ``httpx.CookieConflict`` raised when two cookies share a name across
    different domains/paths.
    """
    domain_specified = domain.startswith(".")
    return Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=domain_specified,
        domain_initial_dot=domain_specified,
        path=path,
        path_specified=True,
        secure=True,
        expires=None,
        discard=False,
        comment=None,
        comment_url=None,
        rest={},
    )


# ---------------------------------------------------------------------------
# Mock discovery client
# ---------------------------------------------------------------------------

class _MockDiscoveryClient:
    """Context-manager stand-in for the fresh, cookieless httpx.Client that
    ``_get_field_names()`` creates for the ``/api/auth/signin`` fetch.

    ``.get()`` delegates to the same ``mock_get`` the test wired onto the
    persistent client so the discovery fetch stays inside the mock.
    """

    def __init__(self, getter):
        self._getter = getter

    def __enter__(self) -> "_MockDiscoveryClient":
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def get(self, url, **kwargs):
        return self._getter(url, **kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_adapter(
    base_url: str = BASE_URL,
    accounts: dict | None = None,
) -> NextAuthAdapter:
    return NextAuthAdapter(
        base_url=base_url,
        accounts=accounts or ACCOUNTS,
    )


def _setup_full_auth_flow(
    adapter: NextAuthAdapter,
    account_name: str = "user_a",
    csrf_token: str = CSRF_TOKEN,
    signin_html: str = SIGNIN_HTML,
    session_cookie_name: str = "next-auth.session-token",
    session_cookie_value: str = "sess_abc123",
    session_response: dict | None = None,
    captcha_html: str | None = None,
    captcha_status: int = 403,
    monkeypatch: pytest.MonkeyPatch | None = None,
):
    """Wire up mocks for the full CSRF -> signin -> credential POST -> verify flow.

    Returns the mock client so tests can inspect call history.

    ``_get_field_names()`` builds its own fresh, cookieless ``httpx.Client``
    for the ``/api/auth/signin`` fetch (ADV-003), so when ``monkeypatch`` is
    supplied this also patches ``auth.nextauth.httpx.Client`` to a
    ``_MockDiscoveryClient`` that routes ``.get()`` back through ``mock_get``.
    The adapter (and its persistent session clients) are created before this
    helper runs, so only the lazily-created discovery client gets the mock.
    """
    session = adapter._sessions[account_name]
    client = session.http_client

    # Derive cookie domain from the adapter's base_url so _get_cookie_safe
    # can match the cookie domain against the target host.
    _cookie_domain = urlparse(adapter._base_url).hostname or "localhost"

    if session_response is None:
        session_response = {"user": {"email": "a@example.com"}, "expires": "2099-01-01"}

    call_log: list[tuple[str, str]] = []

    def mock_get(url, **kwargs):
        call_log.append(("GET", url))
        if "/api/auth/csrf" in url:
            return _MockResponse(200, json_body={"csrfToken": csrf_token})
        elif "/api/auth/signin" in url:
            return _MockResponse(
                200,
                text=signin_html,
                headers={"content-type": "text/html"},
            )
        elif "/api/auth/session" in url:
            return _MockResponse(200, json_body=session_response)
        return _MockResponse(404)

    def mock_post(url, **kwargs):
        call_log.append(("POST", url))
        if "/api/auth/callback/credentials" in url:
            # Simulate the server setting a session cookie via _cookies
            # (httpx.Client._cookies is the mutable internal jar).
            # Set with explicit domain so _get_cookie_safe can match it
            # against base_url's host.
            client._cookies.set(
                session_cookie_name,
                session_cookie_value,
                domain=_cookie_domain,
            )
            if captcha_html is not None:
                return _MockResponse(
                    captcha_status,
                    text=captcha_html,
                    headers={"content-type": "text/html"},
                )
            return _MockResponse(
                200,
                json_body={"url": f"{BASE_URL}/"},
                headers={"content-type": "application/json"},
            )
        return _MockResponse(404)

    client.get = mock_get
    client.post = mock_post

    if monkeypatch is not None:
        monkeypatch.setattr(
            "auth.nextauth.httpx.Client",
            lambda **_kw: _MockDiscoveryClient(mock_get),
        )

    return client, call_log


# ---------------------------------------------------------------------------
# Happy path: CSRF + form submit + session verification
# ---------------------------------------------------------------------------

class TestCSRFAndFormSubmit:
    """CSRF fetch -> form POST -> session cookie -> /api/auth/session verify."""

    def test_csrf_fetch_and_form_submit(self, monkeypatch):
        """Full auth flow: CSRF, signin HTML, credential POST, session verify."""
        adapter = _make_adapter()
        client, call_log = _setup_full_auth_flow(adapter, monkeypatch=monkeypatch)

        headers = adapter.get_headers("user_a")

        # Should have Cookie header with session token.
        assert "Cookie" in headers
        assert "next-auth.session-token=sess_abc123" in headers["Cookie"]

        # Verify the flow order.
        methods_urls = [(m, u.split("?")[0]) for m, u in call_log]
        assert ("GET", f"{BASE_URL}/api/auth/csrf") in methods_urls
        assert ("GET", f"{BASE_URL}/api/auth/signin") in methods_urls
        assert ("POST", f"{BASE_URL}/api/auth/callback/credentials") in methods_urls
        assert ("GET", f"{BASE_URL}/api/auth/session") in methods_urls


# ---------------------------------------------------------------------------
# Field name discovery
# ---------------------------------------------------------------------------

class TestFieldDiscovery:
    """HTML form field name discovery."""

    def test_discovered_field_names(self, monkeypatch):
        """HTML with <input name="username"> -> adapter uses correct field."""
        adapter = _make_adapter()
        client, call_log = _setup_full_auth_flow(
            adapter,
            signin_html=SIGNIN_HTML_CUSTOM_FIELDS,
            monkeypatch=monkeypatch,
        )

        headers = adapter.get_headers("user_a")

        # Verify the adapter discovered the custom field names.
        session = adapter._sessions["user_a"]
        assert session.field_names["email_field"] == "username"
        assert session.field_names["password_field"] == "pass"

    def test_discover_field_names_standard(self):
        """Standard email/password inputs are discovered correctly."""
        fields = _discover_field_names(SIGNIN_HTML)
        assert fields["email_field"] == "email"
        assert fields["password_field"] == "password"

    def test_discover_field_names_custom(self):
        """Custom username/pass inputs are discovered correctly."""
        fields = _discover_field_names(SIGNIN_HTML_CUSTOM_FIELDS)
        assert fields["email_field"] == "username"
        assert fields["password_field"] == "pass"


# ---------------------------------------------------------------------------
# Session roll
# ---------------------------------------------------------------------------

class TestSessionRoll:
    """Session cookie roll detection."""

    def test_session_roll(self):
        """GET /api/auth/session sets new cookie -> adapter updates."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]

        # Pre-populate with an existing session.
        session.session_cookie_name = "next-auth.session-token"
        session.session_cookie_value = "old_sess_value"

        session.http_client._cookies = _make_cookie_jar({
            "next-auth.session-token": "new_rolled_value",
        })

        def mock_get(url, **kwargs):
            return _MockResponse(
                200,
                json_body={"user": {"email": "a@example.com"}, "expires": "2099-01-01"},
            )

        session.http_client.get = mock_get

        # is_expired() should detect the session is valid and update the cookie.
        expired = adapter.is_expired("user_a")
        assert expired is False
        assert session.session_cookie_value == "new_rolled_value"


# ---------------------------------------------------------------------------
# Error: CSRF non-200
# ---------------------------------------------------------------------------

class TestCSRFErrors:
    """CSRF fetch error handling."""

    def test_csrf_fetch_non_200_raises(self):
        """CSRF endpoint returns 500 -> clear RuntimeError."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]

        def mock_get(url, **kwargs):
            if "/api/auth/csrf" in url:
                return _MockResponse(500, text="Internal Server Error")
            return _MockResponse(404)

        session.http_client.get = mock_get

        with pytest.raises(RuntimeError, match="CSRF fetch failed.*500"):
            adapter.get_headers("user_a")


# ---------------------------------------------------------------------------
# Error: No session cookie after submit
# ---------------------------------------------------------------------------

class TestNoSessionCookie:
    """Form submit redirect but no session cookie."""

    def test_form_submit_no_session_cookie(self):
        """Credential POST succeeds but no session cookie -> auth failure."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        client = session.http_client

        # Empty cookie jar -- no session cookie set.
        client._cookies = _make_cookie_jar()

        call_count = 0

        def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/api/auth/csrf" in url:
                return _MockResponse(200, json_body={"csrfToken": CSRF_TOKEN})
            elif "/api/auth/signin" in url:
                return _MockResponse(
                    200, text=SIGNIN_HTML, headers={"content-type": "text/html"}
                )
            return _MockResponse(404)

        def mock_post(url, **kwargs):
            # Don't set any cookies in the jar.
            return _MockResponse(
                200,
                json_body={"url": f"{BASE_URL}/"},
                headers={"content-type": "application/json"},
            )

        client.get = mock_get
        client.post = mock_post

        with pytest.raises(RuntimeError, match="did not set a session cookie"):
            adapter.get_headers("user_a")


# ---------------------------------------------------------------------------
# JS-rendered form fallback
# ---------------------------------------------------------------------------

class TestJSRenderedFallback:
    """Fallback when sign-in page has no <input> elements."""

    def test_js_rendered_form_fallback(self, caplog, monkeypatch):
        """No <input> in HTML -> fallback to email/password with log warning."""
        js_html = "<html><body><div id='app'></div><script>render()</script></body></html>"

        adapter = _make_adapter()
        client, call_log = _setup_full_auth_flow(
            adapter,
            signin_html=js_html,
            monkeypatch=monkeypatch,
        )

        with caplog.at_level(logging.WARNING, logger="auth.nextauth"):
            headers = adapter.get_headers("user_a")

        # Should still work with default fields.
        assert "Cookie" in headers

        # Should have logged a warning about no <input> elements.
        assert any(
            "no <input>" in record.message.lower() or "js-rendered" in record.message.lower()
            for record in caplog.records
        ), f"Expected JS-rendered form warning, got: {[r.message for r in caplog.records]}"

        # Field names should be defaults.
        session = adapter._sessions["user_a"]
        assert session.field_names["email_field"] == "email"
        assert session.field_names["password_field"] == "password"


# ---------------------------------------------------------------------------
# Secure cookie detection
# ---------------------------------------------------------------------------

class TestSecureCookie:
    """__Secure- prefix cookies for HTTPS targets."""

    def test_secure_cookie_https_vs_http(self):
        """__Secure-next-auth.session-token detected for HTTPS target."""
        adapter = _make_adapter()
        client, _ = _setup_full_auth_flow(
            adapter,
            session_cookie_name="__Secure-next-auth.session-token",
            session_cookie_value="secure_sess_val",
        )

        headers = adapter.get_headers("user_a")
        assert "__Secure-next-auth.session-token=secure_sess_val" in headers["Cookie"]


# ---------------------------------------------------------------------------
# get_token() raises NotImplementedError
# ---------------------------------------------------------------------------

class TestGetTokenNotImplemented:
    """get_token() must raise NotImplementedError for cookie-based auth."""

    def test_get_token_raises_not_implemented(self):
        """get_token() -> NotImplementedError with descriptive message."""
        adapter = _make_adapter()
        with pytest.raises(NotImplementedError, match="cookie-based auth"):
            adapter.get_token("user_a")


# ---------------------------------------------------------------------------
# CAPTCHA detection
# ---------------------------------------------------------------------------

class TestCaptchaDetection:
    """CAPTCHA enforcement detection on credential POST."""

    def test_captcha_detection_cf_chl_bypass(self, monkeypatch):
        """403 + HTML with cf-chl-bypass -> CaptchaEnforcedError.

        Under the ADV-007 gating a single indicator is only conclusive on a
        403/503 challenge response (or 2+ indicators on a 200), so the mock
        returns the default 403 challenge status.
        """
        captcha_page = (
            '<html><body><div class="cf-chl-bypass">Checking your browser...</div>'
            "</body></html>"
        )
        adapter = _make_adapter()
        client, _ = _setup_full_auth_flow(
            adapter,
            captcha_html=captcha_page,
            captcha_status=403,
            monkeypatch=monkeypatch,
        )

        with pytest.raises(CaptchaEnforcedError) as exc_info:
            adapter.get_headers("user_a")

        msg = str(exc_info.value)
        assert "CAPTCHA" in msg
        assert "user_a" in msg

    def test_captcha_detection_hcaptcha(self):
        """200 + HTML with h-captcha -> CaptchaEnforcedError."""
        captcha_page = (
            '<html><body><div class="h-captcha" data-sitekey="xyz"></div>'
            "</body></html>"
        )
        adapter = _make_adapter()
        client, _ = _setup_full_auth_flow(adapter, captcha_html=captcha_page)

        with pytest.raises(CaptchaEnforcedError):
            adapter.get_headers("user_a")

    def test_captcha_detection_grecaptcha(self):
        """200 + HTML with g-recaptcha -> CaptchaEnforcedError."""
        captcha_page = (
            '<html><body><div class="g-recaptcha" data-sitekey="xyz"></div>'
            "</body></html>"
        )
        adapter = _make_adapter()
        client, _ = _setup_full_auth_flow(adapter, captcha_html=captcha_page)

        with pytest.raises(CaptchaEnforcedError):
            adapter.get_headers("user_a")

    def test_captcha_detection_turnstile(self):
        """200 + HTML with turnstile -> CaptchaEnforcedError."""
        captcha_page = (
            '<html><body><div class="cf-turnstile" data-sitekey="xyz">turnstile</div>'
            "</body></html>"
        )
        adapter = _make_adapter()
        client, _ = _setup_full_auth_flow(adapter, captcha_html=captcha_page)

        with pytest.raises(CaptchaEnforcedError):
            adapter.get_headers("user_a")

    def test_captcha_is_auth_config_error_subclass(self):
        """CaptchaEnforcedError must be an AuthConfigError subclass."""
        assert issubclass(CaptchaEnforcedError, AuthConfigError)


# ---------------------------------------------------------------------------
# Credential scrubbing
# ---------------------------------------------------------------------------

class TestCredentialScrubbing:
    """_NextAuthSession repr/str must not expose password."""

    def test_repr_does_not_contain_password(self):
        """__repr__ redacts password."""
        session = _NextAuthSession(
            email="test@example.com",
            password="super_secret_password",
        )
        repr_str = repr(session)
        assert "super_secret_password" not in repr_str
        assert "***" in repr_str

    def test_str_does_not_contain_password(self):
        """__str__ redacts password."""
        session = _NextAuthSession(
            email="test@example.com",
            password="super_secret_password",
        )
        str_val = str(session)
        assert "super_secret_password" not in str_val

    def test_repr_contains_email_for_debugging(self):
        """__repr__ still shows the email for identification."""
        session = _NextAuthSession(
            email="debug@example.com",
            password="secret",
        )
        assert "debug@example.com" in repr(session)

    def test_repr_shows_set_for_cookie_when_present(self):
        """__repr__ shows '<set>' when session_cookie_value is populated."""
        session = _NextAuthSession(
            email="test@example.com",
            password="secret",
            session_cookie_value="actual_cookie_value",
        )
        repr_str = repr(session)
        assert "<set>" in repr_str
        assert "actual_cookie_value" not in repr_str

    def test_password_not_in_exception_traceback(self):
        """Password must not leak into exception messages from auth failures."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        client = session.http_client

        jar = _make_cookie_jar()
        client._cookies = jar

        def mock_get(url, **kwargs):
            if "/api/auth/csrf" in url:
                return _MockResponse(200, json_body={"csrfToken": CSRF_TOKEN})
            elif "/api/auth/signin" in url:
                return _MockResponse(
                    200, text=SIGNIN_HTML, headers={"content-type": "text/html"}
                )
            return _MockResponse(404)

        def mock_post(url, **kwargs):
            return _MockResponse(200, json_body={}, headers={"content-type": "application/json"})

        client.get = mock_get
        client.post = mock_post

        try:
            adapter.get_headers("user_a")
        except RuntimeError as exc:
            assert "pass_a" not in str(exc)


# ---------------------------------------------------------------------------
# v5 preferred over v4
# ---------------------------------------------------------------------------

class TestV5PreferredOverV4:
    """When both v4 and v5 cookies are present, v5 wins."""

    def test_v5_preferred_over_v4(self):
        """Both v4 and v5 session cookies present -> v5 is used."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        client = session.http_client

        # Jar with both v4 and v5 cookies.
        jar = _make_cookie_jar({
            "next-auth.session-token": "v4_value",
            "authjs.session-token": "v5_value",
        })
        client._cookies = jar

        call_count = 0

        def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/api/auth/csrf" in url:
                return _MockResponse(200, json_body={"csrfToken": CSRF_TOKEN})
            elif "/api/auth/signin" in url:
                return _MockResponse(
                    200, text=SIGNIN_HTML, headers={"content-type": "text/html"}
                )
            elif "/api/auth/session" in url:
                return _MockResponse(
                    200,
                    json_body={"user": {"email": "a@example.com"}, "expires": "2099-01-01"},
                )
            return _MockResponse(404)

        def mock_post(url, **kwargs):
            # Credential POST -- cookies already in jar.
            return _MockResponse(
                200,
                json_body={"url": f"{BASE_URL}/"},
                headers={"content-type": "application/json"},
            )

        client.get = mock_get
        client.post = mock_post

        headers = adapter.get_headers("user_a")

        # The *session* cookie selected must be the v5 variant (v5 preferred
        # over v4 when both are present mid-migration).
        assert session.session_cookie_name == "authjs.session-token"
        assert session.session_cookie_value == "v5_value"

        # get_headers() now exports ALL jar cookies (ADV-009), so the v5
        # session cookie must appear in the Cookie header. It is acceptable
        # for the v4 cookie to also appear -- exporting the full jar is the
        # intended behavior; what matters is v5 is the canonical session.
        assert "authjs.session-token=v5_value" in headers["Cookie"]

    def test_v5_secure_preferred_over_v4_secure(self):
        """__Secure- v5 preferred over __Secure- v4."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        client = session.http_client

        jar = _make_cookie_jar({
            "__Secure-next-auth.session-token": "v4_secure",
            "__Secure-authjs.session-token": "v5_secure",
        })
        client._cookies = jar

        def mock_get(url, **kwargs):
            if "/api/auth/csrf" in url:
                return _MockResponse(200, json_body={"csrfToken": CSRF_TOKEN})
            elif "/api/auth/signin" in url:
                return _MockResponse(
                    200, text=SIGNIN_HTML, headers={"content-type": "text/html"}
                )
            elif "/api/auth/session" in url:
                return _MockResponse(
                    200,
                    json_body={"user": {"email": "a@example.com"}, "expires": "2099-01-01"},
                )
            return _MockResponse(404)

        def mock_post(url, **kwargs):
            return _MockResponse(
                200,
                json_body={"url": f"{BASE_URL}/"},
                headers={"content-type": "application/json"},
            )

        client.get = mock_get
        client.post = mock_post

        headers = adapter.get_headers("user_a")
        assert "__Secure-authjs.session-token=v5_secure" in headers["Cookie"]


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------

class TestAdapterFactory:
    """Factory registration in auth/__init__.py."""

    def test_factory_returns_nextauth_adapter(self, monkeypatch):
        """create_adapter returns NextAuthAdapter for 'nextauth' profile."""
        from auth import create_adapter

        monkeypatch.setenv("PENTEST_USER_A_EMAIL", "a@example.com")
        monkeypatch.setenv("PENTEST_USER_A_PASSWORD", "pass_a")

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="nextauth"),
            target=SimpleNamespace(base_url="https://example.com"),
        )

        adapter = create_adapter(profile)
        assert isinstance(adapter, NextAuthAdapter)
        adapter.close()

    def test_factory_missing_base_url_raises(self, monkeypatch):
        """create_adapter raises AuthConfigError when target.base_url absent."""
        from auth import create_adapter

        monkeypatch.setenv("PENTEST_USER_A_EMAIL", "a@example.com")
        monkeypatch.setenv("PENTEST_USER_A_PASSWORD", "pass_a")

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="nextauth"),
            target=None,
        )

        with pytest.raises(AuthConfigError, match="base URL"):
            create_adapter(profile)

    def test_factory_missing_credentials_raises(self, monkeypatch):
        """create_adapter raises AuthConfigError when no credentials."""
        from auth import create_adapter

        monkeypatch.delenv("PENTEST_USER_A_EMAIL", raising=False)
        monkeypatch.delenv("PENTEST_USER_A_PASSWORD", raising=False)
        monkeypatch.delenv("PENTEST_USER_B_EMAIL", raising=False)
        monkeypatch.delenv("PENTEST_USER_B_PASSWORD", raising=False)

        profile = SimpleNamespace(
            stack=SimpleNamespace(auth="nextauth"),
            target=SimpleNamespace(base_url="https://example.com"),
        )

        with pytest.raises(AuthConfigError, match="No test account credentials"):
            create_adapter(profile)


# ---------------------------------------------------------------------------
# Duplicate-name cookies (Codex finding 1 — CookieConflict)
# ---------------------------------------------------------------------------

class TestDuplicateNameCookies:
    """_extract_session_cookie must not raise httpx.CookieConflict."""

    def test_get_raises_conflict_but_extractor_does_not(self):
        """Sanity: two same-name cookies across domains -> .get() raises,
        but _extract_session_cookie() returns a value safely."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        client = session.http_client

        client._cookies = httpx.Cookies()
        client._cookies.jar.set_cookie(
            _scoped_cookie(
                "next-auth.session-token", "parent_val", ".example.com"
            )
        )
        client._cookies.jar.set_cookie(
            _scoped_cookie(
                "next-auth.session-token", "host_val", "myapp.example.com"
            )
        )

        # Baseline: the raw httpx accessor blows up on the duplicate name.
        with pytest.raises(httpx.CookieConflict):
            client.cookies.get("next-auth.session-token")

        # The adapter must not propagate that.
        name, value = adapter._extract_session_cookie(client)
        assert name == "next-auth.session-token"
        # Host-only (myapp.example.com, no leading dot) is most specific.
        assert value == "host_val"

    def test_full_auth_flow_with_duplicate_name_cookies(self):
        """End-to-end auth where the server sets host + parent cookies of
        the same name still resolves a session without CookieConflict."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        client = session.http_client
        client._cookies = httpx.Cookies()

        def mock_get(url, **kwargs):
            if "/api/auth/csrf" in url:
                return _MockResponse(200, json_body={"csrfToken": CSRF_TOKEN})
            elif "/api/auth/signin" in url:
                return _MockResponse(
                    200, text=SIGNIN_HTML, headers={"content-type": "text/html"}
                )
            elif "/api/auth/session" in url:
                return _MockResponse(
                    200,
                    json_body={"user": {"email": "a@example.com"}},
                )
            return _MockResponse(404)

        def mock_post(url, **kwargs):
            # Server sets the SAME session cookie name on two scopes.
            client._cookies.jar.set_cookie(
                _scoped_cookie(
                    "next-auth.session-token", "parent_val", ".example.com"
                )
            )
            client._cookies.jar.set_cookie(
                _scoped_cookie(
                    "next-auth.session-token",
                    "host_val",
                    "myapp.example.com",
                )
            )
            return _MockResponse(
                200,
                json_body={"url": f"{BASE_URL}/"},
                headers={"content-type": "application/json"},
            )

        client.get = mock_get
        client.post = mock_post

        # Must not raise httpx.CookieConflict.
        headers = adapter.get_headers("user_a")
        assert session.session_cookie_name == "next-auth.session-token"
        assert session.session_cookie_value == "host_val"
        assert "next-auth.session-token=host_val" in headers["Cookie"]


# ---------------------------------------------------------------------------
# Auth-time cooldown (Codex finding 2 — last_auth_time)
# ---------------------------------------------------------------------------

class TestAuthCooldown:
    """last_auth_time must be set after auth so is_expired() short-circuits."""

    def test_last_auth_time_set_after_authenticate(self, monkeypatch):
        """A successful _authenticate() records session.last_auth_time."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        assert session.last_auth_time == 0.0

        before = time.time()
        _setup_full_auth_flow(adapter, monkeypatch=monkeypatch)
        adapter.get_headers("user_a")

        assert session.last_auth_time >= before
        assert session.last_auth_time <= time.time()

    def test_cooldown_short_circuits_is_expired(self, monkeypatch):
        """After auth, is_expired() returns False WITHOUT a network call."""
        adapter = _make_adapter()
        client, call_log = _setup_full_auth_flow(adapter, monkeypatch=monkeypatch)
        adapter.get_headers("user_a")

        calls_after_auth = len(call_log)

        # Within the 30s cooldown: must not hit /api/auth/session again.
        assert adapter.is_expired("user_a") is False
        assert len(call_log) == calls_after_auth, (
            "is_expired() made a network call despite the cooldown — "
            "last_auth_time cooldown is dead code"
        )

    def test_is_expired_network_check_refreshes_cooldown(self):
        """A real /api/auth/session validity check refreshes last_auth_time."""
        adapter = _make_adapter()
        session = adapter._sessions["user_a"]
        session.session_cookie_name = "next-auth.session-token"
        session.session_cookie_value = "sess_val"
        session.http_client._cookies = _make_cookie_jar(
            {"next-auth.session-token": "sess_val"}
        )
        # last_auth_time stays 0.0 so the cooldown does NOT short-circuit;
        # the network check runs and should then anchor the cooldown.
        assert session.last_auth_time == 0.0

        def mock_get(url, **kwargs):
            return _MockResponse(
                200, json_body={"user": {"email": "a@example.com"}}
            )

        session.http_client.get = mock_get

        before = time.time()
        assert adapter.is_expired("user_a") is False
        assert session.last_auth_time >= before


# ---------------------------------------------------------------------------
# Non-sticky field-name fallback (Codex finding 3)
# ---------------------------------------------------------------------------

class TestNonStickyFieldCache:
    """Transient signin-discovery failure must NOT poison the cache."""

    def test_transient_failure_does_not_cache(self, monkeypatch):
        """First call: signin 503 -> default fields, NOT cached.
        Second call: signin 200 custom -> discovery re-attempted."""
        adapter = _make_adapter()

        state = {"signin_ok": False}

        def mock_get(url, **kwargs):
            if "/api/auth/signin" in url:
                if not state["signin_ok"]:
                    return _MockResponse(503, text="Service Unavailable")
                return _MockResponse(
                    200,
                    text=SIGNIN_HTML_CUSTOM_FIELDS,
                    headers={"content-type": "text/html"},
                )
            return _MockResponse(404)

        monkeypatch.setattr(
            "auth.nextauth.httpx.Client",
            lambda **_kw: _MockDiscoveryClient(mock_get),
        )

        # Transient failure path.
        fields1 = adapter._get_field_names()
        assert fields1 == {"email_field": "email", "password_field": "password"}
        assert adapter._field_names_cache is None, (
            "transient discovery failure must NOT be cached"
        )

        # Endpoint recovers — discovery must run again, not serve a cached
        # fallback.
        state["signin_ok"] = True
        fields2 = adapter._get_field_names()
        assert fields2 == {"email_field": "username", "password_field": "pass"}
        assert adapter._field_names_cache == fields2

    def test_network_error_does_not_cache(self, monkeypatch):
        """httpx.HTTPError during discovery -> default fields, NOT cached."""
        adapter = _make_adapter()

        def boom_get(url, **kwargs):
            raise httpx.ConnectError("network down")

        monkeypatch.setattr(
            "auth.nextauth.httpx.Client",
            lambda **_kw: _MockDiscoveryClient(boom_get),
        )

        fields = adapter._get_field_names()
        assert fields == {"email_field": "email", "password_field": "password"}
        assert adapter._field_names_cache is None

    def test_js_rendered_success_is_still_cached(self, monkeypatch):
        """A successful fetch with no <input> (JS form) IS cached -- that is
        a real successful discovery, not a transient failure."""
        adapter = _make_adapter()
        js_html = "<html><body><div id='app'></div></body></html>"

        def mock_get(url, **kwargs):
            if "/api/auth/signin" in url:
                return _MockResponse(
                    200, text=js_html, headers={"content-type": "text/html"}
                )
            return _MockResponse(404)

        monkeypatch.setattr(
            "auth.nextauth.httpx.Client",
            lambda **_kw: _MockDiscoveryClient(mock_get),
        )

        fields = adapter._get_field_names()
        assert fields == {"email_field": "email", "password_field": "password"}
        # Real successful fetch -> cached (not re-fetched next time).
        assert adapter._field_names_cache == fields


# ---------------------------------------------------------------------------
# Cleanup
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
            assert isinstance(adapter, NextAuthAdapter)

    def test_unknown_account_raises_value_error(self):
        """get_headers() with unknown account name raises ValueError."""
        adapter = _make_adapter()
        with pytest.raises(ValueError, match="Unknown account"):
            adapter.get_headers("user_z")
