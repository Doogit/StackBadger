"""Unit tests for discover_live() in discover.py.

All HTTP calls are mocked via unittest.mock so no real network is required.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# Ensure the package root is on the path so ``import discover`` works when
# pytest is invoked from any working directory.
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent       # tests/
_PKG_ROOT = _HERE.parent                      # StackBadger/
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from discover import discover_live, _decode_clerk_fapi_host  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jwt(role: str = "anon") -> str:
    """Craft a minimal syntactically-valid JWT with the given role in payload."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload_bytes = json.dumps({"role": role, "iss": "supabase"}).encode()
    payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    # Signature segment: arbitrary valid base64url block
    sig = base64.urlsafe_b64encode(b"fakesignature1234").rstrip(b"=").decode()
    return f"eyJhbGci{header}.{payload}.{sig}"


def _encode_fapi_host(hostname: str) -> str:
    """Encode a hostname the way Clerk encodes it in pk_test_/<pk_live_ keys."""
    encoded = base64.b64encode(hostname.encode()).rstrip(b"=").decode()
    return f"pk_test_{encoded}$"


def _mock_response(
    status_code: int = 200,
    text: str = "",
    headers: dict | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp


def _mock_client_response(
    status_code: int = 200,
    text: str = "",
) -> MagicMock:
    """Return a MagicMock usable as an httpx.Client.get() return value."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {}
    return resp


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------

class TestDiscoverLiveHappyPath:
    """Verify that all five fields are extracted when present in bundles."""

    def test_all_fields_returned(self):
        """HTML with script tags, JS with Supabase URL + anon JWT + Clerk pk."""
        supabase_url = "https://abcdefghij.supabase.co"
        anon_jwt = _make_jwt("anon")
        fapi_host = "clerk.example.com"
        clerk_pk = _encode_fapi_host(fapi_host)
        api_prefix = "/.netlify/functions/"

        html = f'<html><head><script src="/assets/index.js"></script></head></html>'
        js_bundle = (
            f'var SUPABASE_URL="{supabase_url}";'
            f'var SUPABASE_ANON_KEY="{anon_jwt}";'
            f'var CLERK_PK="{clerk_pk}";'
            f'fetch("{api_prefix}my-func");'
        )

        mock_html_resp = _mock_response(200, html)
        mock_js_resp = _mock_client_response(200, js_bundle)

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.get = MagicMock(return_value=mock_js_resp)

        with patch("httpx.get", return_value=mock_html_resp), \
             patch("httpx.Client", return_value=mock_client_instance):
            result = discover_live("https://example.com")

        assert result["supabase_url"] == supabase_url
        assert result["supabase_anon_key"] == anon_jwt
        assert result["clerk_publishable_key"] == clerk_pk
        assert result["clerk_fapi_host"] == fapi_host
        assert result["api_prefix"] == api_prefix

    def test_pk_live_also_handled(self):
        """pk_live_ prefix is decoded correctly alongside pk_test_."""
        fapi_host = "clerk.prod-example.com"
        encoded = base64.b64encode(fapi_host.encode()).rstrip(b"=").decode()
        clerk_pk_live = f"pk_live_{encoded}$"

        html = '<html><head><script src="/bundle.js"></script></head></html>'
        js_bundle = f'var PK="{clerk_pk_live}";'

        mock_html_resp = _mock_response(200, html)
        mock_js_resp = _mock_client_response(200, js_bundle)

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.get = MagicMock(return_value=mock_js_resp)

        with patch("httpx.get", return_value=mock_html_resp), \
             patch("httpx.Client", return_value=mock_client_instance):
            result = discover_live("https://example.com")

        assert result["clerk_publishable_key"] == clerk_pk_live
        assert result["clerk_fapi_host"] == fapi_host


class TestClerkFapiHostDerivation:
    """FAPI host is correctly derived from the publishable key via base64 decode."""

    def test_pk_test_decodes_correctly(self):
        fapi_host = "happy-dog-12.clerk.accounts.dev"
        pk = _encode_fapi_host(fapi_host)
        assert _decode_clerk_fapi_host(pk) == fapi_host

    def test_pk_live_decodes_correctly(self):
        fapi_host = "myapp.clerk.accounts.com"
        encoded = base64.b64encode(fapi_host.encode()).rstrip(b"=").decode()
        pk = f"pk_live_{encoded}$"
        assert _decode_clerk_fapi_host(pk) == fapi_host

    def test_malformed_base64_returns_none(self):
        """Garbage after prefix → None with warning."""
        result = _decode_clerk_fapi_host("pk_test_!!!not-valid-base64!!!")
        assert result is None

    def test_no_dot_in_decoded_returns_none(self):
        """Decoded value without a dot is not a valid hostname."""
        # Encode a string with no dots
        no_dot = base64.b64encode(b"nodothere").rstrip(b"=").decode()
        pk = f"pk_test_{no_dot}$"
        result = _decode_clerk_fapi_host(pk)
        assert result is None

    def test_whitespace_in_decoded_returns_none(self):
        """Decoded value with whitespace is not a valid hostname."""
        bad = base64.b64encode(b"host name.com").rstrip(b"=").decode()
        pk = f"pk_test_{bad}$"
        result = _decode_clerk_fapi_host(pk)
        assert result is None

    def test_unknown_prefix_returns_none(self):
        """Keys without pk_test_ or pk_live_ are not handled."""
        result = _decode_clerk_fapi_host("pk_staging_abc123")
        assert result is None


# ---------------------------------------------------------------------------
# WAF detection
# ---------------------------------------------------------------------------

class TestWafDetection:
    """WAF challenge pages return all-None dict with a stderr warning."""

    def test_cloudflare_challenge_returns_all_none(self, capsys):
        waf_html = (
            '<html><body>'
            '<script>window._cf_chl_opt = {cType: "managed"};</script>'
            '<script src="https://challenges.cloudflare.com/cf-chl-bypass"></script>'
            '</body></html>'
        )
        mock_html_resp = _mock_response(403, waf_html)

        with patch("httpx.get", return_value=mock_html_resp):
            result = discover_live("https://example.com")

        assert result["supabase_url"] is None
        assert result["supabase_anon_key"] is None
        assert result["clerk_publishable_key"] is None
        assert result["clerk_fapi_host"] is None
        assert result["api_prefix"] is None
        captured = capsys.readouterr()
        assert "WAF" in captured.err

    def test_aws_waf_header_returns_all_none(self, capsys):
        mock_html_resp = _mock_response(
            200,
            "<html><body>blocked</body></html>",
            headers={"x-amzn-waf-action": "BLOCK"},
        )

        with patch("httpx.get", return_value=mock_html_resp):
            result = discover_live("https://example.com")

        assert result["supabase_url"] is None
        assert result["clerk_publishable_key"] is None
        assert result["api_prefix"] is None
        captured = capsys.readouterr()
        assert "WAF" in captured.err


# ---------------------------------------------------------------------------
# No script tags
# ---------------------------------------------------------------------------

class TestNoScriptTags:
    """HTML with no <script src=...> tags returns all-None with warning."""

    def test_no_script_tags_returns_all_none(self, capsys):
        html = "<html><body><p>Hello world</p></body></html>"
        mock_html_resp = _mock_response(200, html)

        with patch("httpx.get", return_value=mock_html_resp):
            result = discover_live("https://example.com")

        assert result["supabase_url"] is None
        assert result["clerk_publishable_key"] is None
        assert result["api_prefix"] is None
        captured = capsys.readouterr()
        assert "script" in captured.err.lower() or "not found" in captured.err.lower()


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    """Multiple matches for the same pattern are deduplicated; first match wins."""

    def test_multiple_jwt_matches_uses_first_anon_jwt(self):
        supabase_url = "https://xyz.supabase.co"
        anon_jwt_1 = _make_jwt("anon")
        anon_jwt_2 = _make_jwt("anon")
        service_jwt = _make_jwt("service_role")

        # anon_jwt_1 appears first; anon_jwt_2 and service_jwt appear after
        html = '<html><head><script src="/app.js"></script></head></html>'
        js = (
            f'"{anon_jwt_1}" "{anon_jwt_2}" "{service_jwt}" '
            f'"{supabase_url}"'
        )

        mock_html_resp = _mock_response(200, html)
        mock_js_resp = _mock_client_response(200, js)

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.get = MagicMock(return_value=mock_js_resp)

        with patch("httpx.get", return_value=mock_html_resp), \
             patch("httpx.Client", return_value=mock_client_instance):
            result = discover_live("https://example.com")

        # First anon JWT should be selected
        assert result["supabase_anon_key"] == anon_jwt_1

    def test_multiple_supabase_urls_uses_first(self):
        url_1 = "https://first.supabase.co"
        url_2 = "https://second.supabase.co"

        html = '<html><head><script src="/app.js"></script></head></html>'
        js = f'"{url_1}" "{url_2}"'

        mock_html_resp = _mock_response(200, html)
        mock_js_resp = _mock_client_response(200, js)

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.get = MagicMock(return_value=mock_js_resp)

        with patch("httpx.get", return_value=mock_html_resp), \
             patch("httpx.Client", return_value=mock_client_instance):
            result = discover_live("https://example.com")

        assert result["supabase_url"] == url_1


# ---------------------------------------------------------------------------
# Target unreachable
# ---------------------------------------------------------------------------

class TestTargetUnreachable:
    """Connection error raises RuntimeError with a clear message."""

    def test_connection_error_raises(self):
        import httpx as _httpx
        with patch("httpx.get", side_effect=_httpx.ConnectError("connection refused")):
            with pytest.raises(RuntimeError, match="target unreachable"):
                discover_live("https://unreachable.invalid")

    def test_timeout_raises(self):
        import httpx as _httpx
        with patch("httpx.get", side_effect=_httpx.TimeoutException("timed out")):
            with pytest.raises(RuntimeError, match="target unreachable"):
                discover_live("https://slow.invalid")


# ---------------------------------------------------------------------------
# Relative URL resolution
# ---------------------------------------------------------------------------

class TestRelativeUrlResolution:
    """Relative script src values are resolved against the target base URL."""

    def test_root_relative_script_resolved(self):
        """A src like '/assets/index.js' is fetched from the target host."""
        supabase_url = "https://proj.supabase.co"
        anon_jwt = _make_jwt("anon")

        html = '<html><head><script src="/assets/index.js"></script></head></html>'
        js = f'"{supabase_url}" "{anon_jwt}"'

        mock_html_resp = _mock_response(200, html)
        mock_js_resp = _mock_client_response(200, js)

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.get = MagicMock(return_value=mock_js_resp)

        with patch("httpx.get", return_value=mock_html_resp), \
             patch("httpx.Client", return_value=mock_client_instance):
            result = discover_live("https://myapp.com")

        # Verify the JS was fetched using the absolute URL derived from the base
        fetched_url = mock_client_instance.get.call_args[0][0]
        assert fetched_url.startswith("https://myapp.com")
        assert result["supabase_url"] == supabase_url

    def test_protocol_relative_script_resolved(self):
        """A src like '//cdn.example.com/app.js' gets https: prepended."""
        supabase_url = "https://proj.supabase.co"
        anon_jwt = _make_jwt("anon")

        html = '<html><head><script src="//cdn.example.com/app.js"></script></head></html>'
        js = f'"{supabase_url}" "{anon_jwt}"'

        mock_html_resp = _mock_response(200, html)
        mock_js_resp = _mock_client_response(200, js)

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.get = MagicMock(return_value=mock_js_resp)

        with patch("httpx.get", return_value=mock_html_resp), \
             patch("httpx.Client", return_value=mock_client_instance):
            result = discover_live("https://myapp.com")

        fetched_url = mock_client_instance.get.call_args[0][0]
        assert fetched_url.startswith("https://cdn.example.com")


# ---------------------------------------------------------------------------
# /api/ prefix variant
# ---------------------------------------------------------------------------

class TestApiPrefix:
    """Both /.netlify/functions/ and /api/ prefixes are detected."""

    def test_api_prefix_detected(self):
        html = '<html><head><script src="/bundle.js"></script></head></html>'
        js = 'fetch("/api/submit", {method: "POST"});'

        mock_html_resp = _mock_response(200, html)
        mock_js_resp = _mock_client_response(200, js)

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)
        mock_client_instance.get = MagicMock(return_value=mock_js_resp)

        with patch("httpx.get", return_value=mock_html_resp), \
             patch("httpx.Client", return_value=mock_client_instance):
            result = discover_live("https://example.com")

        assert result["api_prefix"] == "/api/"
