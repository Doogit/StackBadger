"""Tests for EvidenceCapture body redaction wiring (plan §6 evidence gate).

The scrub regexes themselves are covered in test_scrub.py; this verifies that
EvidenceCapture actually routes response/request bodies through scrub_evidence_body
before they are written to disk, so a captured OAuth/Gmail/Drive Response cannot
persist a live token or restricted-scope content to reports/evidence/.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from conftest import EvidenceCapture  # noqa: E402


def _written(tmp_path: Path) -> dict:
    """Return the single evidence JSON written under tmp_path."""
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1, f"expected one evidence file, got {files}"
    return json.loads(files[0].read_text(encoding="utf-8"))


def test_response_body_oauth_token_scrubbed_on_disk(tmp_path):
    cap = EvidenceCapture(node_id="tests/test_x.py::test_send", evidence_dir=tmp_path)
    req = httpx.Request("POST", "https://example.com/api/email/send")
    resp = httpx.Response(
        200, request=req,
        json={"access_token": "ya29.a0AfH6SMByLiveTokenValue1234567890", "ok": True},
    )
    cap.capture(resp, "send")

    record = _written(tmp_path)
    body = record["response"]["body"]
    assert "ya29.a0AfH6SMByLiveTokenValue1234567890" not in body
    assert "[REDACTED_TOKEN_VALUE]" in body
    assert '"ok": true' in body or '"ok":true' in body  # non-secret survives


def test_response_body_gmail_payload_scrubbed_on_disk(tmp_path):
    cap = EvidenceCapture(node_id="tests/test_x.py::test_read", evidence_dir=tmp_path)
    req = httpx.Request("GET", "https://example.com/api/inbox")
    resp = httpx.Response(
        200, request=req,
        json={"snippet": "Hi Bob, wire the funds to...", "threadId": "abc"},
    )
    cap.capture(resp, "read")

    body = _written(tmp_path)["response"]["body"]
    assert "wire the funds" not in body
    assert "restricted-scope content" in body


def test_request_body_client_secret_scrubbed_on_disk(tmp_path):
    cap = EvidenceCapture(node_id="tests/test_x.py::test_exchange", evidence_dir=tmp_path)
    req = httpx.Request(
        "POST", "https://example.com/api/oauth/token",
        json={"client_secret": "GOCSPX-liveSecretValue9999", "grant_type": "code"},
    )
    resp = httpx.Response(200, request=req, json={"ok": True})
    cap.capture(resp, "exchange")

    req_body = _written(tmp_path)["request"]["body"]
    assert "GOCSPX-liveSecretValue9999" not in req_body
    assert "[REDACTED_TOKEN_VALUE]" in req_body


def test_benign_app_response_left_intact(tmp_path):
    cap = EvidenceCapture(node_id="tests/test_x.py::test_plain", evidence_dir=tmp_path)
    req = httpx.Request("GET", "https://example.com/api/item/42")
    resp = httpx.Response(200, request=req, json={"id": 42, "status": "ok"})
    cap.capture(resp, "plain")

    body = _written(tmp_path)["response"]["body"]
    assert '"id": 42' in body or '"id":42' in body
    assert "ok" in body


def test_url_field_oauth_code_scrubbed_on_disk(tmp_path):
    # An OAuth callback code in the request URL must not persist verbatim.
    cap = EvidenceCapture(node_id="tests/test_x.py::test_cb", evidence_dir=tmp_path)
    req = httpx.Request(
        "GET", "https://example.com/api/oauth/callback?code=4/0AeLiveAuthCode123&state=s"
    )
    resp = httpx.Response(200, request=req, json={"ok": True})
    cap.capture(resp, "cb")

    url = _written(tmp_path)["request"]["url"]
    assert "4/0AeLiveAuthCode123" not in url
    assert "code=[REDACTED]" in url
    # Path/host preserved for debugging.
    assert "https://example.com/api/oauth/callback" in url


def test_location_header_token_scrubbed_on_disk(tmp_path):
    # A token in a (non-denylisted) Location redirect header must be scrubbed.
    cap = EvidenceCapture(node_id="tests/test_x.py::test_redir", evidence_dir=tmp_path)
    req = httpx.Request("GET", "https://example.com/connect")
    resp = httpx.Response(
        302, request=req,
        headers={"location": "https://example.com/cb#access_token=ya29.aLiveTokenValue123456"},
    )
    cap.capture(resp, "redir")

    loc = _written(tmp_path)["response"]["headers"]["location"]
    assert "ya29.aLiveTokenValue123456" not in loc


def test_request_cookie_header_redacted_on_disk(tmp_path):
    # The request Cookie header (session/PKCE/state) is now denylisted.
    cap = EvidenceCapture(node_id="tests/test_x.py::test_cookie", evidence_dir=tmp_path)
    req = httpx.Request(
        "GET", "https://example.com/api/me",
        headers={"cookie": "next-auth.session-token=opaqueSessionValue123456789"},
    )
    resp = httpx.Response(200, request=req, json={"ok": True})
    cap.capture(resp, "cookie")

    cookie = _written(tmp_path)["request"]["headers"]["cookie"]
    assert "opaqueSessionValue123456789" not in cookie
