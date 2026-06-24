"""Tests for ZAP report secret scrubbing (reports.scrub).

Match/no-match vectors for the redaction regexes, including the cookie-shaped
secret vectors that motivated extending the scrubber for NextAuth support.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from reports.scrub import (
    _secrets_from_env,
    scrub_evidence_body,
    scrub_file,
    scrub_text,
)


# ---------------------------------------------------------------------------
# Bearer / JWT (existing behavior — guard against regression)
# ---------------------------------------------------------------------------

def test_bearer_header_redacted():
    out = scrub_text("Authorization: Bearer abc123.def-456_GHI")
    assert "abc123" not in out
    assert "Bearer [REDACTED]" in out


def test_jwt_shaped_value_redacted():
    jwt = "eyJ" + "A1b2C3d4E5f6G7h8I9j0" + ".payloadpart.sigpart_-"
    out = scrub_text(f'{{"token":"{jwt}"}}')
    assert "payloadpart" not in out
    assert "[REDACTED_JWT]" in out


def test_bearer_with_standard_base64_chars_not_truncated():
    # Opaque/standard-base64 access tokens contain + / = — the whole token
    # must be redacted, not truncated at the first such char.
    out = scrub_text("Authorization: Bearer ab+cd/ef12+gh/ij==")
    assert "cd/ef" not in out and "gh/ij" not in out
    assert "Bearer [REDACTED]" in out


def test_bearer_jwt_redacted_once_bearer_wins():
    # A Bearer value that is itself a JWT redacts via the Bearer pass (sharper
    # than the test_scrub_file 'or' assertion — guards the Bearer pass itself).
    out = scrub_text("Authorization: Bearer eyJabcdefghijklmnopqrstuvwxyz0123")
    assert out == "Authorization: Bearer [REDACTED]"


def test_jwt_min_length_boundary():
    # _JWT_RE requires 20+ chars after eyJ. Pin the boundary so a future edit
    # can't loosen it.
    nineteen = "eyJ" + "a" * 19
    twenty = "eyJ" + "a" * 20
    assert scrub_text(f"x={nineteen}") == f"x={nineteen}"      # no match
    assert "[REDACTED_JWT]" in scrub_text(f"x={twenty}")        # match


# ---------------------------------------------------------------------------
# NextAuth / Auth.js cookie redaction (the new coverage)
# ---------------------------------------------------------------------------

def test_opaque_session_cookie_redacted_name_preserved():
    # Opaque (non-eyJ) database-session token — the case Bearer/JWT miss.
    raw = "Cookie: next-auth.session-token=9f8e7d6c5b4a3210deadbeef; theme=dark"
    out = scrub_text(raw)
    assert "9f8e7d6c5b4a3210deadbeef" not in out
    assert "next-auth.session-token=[REDACTED_COOKIE]" in out
    # Non-secret cookie left intact.
    assert "theme=dark" in out


def test_secure_authjs_v5_cookie_redacted():
    raw = "Cookie: __Secure-authjs.session-token=opaqueValue123456; other=1"
    out = scrub_text(raw)
    assert "opaqueValue123456" not in out
    assert "__Secure-authjs.session-token=[REDACTED_COOKIE]" in out


def test_chunked_session_cookie_redacted():
    raw = (
        "Cookie: next-auth.session-token.0=chunkAAAA1111; "
        "next-auth.session-token.1=chunkBBBB2222"
    )
    out = scrub_text(raw)
    assert "chunkAAAA1111" not in out
    assert "chunkBBBB2222" not in out
    assert out.count("[REDACTED_COOKIE]") == 2


def test_csrf_and_callback_cookies_redacted():
    raw = (
        "Cookie: authjs.csrf-token=tok123%7Chmac456; "
        "authjs.callback-url=https%3A%2F%2Fexample.com"
    )
    out = scrub_text(raw)
    assert "tok123" not in out
    assert "example.com" not in out
    assert out.count("[REDACTED_COOKIE]") == 2


def test_oauth_flow_cookies_redacted():
    # get_headers() exports the full jar, including PKCE/state/nonce cookies
    # which are opaque OAuth secrets (not eyJ-shaped).
    raw = (
        "Cookie: next-auth.pkce.code_verifier=verifierSECRET123; "
        "authjs.state=stateSECRET456; next-auth.nonce=nonceSECRET789"
    )
    out = scrub_text(raw)
    assert "verifierSECRET123" not in out
    assert "stateSECRET456" not in out
    assert "nonceSECRET789" not in out
    assert out.count("[REDACTED_COOKIE]") == 3


def test_json_escaped_header_terminates_at_quote():
    # As embedded in a ZAP JSON report: header value ends at an escaped quote.
    raw = '{"header":"Cookie: authjs.session-token=secretvalue999\\",\\"next\\":1}'
    out = scrub_text(raw)
    assert "secretvalue999" not in out
    assert "authjs.session-token=[REDACTED_COOKIE]" in out
    # Structure after the value survives.
    assert '\\"next\\":1' in out


# ---------------------------------------------------------------------------
# No-match / non-over-redaction
# ---------------------------------------------------------------------------

def test_unrelated_cookie_not_redacted():
    raw = "Cookie: session_id=keepme123; csrftoken=keepme456"
    out = scrub_text(raw)
    # These names are not NextAuth auth cookies — must pass through.
    assert out == raw


def test_cookie_name_without_value_unchanged():
    # A bare reference to the cookie name (no "=value") should not match.
    raw = "The next-auth.session-token cookie was set."
    assert scrub_text(raw) == raw


# ---------------------------------------------------------------------------
# Literal seeded-secret redaction (extra_secrets) — catches the exact value
# run.sh seeded, including cookie names the allowlist does not know.
# ---------------------------------------------------------------------------

def test_extra_secret_redacts_full_seeded_cookie_header():
    # The seeded Cookie header carries an unknown (non-allowlisted) cookie too;
    # the literal-secret pass redacts the whole thing as a unit.
    seeded = "next-auth.session-token=abc123def456; custom-app-cookie=opaqueXYZ789"
    raw = f'{{"req":"Cookie: {seeded}"}}'
    out = scrub_text(raw, extra_secrets=(seeded,))
    assert "abc123def456" not in out
    assert "opaqueXYZ789" not in out
    assert "[REDACTED_SECRET]" in out


def test_extra_secret_below_min_length_not_redacted():
    # Short secrets are skipped to avoid over-redaction.
    raw = "value is short1"
    assert scrub_text(raw, extra_secrets=("short1",)) == raw


def test_extra_secret_empty_string_ignored():
    raw = "nothing to redact here"
    assert scrub_text(raw, extra_secrets=("",)) == raw


def test_secrets_from_env_expands_cookie_values(monkeypatch):
    # run.sh seeds ZAP_SCRUB_SECRETS as "<full Cookie header>\n<jwt>". The env
    # reader must yield the whole header AND each individual cookie value so a
    # single value reflected alone (not the full header) is still redactable.
    monkeypatch.setenv(
        "ZAP_SCRUB_SECRETS",
        "next-auth.session-token=sessVALUE1234567; theme=dark\n"
        "eyJjwtVALUEabcdefghij1234567890",
    )
    secrets = _secrets_from_env()
    assert "next-auth.session-token=sessVALUE1234567; theme=dark" in secrets
    assert "sessVALUE1234567" in secrets          # individual value expanded
    assert "eyJjwtVALUEabcdefghij1234567890" in secrets

    # A bare reflected session value (no full-header context) is now redacted.
    reflected = '{"leaked":"sessVALUE1234567"}'
    out = scrub_text(reflected, extra_secrets=secrets)
    assert "sessVALUE1234567" not in out


def test_secrets_from_env_empty(monkeypatch):
    monkeypatch.delenv("ZAP_SCRUB_SECRETS", raising=False)
    assert _secrets_from_env() == ()


# ---------------------------------------------------------------------------
# OAuth / Gmail / Drive / M365 evidence-body redaction (scrub_evidence_body)
# ---------------------------------------------------------------------------

def test_evidence_body_redacts_google_access_token():
    body = '{"access_token":"ya29.a0AfH6SMByExampleTokenValue123","expires_in":3599}'
    out = scrub_evidence_body(body)
    assert "ya29.a0AfH6SMByExampleTokenValue123" not in out
    # JSON field-value redaction fires on the access_token field.
    assert "[REDACTED_TOKEN_VALUE]" in out
    # Field name preserved so a leak finding still shows what was exposed.
    assert '"access_token"' in out
    # expires_in (non-secret) survives.
    assert "3599" in out


def test_evidence_body_redacts_google_refresh_token_bare():
    # A bare refresh token with no JSON wrapper (the shape-pass must catch it).
    body = "token is 1//0eXampleRefreshTokenValue_abc-DEF here"
    out = scrub_evidence_body(body)
    assert "1//0eXampleRefreshTokenValue_abc-DEF" not in out
    assert "[REDACTED_OAUTH_TOKEN]" in out


def test_evidence_body_redacts_client_secret_field():
    body = '{"client_secret":"GOCSPX-supersecretvalue123","grant_type":"refresh_token"}'
    out = scrub_evidence_body(body)
    assert "GOCSPX-supersecretvalue123" not in out
    assert '"client_secret":"[REDACTED_TOKEN_VALUE]"' in out
    # grant_type is not a secret field — left intact.
    assert "refresh_token" in out


def test_evidence_body_wholesale_redacts_gmail_payload():
    body = '{"id":"18c","snippet":"Hi Bob, the invoice is attached","threadId":"18c"}'
    out = scrub_evidence_body(body)
    assert "Hi Bob" not in out
    assert "invoice" not in out
    assert "restricted-scope content" in out


def test_evidence_body_wholesale_redacts_drive_payload():
    body = '{"name":"Q3-financials.pdf","webContentLink":"https://drive/download/abc"}'
    out = scrub_evidence_body(body)
    assert "Q3-financials.pdf" not in out
    assert "restricted-scope content" in out


def test_evidence_body_redacts_by_sensitive_url_host():
    # A binary/opaque Drive blob with no JSON markers — the URL host triggers it.
    body = "PK\x03\x04 binary zip bytes pretending to be a drive export"
    out = scrub_evidence_body(body, url="https://www.googleapis.com/drive/v3/files/abc?alt=media")
    assert "binary zip bytes" not in out
    assert "restricted-scope content" in out


def test_evidence_body_preserves_benign_app_response():
    # A normal app JSON response with no token shapes / Gmail markers is untouched
    # so ordinary evidence stays debuggable (e.g. an IDOR finding's body).
    body = '{"id":42,"owner":"user_b","status":"ok"}'
    assert scrub_evidence_body(body) == body


def test_evidence_body_email_in_plain_app_response_kept():
    # An email in a generic app response is NOT redacted (it may BE the finding,
    # e.g. an IDOR leaking another user's address); only Gmail/Drive payloads are
    # wholesale-redacted. This pins that scoping decision.
    body = '{"contact":"victim@example.com"}'
    assert scrub_evidence_body(body) == body


def test_evidence_body_still_redacts_bearer_and_jwt():
    # scrub_evidence_body composes the base scrub_text passes.
    jwt = "eyJ" + "A1b2C3d4E5f6G7h8I9j0" + ".payloadpart.sigpart"
    out = scrub_evidence_body(f'{{"authorization":"Bearer {jwt}"}}')
    assert "payloadpart" not in out
    assert "Bearer [REDACTED]" in out or "[REDACTED_JWT]" in out


def test_evidence_body_empty_passthrough():
    assert scrub_evidence_body("") == ""
    assert scrub_evidence_body("[body omitted]") == "[body omitted]"


# ---------------------------------------------------------------------------
# File round-trip
# ---------------------------------------------------------------------------

def test_scrub_file_in_place(tmp_path):
    p = tmp_path / "zap-report.json"
    p.write_text(
        '{"req":"Cookie: next-auth.session-token=topsecretcookie; a=b",'
        '"auth":"Authorization: Bearer eyJabcdefghijklmnopqrstuvwxyz0123"}',
        encoding="utf-8",
    )
    scrub_file(p)
    out = p.read_text(encoding="utf-8")
    assert "topsecretcookie" not in out
    assert "Bearer [REDACTED]" in out or "[REDACTED_JWT]" in out
    assert "[REDACTED_COOKIE]" in out
    assert "a=b" in out
