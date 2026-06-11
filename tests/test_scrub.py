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

from reports.scrub import _secrets_from_env, scrub_file, scrub_text


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
