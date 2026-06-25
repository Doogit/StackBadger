"""Secret scrubbing for ZAP reports before persistence and aggregation.

The ZAP JSON report embeds full request/response headers, which can carry
authentication secrets:

- **Bearer JWTs** — Clerk / Firebase / Supabase-Auth stacks seed an
  ``Authorization: Bearer <jwt>`` header.
- **NextAuth / Auth.js cookies** — cookie-based stacks seed a ``Cookie:``
  header. The NextAuth adapter's ``get_headers()`` exports the *entire* scoped
  cookie jar (session, CSRF, callback, and OAuth-flow cookies such as
  ``pkce.code_verifier`` / ``state`` / ``nonce``). These tokens are often
  opaque (database-session strategy / OAuth secrets) and are NOT ``eyJ``-shaped,
  so the Bearer/JWT patterns alone would let them through into the report.

Two layers of redaction run, in this order:

1. **Literal secrets** — the exact credential ``run.sh`` seeded into ZAP
   (passed via ``ZAP_SCRUB_SECRETS``). The seeded NextAuth cookie is the whole
   ``Cookie:`` header, so it is redacted both as a unit (catching any cookie
   name the allowlist below does not know) and per individual cookie value
   (catching a single seeded value reflected in isolation).
2. **Pattern redaction** — Bearer tokens, JWT/JWE-shaped values, and the values
   of known NextAuth / Auth.js cookie names. This catches Bearer/JWT-shaped or
   known-cookie-named credentials even when the harness did not seed them (e.g.
   a rolled session token, or another user's JWT reflected by an endpoint).

**Accepted residual:** an *opaque* (non-eyJ) token the harness never seeded,
appearing without a known cookie-name prefix (e.g. a second user's
database-session token reflected bare in a response body), matches neither
layer. A redactor cannot recognize an arbitrary opaque string it was never
given; such a reflection is itself a finding and is left for the operator.

Invoked from ``run.sh`` via ``python -m reports.scrub <report.json>``.

Regex dialect: Python ``re``. Match/no-match vectors live in
``tests/test_scrub.py`` per the project's regex-testing rule ([RX-TEST]).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# "Authorization: Bearer <token>" or any bare "Bearer <token>". The value class
# includes the full base64 / base64url alphabet (incl. + / =) so a standard-
# base64 opaque access token is not truncated mid-secret.
_BEARER_RE = re.compile(r"Bearer [A-Za-z0-9._/+=-]+")

# JWT / JWE-shaped values anywhere (base64url header starting "eyJ"). Catches
# Clerk/Firebase/Supabase Bearer payloads and Auth.js JWE session cookies.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9._/+=-]{20,}")

# NextAuth / Auth.js cookie names whose values are auth secrets. Covers v4
# (``next-auth.*``) and v5 (``authjs.*``): the session token, CSRF token,
# callback URL, and the OAuth-flow cookies (PKCE verifier, state, nonce) that
# ``get_headers()`` exports alongside the session. The regex additionally
# tolerates ``__Secure-`` / ``__Host-`` prefixes and chunk suffixes (``.0``,
# ``.1``, ... — used when the token exceeds the 4 KB cookie size limit).
_COOKIE_NAMES = (
    "next-auth.session-token",
    "authjs.session-token",
    "next-auth.csrf-token",
    "authjs.csrf-token",
    "next-auth.callback-url",
    "authjs.callback-url",
    "next-auth.pkce.code_verifier",
    "authjs.pkce.code_verifier",
    "next-auth.state",
    "authjs.state",
    "next-auth.nonce",
    "authjs.nonce",
)
_COOKIE_RE = re.compile(
    r"((?:__Secure-|__Host-)?(?:"
    + "|".join(re.escape(name) for name in _COOKIE_NAMES)
    + r")(?:\.\d+)?)="
    # Value runs until a cookie/header delimiter. Stops at ; , whitespace,
    # quote, or backslash so JSON-escaped header strings (``\"``) terminate it.
    + r"[^;,\"'\s\\]+"
)

# Literal secrets shorter than this are not redacted — too likely to collide
# with non-secret substrings and over-redact the report.
_MIN_SECRET_LEN = 8

# ---------------------------------------------------------------------------
# OAuth / delegated-send (Gmail / Drive / M365) response-body redaction
# ---------------------------------------------------------------------------
#
# EvidenceCapture persists response BODIES in full. The §P1-D delegated-send
# probe and §P1-B OAuth-client probes touch endpoints that can carry live
# OAuth tokens or restricted-scope user content (email text, Drive files), so a
# captured Response could otherwise write a real credential or PII to
# reports/evidence/. The probes themselves capture sanitized FakeResponse bodies,
# but this pass is the defense-in-depth gate (plan §6): it runs on every evidence
# body so a real Response that slips through is still scrubbed.

# Google OAuth access token (ya29.<...>), refresh token (1//<...>), and OAuth
# client secret (GOCSPX-<...>). These are bare secrets with no key=value wrapper,
# so the JWT/Bearer passes miss them.
_GOOGLE_ACCESS_TOKEN_RE = re.compile(r"ya29\.[A-Za-z0-9_.\-]{10,}")
_GOOGLE_REFRESH_TOKEN_RE = re.compile(r"1//[0-9A-Za-z_\-]{10,}")
_GOOGLE_CLIENT_SECRET_RE = re.compile(r"GOCSPX-[A-Za-z0-9_\-]{10,}")

# JSON token/secret field values. Redacts only the VALUE, preserving the field
# name so a leakage finding still shows WHICH secret was exposed (e.g.
# ``"access_token":"[REDACTED_TOKEN_VALUE]"``). Tolerates whitespace around the
# colon; stops at the closing quote so surrounding JSON structure survives.
_TOKEN_FIELD_NAMES = (
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "authorization_code",
    "token",
)
_TOKEN_FIELD_RE = re.compile(
    r'("(?:' + "|".join(_TOKEN_FIELD_NAMES) + r')"\s*:\s*)"[^"]*"'
)

# --- Token-DISCLOSURE detection (shared by the V10.1.1 leak probe) ----------
# The redaction regex above redacts ANY value (even short/empty) — safe to
# over-redact evidence. DETECTION is the opposite trade-off: it must flag a real
# disclosure without false-positiving on a benign field NAME (e.g.
# {"access_token_expired": false}), so it requires a NON-TRIVIAL value (>=16
# chars). Both detection and redaction draw on the SAME field-name vocabulary
# (_TOKEN_FIELD_NAMES) so the probe can never be narrower than the scrubber.
#
# JSON form: "access_token":"<16+ chars>". Form/query form: access_token=<16+>
# (\b prevents matching the tail of an unrelated key such as csrf_token=).
_TOKEN_VALUE_JSON_RE = re.compile(
    r'"(?:' + "|".join(_TOKEN_FIELD_NAMES) + r')"\s*:\s*"[^"]{16,}"'
)
_TOKEN_VALUE_FORM_RE = re.compile(
    r"\b(?:" + "|".join(_TOKEN_FIELD_NAMES) + r")=[^&\s\"'<>#]{16,}",
    re.IGNORECASE,
)


def contains_token_material(text: str) -> bool:
    """True when *text* discloses an OAuth token / secret VALUE.

    Single source of truth for the §P1-D leak probe so its detection can never be
    narrower than the redactor: covers bare Google access/refresh/client-secret
    shapes plus any value-bearing token field from :data:`_TOKEN_FIELD_NAMES` in
    either JSON (``"token":"..."``) or form/query (``access_token=...``) form.
    Requires a non-trivial value, so a benign field name with no real value (e.g.
    ``{"access_token_expired": false}``) is not a false positive.
    """
    if not text:
        return False
    return bool(
        _GOOGLE_ACCESS_TOKEN_RE.search(text)
        or _GOOGLE_REFRESH_TOKEN_RE.search(text)
        or _GOOGLE_CLIENT_SECRET_RE.search(text)
        or _TOKEN_VALUE_JSON_RE.search(text)
        or _TOKEN_VALUE_FORM_RE.search(text)
    )

# Sensitive query-string / fragment params whose VALUE is a credential or an
# authorization code carried in a URL (OAuth callback ``?code=`` or implicit-flow
# ``#access_token=``). Value preserved-key, redacted-value; stops at the next
# delimiter so the rest of the URL survives.
_URL_TOKEN_PARAM_RE = re.compile(
    r"((?:access_token|refresh_token|id_token|code|client_secret)=)[^&\s\"'<>#]+",
    re.IGNORECASE,
)

# Host substrings that, in a request URL, mean the whole response body is
# restricted-scope user content (Gmail / Drive / Graph). Any one is a strong
# enough signal to redact wholesale.
_SENSITIVE_HOST_MARKERS = (
    "gmail.googleapis.com",
    "www.googleapis.com/drive",
    "graph.microsoft.com",
)

# Drive-specific body markers distinctive enough to trigger wholesale redaction
# on their own (they do not appear in ordinary app JSON).
_STRONG_BODY_MARKERS = (
    '"webContentLink"',
    '"webViewLink"',
)

# Gmail body markers that are individually weak (a benign field may use the same
# name), so wholesale redaction requires TWO or more to co-occur — a real Gmail
# message resource carries several at once, a benign ``{"historyId": 5}`` carries
# one. This avoids over-redacting unrelated evidence (it would otherwise destroy a
# non-OAuth finding's body).
_WEAK_BODY_MARKERS = (
    '"snippet"',
    '"threadId"',
    '"labelIds"',
    '"historyId"',
    '"payload"',
)


def _is_gmail_drive_payload(body: str, url: str) -> bool:
    """True when the body should be wholesale-redacted as restricted-scope content."""
    if any(m in (url or "") or m in body for m in _SENSITIVE_HOST_MARKERS):
        return True
    if any(m in body for m in _STRONG_BODY_MARKERS):
        return True
    return sum(1 for m in _WEAK_BODY_MARKERS if m in body) >= 2


def _redact_token_shapes(text: str) -> str:
    """Redact bare Google token / client-secret shapes anywhere in *text*."""
    text = _GOOGLE_ACCESS_TOKEN_RE.sub("[REDACTED_OAUTH_TOKEN]", text)
    text = _GOOGLE_REFRESH_TOKEN_RE.sub("[REDACTED_OAUTH_TOKEN]", text)
    text = _GOOGLE_CLIENT_SECRET_RE.sub("[REDACTED_OAUTH_TOKEN]", text)
    return text


def scrub_evidence_body(body: str, url: str = "") -> str:
    """Return an evidence request/response *body* with OAuth secrets / PII removed.

    Layered, most-aggressive-first:

    1. **Gmail/Drive/M365 payload** — if the body (or its source *url* host) looks
       like a Gmail / Drive / Graph response, the entire body is replaced with a
       redaction marker. Such a body is wholesale restricted-scope user content.
       The trigger is a sensitive URL host, a Drive-specific body marker, or two+
       co-occurring Gmail markers (one weak marker alone does not over-redact a
       benign body).
    2. **Bearer / JWT / cookie** — the existing :func:`scrub_text` passes.
    3. **OAuth token shapes** — bare Google access/refresh tokens and client
       secrets, plus JSON ``access_token`` / ``refresh_token`` / ``id_token`` /
       ``client_secret`` / ``token`` field values (value only; field name
       preserved so a leak is still visible).

    ``url`` is the request URL; a googleapis/graph host triggers the wholesale
    redaction even when the body markers are absent (e.g. a binary Drive blob).
    """
    if not body:
        return body
    if _is_gmail_drive_payload(body, url or ""):
        return "[REDACTED: Gmail/Drive/M365 response body — restricted-scope content]"
    text = scrub_text(body)
    text = _redact_token_shapes(text)
    text = _TOKEN_FIELD_RE.sub(r'\1"[REDACTED_TOKEN_VALUE]"', text)
    return text


def scrub_locator(value: str) -> str:
    """Redact OAuth token material from a URL or single header value.

    Used for the evidence ``url`` field and non-credential header values, where a
    token can ride in a query string (``?code=`` / ``#access_token=``), a
    ``Location`` redirect, or a Bearer/JWT/cookie header. Preserves host/path and
    non-secret text so the evidence stays useful (e.g. open-redirect Location
    targets remain readable). NOT wholesale — never destroys the whole value.
    """
    if not value:
        return value
    out = scrub_text(value)                 # Bearer / JWT / known cookie values
    out = _redact_token_shapes(out)         # bare ya29. / 1// / GOCSPX- shapes
    out = _URL_TOKEN_PARAM_RE.sub(r"\1[REDACTED]", out)
    return out


def scrub_text(text: str, extra_secrets: tuple[str, ...] = ()) -> str:
    """Return ``text`` with auth secrets redacted.

    ``extra_secrets`` are exact credential strings (the values ``run.sh`` seeded
    into ZAP) redacted as literal substrings first, so the whole seeded value is
    removed as a unit before pattern redaction can fragment it. Then Bearer
    tokens, JWT/JWE-shaped values, and known NextAuth / Auth.js cookie values
    are redacted (cookie names are preserved so the report still shows *which*
    cookie was present).
    """
    for secret in extra_secrets:
        if secret and len(secret) >= _MIN_SECRET_LEN:
            text = text.replace(secret, "[REDACTED_SECRET]")
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    text = _COOKIE_RE.sub(r"\1=[REDACTED_COOKIE]", text)
    return text


def _expand_secret(raw: str):
    """Yield redaction targets for one seeded credential.

    A seeded NextAuth cookie is a ``name=value; name2=value2`` header; yield the
    whole header plus each individual cookie *value*, so a single value reflected
    in isolation is redacted even though the full-header literal would not match.
    Bearer/JWT values (no ``name=value`` structure) yield just themselves.
    """
    yield raw
    for pair in re.split(r"[;,]\s*", raw):
        if "=" in pair:
            value = pair.split("=", 1)[1]
            if value:
                yield value


def _secrets_from_env() -> tuple[str, ...]:
    """Read literal secrets from ``ZAP_SCRUB_SECRETS`` (newline-separated).

    Each non-blank line is expanded into the whole value plus its individual
    cookie values (see :func:`_expand_secret`), de-duplicated while preserving
    order. The ``_MIN_SECRET_LEN`` guard in :func:`scrub_text` drops any that are
    too short to redact safely.
    """
    raw = os.environ.get("ZAP_SCRUB_SECRETS", "")
    seen: dict[str, None] = {}
    for line in raw.splitlines():
        if line.strip():
            for target in _expand_secret(line):
                seen.setdefault(target, None)
    return tuple(seen)


def scrub_file(path: str | Path, extra_secrets: tuple[str, ...] = ()) -> None:
    """Scrub ``path`` in place (UTF-8)."""
    p = Path(path)
    p.write_text(
        scrub_text(p.read_text(encoding="utf-8"), extra_secrets),
        encoding="utf-8",
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m reports.scrub <report.json>", file=sys.stderr)
        raise SystemExit(2)
    scrub_file(sys.argv[1], _secrets_from_env())
