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
