"""Data-protection probes — secrets/PII in URLs, cache hygiene, host-surface awareness.

ASVS 5.0:
  - V14.2.1 (L1): the application does not include sensitive information in the
    URL or query string (tokens, session ids, API keys, credentials, PII).
  - V14.3.2: responses carrying sensitive data set Cache-Control: no-store (or
    no-cache / private) so they are not written to shared or browser caches.
  - V14.3.3: defence-in-depth response headers (Referrer-Policy, etc.) that keep
    URLs and data from leaking to third parties.

CWE-598 (sensitive data in GET/URL/query) · CWE-200 (information exposure) ·
CWE-524 (sensitive information in a cache).

Read-only by design
-------------------
Every probe here is a GET / observation probe — it sends no INSERT/UPDATE/
DELETE/upload, so NONE carry ``@pytest.mark.write_probe``. They are dual-tagged
``asvs(...)`` + ``cwe(...)`` for the coverage ledger; the heavier follow-a-
redirect scan also carries ``@pytest.mark.asvs_extended`` (SCAN_SCOPE=asvs).

Host-surface awareness
----------------------
Response-header defaults differ per managed host (Netlify vs Vercel vs
Cloudflare emit different default Cache-Control / Referrer-Policy behaviour), so
the cache probe records the derived host surface in its message rather than
assuming Netlify. The host is derived from ``profile.stack.hosting`` and, as a
fallback, ``profile.target.api_prefix``. Where the host is unknown the probe
still runs (the no-store requirement is host-independent) but documents the
unknown surface in the evidence/assert text.

Secret-never-persisted invariant
--------------------------------
A URL or redirect Location may itself carry a token. We therefore NEVER capture
the raw response to evidence: every capture goes through
``FakeResponse(status, sanitized_url, "[body omitted]", method)`` with the
URL stripped of its query string, mirroring tests/test_session.py.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path
from urllib.parse import unquote, urlsplit

import httpx
import pytest

# ---------------------------------------------------------------------------
# Package-root import shim (mirrors the other test modules)
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from tests.conftest import endpoints_for_category, probe_body_for  # noqa: E402
from tests.helpers import (  # noqa: E402
    FakeResponse,
    cache_control_is_safe,
    netlify_url,
)


# ---------------------------------------------------------------------------
# Secret / PII patterns scanned for in app-generated URLs and redirects
# ---------------------------------------------------------------------------

# HIGH-confidence sensitive query-parameter NAMES (case-insensitive). A value
# carried under one of these keys in a URL is a CWE-598 finding regardless of the
# value shape — the key name alone names a credential/secret/session, so we
# self-escalate to HIGH. (A short OAuth ``code`` is deliberately NOT here.)
_HIGH_PARAM_KEYS = (
    "access_token",
    "refresh_token",
    "id_token",
    "apikey",
    "api_key",
    "api-key",
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "session",
    "sessionid",
    "session_id",
    "sid",
    "authorization",
    "jwt",
)

# AMBIGUOUS parameter NAMES. These keys (``code``/``key``/``auth``/``token``)
# routinely carry benign values: an OAuth authorization-code redirect
# (``?code=...&state=...``), a publishable key, etc. A bare match here does NOT
# self-escalate to HIGH; it only becomes a HIGH finding when the VALUE itself is
# secret-shaped (a JWT or a long high-entropy token — see _scan_url_for_secrets).
_AMBIGUOUS_PARAM_KEYS = (
    "token",
    "auth",
    "key",
    "code",
)

# A JWT-shaped string: three base64url segments separated by dots. This catches
# bearer/id tokens reflected into a URL even under an unexpected key name.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

# A plausible email address (PII) appearing anywhere in the URL.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# A long, high-entropy value — a credential-shaped string even without a JWT
# header. Used to qualify an AMBIGUOUS key's value as secret-shaped (so a short
# OAuth ``code`` does not fire, but a 40+ char opaque token does).
_HIGH_ENTROPY_VALUE_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{40,}$")

# ``key=value`` pairs whose KEY is HIGH-confidence sensitive — self-escalates.
_HIGH_KV_RE = re.compile(
    r"(?i)(?:^|[?&#])(" + "|".join(re.escape(k) for k in _HIGH_PARAM_KEYS) + r")=([^&#\s]+)"
)

# ``key=value`` pairs whose KEY is AMBIGUOUS — only a finding if the value is
# secret-shaped.
_AMBIGUOUS_KV_RE = re.compile(
    r"(?i)(?:^|[?&#])(" + "|".join(re.escape(k) for k in _AMBIGUOUS_PARAM_KEYS) + r")=([^&#\s]+)"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_url(url: str) -> str:
    """Drop the query string and fragment so a captured URL never leaks a token.

    Returns scheme://host/path only — enough to identify the offending endpoint
    in the report without persisting the secret-bearing query.
    """
    parts = urlsplit(url)
    if not parts.scheme:
        return url.split("?", 1)[0].split("#", 1)[0]
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _scan_url_for_secrets(url: str) -> tuple[list[str], list[str]]:
    """Scan a URL for secret/PII leakage. Return ``(high_reasons, low_reasons)``.

    Scans the full URL — path, query AND fragment — after percent-decoding, so
    encoded params (``%65yJ...``) and implicit-flow ``#access_token=...``
    fragments do not evade detection. Reason strings deliberately name the *kind*
    of leak, never the secret value.

    HIGH reasons self-escalate the finding to HIGH severity:
      - a HIGH-confidence sensitive key (access_token, password, secret, ...),
      - a JWT-shaped value under ANY key,
      - an AMBIGUOUS key (code/key/auth/token) whose value is itself
        secret-shaped (JWT or long high-entropy).

    LOW reasons are recorded but do NOT escalate (e.g. an email address, or a
    bare ``?code=<short>`` OAuth redirect that is benign on its own).
    """
    high: list[str] = []
    low: list[str] = []
    if not url:
        return high, low

    # Percent-decode so encoded keys/values are matched, then also scan the
    # fragment (implicit-flow ``#access_token=eyJ...``), which urlsplit() keeps
    # out of ``query``.
    decoded = unquote(url)
    parts = urlsplit(decoded)
    # Build the set of strings the regexes run against: the full decoded URL
    # plus the fragment treated as a query-like ``key=value`` blob (prefixed
    # with ``?`` so the ``(?:^|[?&#])`` anchor fires on its first pair).
    scan_targets = [decoded]
    if parts.fragment:
        scan_targets.append("?" + parts.fragment)

    for target in scan_targets:
        for m in _HIGH_KV_RE.finditer(target):
            high.append(
                f"sensitive query parameter '{m.group(1).lower()}=' present in URL"
            )
        for m in _AMBIGUOUS_KV_RE.finditer(target):
            value = m.group(2)
            if _JWT_RE.search(value) or _HIGH_ENTROPY_VALUE_RE.match(value):
                high.append(
                    f"ambiguous parameter '{m.group(1).lower()}=' carries a "
                    "secret-shaped value in URL"
                )
        if _JWT_RE.search(target):
            high.append("JWT-shaped token reflected in URL")
        if _EMAIL_RE.search(target):
            low.append("email address (PII) present in URL")

    # De-duplicate each list while preserving order.
    def _dedup(items: list[str]) -> list[str]:
        seen: set[str] = set()
        return [r for r in items if not (r in seen or seen.add(r))]

    return _dedup(high), _dedup(low)


def _host_surface(profile) -> str:
    """Derive the managed-host surface from the profile, or 'unknown'.

    Prefers ``profile.stack.hosting``; falls back to an ``api_prefix`` heuristic
    (``/.netlify/functions`` → netlify, ``/api`` is ambiguous). Never assumes
    Netlify when the profile is silent.
    """
    hosting = ((profile.stack and getattr(profile.stack, "hosting", "")) or "").lower()
    if hosting in ("netlify", "vercel", "cloudflare", "cloudflare-pages", "cloudflare_pages"):
        return hosting
    if hosting:
        return hosting  # some other declared host — report it verbatim
    api_prefix = ((profile.target and profile.target.api_prefix) or "").lower()
    if "netlify" in api_prefix:
        return "netlify"
    # ``/api`` is used by Vercel, Cloudflare Pages Functions and many custom
    # stacks — ambiguous, so we do not guess.
    return "unknown"


def _build_probe_targets(profile) -> list[dict]:
    """Authenticated + anonymous endpoints from the profile (deduped by path)."""
    targets: list[dict] = []
    seen_paths: set[str] = set()
    for category in ("authenticated", "anonymous"):
        for ep in endpoints_for_category(profile, category):
            path = ep.get("path")
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            targets.append(ep)
    return targets


# ---------------------------------------------------------------------------
# V14.2.1 / CWE-598 / CWE-200 — token or PII in an app-generated URL / redirect
# ---------------------------------------------------------------------------

@pytest.mark.asvs_extended
@pytest.mark.asvs("14.2.1")
@pytest.mark.cwe("598")
def test_no_secret_or_pii_in_app_generated_urls(profile, evidence):
    """No app-generated URL or redirect Location may carry a token / key / PII.

    For each authenticated + anonymous endpoint declared by the profile we send
    the request WITHOUT following redirects and inspect:
      - the final request URL (in case the client appended sensitive query args),
      - any ``Location`` redirect header the app emits,
      - any ``Refresh`` header redirect.

    A JWT-shaped string, an ``access_token=`` / ``apikey=`` / ``password=`` style
    sensitive parameter, or an email address in any of those URLs is a CWE-598 /
    CWE-200 leak. The probe self-escalates to HIGH via ``pytest.fail("HIGH: ...")``
    so the aggregator's ``_extract_severity_from_message`` upgrades the finding
    above the module's MEDIUM default.

    Endpoints are derived entirely from the profile; skips cleanly when the
    profile declares no authenticated or anonymous endpoints. On the example
    profile the placeholder host short-circuits live requests via the ``profile``
    fixture, so this skips before any traffic is sent.
    """
    targets = _build_probe_targets(profile)
    if not targets:
        pytest.skip(
            "No authenticated or anonymous endpoints in profile — nothing to "
            "scan for secret-in-URL leakage (V14.2.1)."
        )

    high_findings: list[str] = []
    low_findings: list[str] = []

    with httpx.Client(timeout=15.0, follow_redirects=False) as client:
        for ep in targets:
            path = ep["path"]
            method = (ep.get("method") or "POST").upper()
            body = probe_body_for(ep)
            url = netlify_url(profile, path)

            try:
                resp = client.request(method, url, json=body)
            except httpx.HTTPError as exc:
                # Network/DNS errors are not a finding — record and move on.
                evidence.capture(
                    FakeResponse(0, _sanitize_url(url),
                                 f"[body omitted] request error: {type(exc).__name__}",
                                 method),
                    label=f"{path.lstrip('/')}_url_scan_request_error",
                )
                continue

            # URLs that may carry a secret: the request URL itself, the
            # redirect Location, and any Refresh-header redirect.
            candidate_urls = [str(resp.request.url)]
            location = resp.headers.get("location")
            if location:
                candidate_urls.append(location)
            refresh = resp.headers.get("refresh", "")
            if "url=" in refresh.lower():
                candidate_urls.append(refresh.split("=", 1)[1])

            for candidate in candidate_urls:
                high_reasons, low_reasons = _scan_url_for_secrets(candidate)
                if high_reasons:
                    high_findings.append(f"{path}: {', '.join(high_reasons)}")
                if low_reasons:
                    low_findings.append(f"{path}: {', '.join(low_reasons)}")
                if high_reasons or low_reasons:
                    # Capture the SANITIZED url (query stripped) — never persist
                    # the token-bearing URL to evidence.
                    evidence.capture(
                        FakeResponse(
                            resp.status_code, _sanitize_url(candidate),
                            "[body omitted] secret/PII detected in URL — query stripped",
                            method,
                        ),
                        label=f"{path.lstrip('/')}_secret_in_url",
                    )

    if high_findings:
        # Self-escalate to HIGH so the aggregator upgrades from the MEDIUM default.
        pytest.fail(
            "HIGH: token/key/PII exposed in app-generated URL(s) — "
            + "; ".join(high_findings)
            + ". Sensitive values in URLs leak to browser history, access logs, "
            "and the Referer header sent to third parties (ASVS V14.2.1, "
            "CWE-598 / CWE-200). Carry tokens and PII in headers or POST bodies."
        )

    if low_findings:
        # Non-escalating: PII/ambiguous params are MEDIUM (the module default),
        # not a self-escalated HIGH — a benign ``?code=`` OAuth redirect or an
        # email in a URL must not flip run.sh to exit 1.
        pytest.fail(
            "token/PII pattern in app-generated URL(s) — "
            + "; ".join(low_findings)
            + ". Review whether the value is sensitive; PII and full URLs leak via "
            "browser history and the Referer header (ASVS V14.2.1, CWE-598 / "
            "CWE-200)."
        )


# ---------------------------------------------------------------------------
# V14.3.2 / CWE-524 — sensitive/authenticated responses must not be cacheable
# ---------------------------------------------------------------------------

@pytest.mark.asvs("14.3.2")
@pytest.mark.cwe("524")
def test_sensitive_responses_are_not_cacheable(profile, user_a_client, evidence):
    """Authenticated responses must set a restrictive Cache-Control.

    Probes each authenticated endpoint from the profile with the signed-in
    user_a client and asserts the response carries Cache-Control: no-store
    (no-cache / private accepted). A cacheable sensitive response can be read
    back from a shared proxy or the browser disk cache by a later user
    (CWE-524).

    Records the derived host surface (Netlify / Vercel / Cloudflare / unknown)
    in the failure message, since per-host header defaults differ — we do NOT
    assume Netlify. Skips cleanly when the profile declares no authenticated
    endpoint.
    """
    endpoints = endpoints_for_category(profile, "authenticated")
    if not endpoints:
        pytest.skip(
            "No authenticated endpoints in profile — no sensitive response to "
            "check for cache hygiene (V14.3.2)."
        )

    surface = _host_surface(profile)
    failures: list[str] = []

    for ep in endpoints:
        path = ep["path"]
        method = (ep.get("method") or "POST").upper()
        body = probe_body_for(ep)
        url = netlify_url(profile, path)

        try:
            resp = user_a_client.request(method, url, json=body, timeout=15)
        except httpx.HTTPError as exc:
            # Transport/DNS error on this endpoint is not a finding — skip it.
            evidence.capture(
                FakeResponse(
                    0, _sanitize_url(url),
                    f"[body omitted] request error: {type(exc).__name__}",
                    method,
                ),
                label=f"{path.lstrip('/')}_cache_probe_request_error",
            )
            continue
        cache_control = resp.headers.get("cache-control", "")

        if not cache_control_is_safe(cache_control):
            failures.append(f"{path}: Cache-Control: {cache_control or '(absent)'}")
            # Headers only — the body may carry per-user PII we must not persist.
            evidence.capture(
                FakeResponse(
                    resp.status_code, _sanitize_url(url),
                    f"[body omitted] host={surface} "
                    f"Cache-Control: {cache_control or '(absent)'}",
                    method,
                ),
                label=f"{path.lstrip('/')}_cacheable_sensitive_response",
            )

    assert not failures, (
        "Authenticated responses are cacheable (host surface: "
        f"{surface}):\n"
        + "\n".join(f"  - {f}" for f in failures)
        + "\nSensitive per-user responses must set Cache-Control: no-store "
        "(no-cache / private accepted) so they are not written to shared or "
        "browser caches (ASVS V14.3.2, CWE-524). Per-host defaults differ; set "
        "this explicitly in your platform config."
    )


# ---------------------------------------------------------------------------
# V14.3.3 / CWE-200 — Referrer-Policy keeps URLs from leaking to third parties
# ---------------------------------------------------------------------------

@pytest.mark.asvs("14.3.3")
@pytest.mark.cwe("200")
def test_referrer_policy_limits_url_leakage(profile, evidence):
    """The main page must set a Referrer-Policy that does not leak full URLs.

    Without a restrictive Referrer-Policy the browser sends the full URL
    (including any query parameters) in the Referer header to third-party
    origins referenced by the page — a defence-in-depth complement to the
    secret-in-URL probe above (ASVS V14.3.3, CWE-200).

    Acceptable values are those that strip the path/query cross-origin:
    ``no-referrer``, ``same-origin``, ``strict-origin``, and
    ``strict-origin-when-cross-origin``. ``unsafe-url`` and an absent header are
    findings. Host-surface aware: records the derived surface, since some hosts
    inject a default Referrer-Policy and others do not.
    """
    base_url = (profile.target and profile.target.base_url) or ""
    surface = _host_surface(profile)
    page_url = base_url.rstrip("/") + "/"

    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.get(page_url)
    except httpx.HTTPError as exc:
        pytest.skip(f"Main page unreachable ({type(exc).__name__}) — cannot check Referrer-Policy")

    policy = resp.headers.get("referrer-policy", "").strip().lower()
    # ``no-referrer-when-downgrade`` is intentionally EXCLUDED: it still sends the
    # full URL+query in the Referer header to every HTTPS third-party origin, so
    # it does not satisfy V14.3.3's leak-prevention requirement.
    safe_policies = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "origin",
    }
    # A header may list multiple tokens; the browser uses the last it understands.
    tokens = {t.strip() for t in policy.split(",") if t.strip()}
    safe = bool(tokens & safe_policies) and "unsafe-url" not in tokens

    if not safe:
        evidence.capture(
            FakeResponse(
                resp.status_code, _sanitize_url(page_url),
                f"[body omitted] host={surface} "
                f"Referrer-Policy: {policy or '(absent)'}",
                "GET",
            ),
            label="missing_or_weak_referrer_policy",
        )

    assert safe, (
        f"Referrer-Policy is {policy or '(absent)'!r} (host surface: {surface}). "
        "Set Referrer-Policy: strict-origin-when-cross-origin so the browser "
        "does not leak the full URL (including query tokens/PII) to third-party "
        "origins (ASVS V14.3.3, CWE-200). Per-host defaults differ; set it "
        "explicitly rather than relying on the host."
    )
