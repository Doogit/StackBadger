"""Shared helpers for the pentest test suite.

Exports
-------
- ``netlify_url(profile, path)`` — canonical Netlify Function URL builder.
- ``supabase_headers(profile, *, include_auth=True, include_content_type=True,
  include_accept=True, prefer=None, require_key=False, **extra_headers)`` —
  PostgREST header constructor.
- ``send_request(method, url, *, headers, ...)`` — unified HTTP sender.
- ``is_spa_catchall(response)`` — SPA catch-all (index.html fallback) detector.
- ``USER_A_UPLOAD_ID``, ``USER_B_UPLOAD_ID`` — sentinel UUIDs.
- ``COMMON_SECRETS`` — list of guessable secret values.
- ``FakeResponse`` — minimal duck-type shim for EvidenceCapture.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

# ---------------------------------------------------------------------------
# Sentinel UUIDs
# ---------------------------------------------------------------------------

# Represents an upload owned by User A (never exists in real data).
USER_A_UPLOAD_ID = "00000000-0000-4000-8000-000000000000"

# Represents an upload owned by User B (never exists in real data).
# Also used as the canonical "other user" upload ID in IDOR and RLS tests.
USER_B_UPLOAD_ID = "00000000-0000-4000-8000-000000000001"

# Canonical attacker-controlled cross-site origin used by CORS-reflection and
# CSRF-forgery probes. A reserved placeholder, not an application-specific name.
EVIL_ORIGIN = "https://evil.com"

# ---------------------------------------------------------------------------
# Common secrets
# ---------------------------------------------------------------------------

COMMON_SECRETS: list[str] = [
    "secret",
    "password",
    "internal",
    "test",
    "admin",
    "changeme",
    "12345",
]

# ---------------------------------------------------------------------------
# URL builders
# ---------------------------------------------------------------------------


def netlify_url(profile, path: str) -> str:
    """Build a full Netlify Function URL from *profile* and a string *path*.

    Args:
        profile: Parsed YAML profile object (attribute-access).
        path: Function path, e.g. ``"/list-documents"`` or
              ``"list-documents"``.  Leading slash is optional.

    Returns:
        Absolute URL, e.g.
        ``"https://example.com/.netlify/functions/list-documents"``.
    """
    base = (profile.target and profile.target.base_url) or ""
    prefix = (profile.target and profile.target.api_prefix) or "/.netlify/functions"
    return base.rstrip("/") + prefix.rstrip("/") + "/" + path.lstrip("/")


# ---------------------------------------------------------------------------
# Header constructors
# ---------------------------------------------------------------------------


def supabase_headers(
    profile,
    *,
    include_auth: bool = True,
    include_content_type: bool = True,
    include_accept: bool = True,
    prefer: str | None = None,
    require_key: bool = False,
    **extra_headers: str,
) -> dict[str, str]:
    """Build PostgREST request headers from *profile*.

    This is the canonical superset of every per-module header builder in the
    test suite.  With all keyword arguments left at their defaults the output is
    byte-identical to the original implementation:
    ``{"apikey": <key>, "Authorization": "Bearer <key>",
    "Content-Type": "application/json", "Accept": "application/json"}``.

    Args:
        profile: Parsed YAML profile object.
        include_auth: When ``True`` (default), add
            ``Authorization: Bearer <anon_key>``.
        include_content_type: When ``True`` (default), add
            ``Content-Type: application/json``.
        include_accept: When ``True`` (default), add
            ``Accept: application/json``.  This is split out of the old bundled
            ``include_content_type`` behaviour so callers (e.g. the anon-session
            probes) can emit ``Accept`` without ``Content-Type``.
        prefer: When not ``None``, add ``Prefer: <prefer>`` (e.g.
            ``"return=representation"`` for PostgREST write probes).
        require_key: When ``True`` and the profile declares no anon key, call
            :func:`pytest.skip` (reproduces the skip-on-missing-key behaviour of
            the rls_bypass / anon_session header builders).
        **extra_headers: Any additional headers to merge in **last** (so callers
            can override the defaults), e.g. the already-hyphenated dynamic
            anon-session header: ``**{"x-anon-session": val}``.

    Returns:
        Dict of HTTP headers suitable for httpx.
    """
    anon_key = (profile.supabase and profile.supabase.anon_key) or ""

    if require_key and not anon_key:
        pytest.skip("Profile declares no Supabase anon key")

    headers: dict[str, str] = {"apikey": anon_key}

    if include_auth:
        headers["Authorization"] = f"Bearer {anon_key}"

    if include_content_type:
        headers["Content-Type"] = "application/json"

    if include_accept:
        headers["Accept"] = "application/json"

    if prefer is not None:
        headers["Prefer"] = prefer

    headers.update(extra_headers)
    return headers


# ---------------------------------------------------------------------------
# SPA catch-all detection
# ---------------------------------------------------------------------------


def is_spa_catchall(response: httpx.Response) -> bool:
    """Return True when *response* looks like an SPA fallback, not a real endpoint.

    Many single-page apps return 200 with the root ``index.html`` for any
    path that does not match a static asset or server route.  This helper
    detects that pattern so tests can distinguish a genuine 200 from a
    catch-all HTML shell.

    Heuristic: status 200 + ``text/html`` Content-Type + body starts with
    ``<!DOCTYPE``.
    """
    return (
        response.status_code == 200
        and "text/html" in (response.headers.get("content-type", ""))
        and response.text.lstrip().startswith("<!DOCTYPE")
    )


# ---------------------------------------------------------------------------
# Shared predicates / accessors (single source of truth across probe modules)
# ---------------------------------------------------------------------------


def cache_control_is_safe(cache_control: str | None) -> bool:
    """Return True when a Cache-Control value keeps a sensitive response out of caches.

    Any of ``no-store`` / ``no-cache`` / ``private`` is accepted (ASVS V14.3.2,
    CWE-524). Centralised here so every data-protection probe enforces identical
    semantics rather than re-deriving the predicate per module.
    """
    cc = (cache_control or "").lower()
    return "no-store" in cc or "no-cache" in cc or "private" in cc


def auth_provider(profile) -> str:
    """Return the active auth provider id (``profile.stack.auth``), lowercased."""
    return ((profile.stack and profile.stack.auth) or "").lower()


def safe_text(resp) -> str:
    """Return ``resp.text``, swallowing decode/encoding errors as ``''``."""
    try:
        return resp.text
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# Unified HTTP sender
# ---------------------------------------------------------------------------


def send_request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    json_body: Any = None,
    content: bytes | None = None,
    body: bytes | None = None,
    files: dict | None = None,
    timeout: float = 15.0,
    follow_redirects: bool = False,
) -> httpx.Response:
    """Send a single HTTP request and return the response.

    This is the canonical superset of all per-module ``_send`` variants in the
    test suite.  It does NOT follow redirects by default.

    Args:
        method: HTTP verb, e.g. ``"POST"``, ``"GET"`` (case-insensitive).
        url: Absolute URL.
        headers: Optional dict of request headers.
        params: Optional query-string parameters.
        json_body: Request body serialised as JSON (sets Content-Type
            automatically via httpx).
        content: Raw bytes body (mutually exclusive with *json_body* and
            *body*).
        body: Alias for *content* — accepted for backwards compatibility with
            callers that used ``body=`` in their local ``_send`` helper.
        files: Multipart file upload dict (httpx ``files=`` format).
        timeout: Request timeout in seconds (default 15.0).  Callers that need
            a longer timeout (e.g. oversized-upload tests at 30 s) pass
            explicitly.
        follow_redirects: Whether to follow HTTP redirects (default False).

    Returns:
        :class:`httpx.Response`.
    """
    with httpx.Client(timeout=timeout, follow_redirects=follow_redirects) as client:
        kwargs: dict = {"headers": headers or {}}
        if params:
            kwargs["params"] = params
        if json_body is not None:
            kwargs["json"] = json_body
        # ``body`` is an alias for ``content``; content takes precedence.
        raw = content if content is not None else body
        if raw is not None:
            kwargs["content"] = raw
        if files is not None:
            kwargs["files"] = files
        # Dispatch via client.request() rather than getattr(client, method.lower()):
        # httpx.Client exposes only the standard verbs as methods, so a
        # non-standard verb such as TRACE has no attribute and getattr would raise
        # AttributeError before any request is built. request() accepts an
        # arbitrary method string.
        return client.request(method.upper(), url, **kwargs)


# ---------------------------------------------------------------------------
# FakeResponse — duck-type shim for EvidenceCapture
# ---------------------------------------------------------------------------


class FakeResponse:
    """Minimal duck-type of :class:`httpx.Response` for EvidenceCapture.

    Use when you need to pass a synthetic response to ``evidence.capture()``
    but do not have a real HTTP response object, e.g. for rate-limit summaries
    or test-constructed payloads.

    Args:
        status_code: Synthetic HTTP status (use 0 for non-HTTP synthetic events).
        url: URL string for the synthetic request.
        body: Plain-text body content.
        method: HTTP method string (default ``"GET"``).
    """

    def __init__(
        self,
        status_code: int,
        url: str,
        body: str,
        method: str = "GET",
    ) -> None:
        self.status_code = status_code
        self.text = body
        self.content = body.encode()
        self.headers: dict = {}
        self.request = httpx.Request(method, url)
