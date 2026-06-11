"""NextAuth / Auth.js auth adapter for the pentest harness.

Auth flow (cookie-based, NOT JWT)
----------------------------------
1. ``GET <base_url><csrf_path>`` -- fetch CSRF token from JSON; httpx stores
   the ``next-auth.csrf-token`` / ``authjs.csrf-token`` cookie automatically.

1b. ``GET <base_url><signin_path>`` (``Accept: text/html``) -- parse the HTML
   ``<input>`` field names so we know what the credential form expects.  Cached
   per instance.  Falls back to ``email`` / ``password`` if no ``<input>`` found.

2. ``POST <base_url><callback_path>`` -- form-encoded body with
   ``csrfToken``, ``callbackUrl``, discovered field names, and ``json=true``.
   Cookies from step 1 are included via the persistent httpx.Client.

Success detection: response sets one of these session cookies:
  - ``next-auth.session-token``        (v4 HTTP)
  - ``__Secure-next-auth.session-token`` (v4 HTTPS)
  - ``authjs.session-token``           (v5 HTTP)
  - ``__Secure-authjs.session-token``  (v5 HTTPS)

Session verified by ``GET <base_url><session_path>`` -> ``{"user": {...}, ...}``.

All endpoint paths default to the standard Auth.js layout (``/api/auth/*``)
but can be overridden via constructor kwargs for deployments that use a custom
``basePath`` or proxy rewrites.

CAPTCHA detection: 200 + text/html body containing CAPTCHA indicators
(``cf-chl-bypass``, ``h-captcha``, ``g-recaptcha``, ``turnstile``) raises
``CaptchaEnforcedError``.

Cookie-only auth: ``get_token()`` raises ``NotImplementedError`` -- NextAuth
uses opaque session cookies, not JWTs.  Use ``get_headers()`` instead.

Environment variables
---------------------
- ``PENTEST_USER_A_EMAIL``     -- email for user_a
- ``PENTEST_USER_A_PASSWORD``  -- password for user_a
- ``PENTEST_USER_B_EMAIL``     -- email for user_b (optional)
- ``PENTEST_USER_B_PASSWORD``  -- password for user_b (optional)
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from typing import Optional
from urllib.parse import urlparse
from urllib.request import Request as _CookieRequest

import httpx

from .base import AbstractAuthAdapter, AuthConfigError, CaptchaEnforcedError

logger = logging.getLogger(__name__)

# All session cookie names NextAuth / Auth.js may set, ordered by preference
# (v5 preferred over v4 when both present).
_SESSION_COOKIE_NAMES = (
    "__Secure-authjs.session-token",     # v5 HTTPS
    "authjs.session-token",              # v5 HTTP
    "__Secure-next-auth.session-token",  # v4 HTTPS
    "next-auth.session-token",           # v4 HTTP
)

# CAPTCHA indicators in HTML responses — CSS class / attribute patterns to
# reduce false positives from bare substring matching.
_CAPTCHA_INDICATORS = [
    'class="cf-turnstile"',
    "cf-chl-bypass",
    'class="h-captcha"',
    'data-sitekey',  # common to hCaptcha and reCAPTCHA
    'class="g-recaptcha"',
]


# ---------------------------------------------------------------------------
# HTML form field parser — single-pass, scoped to credentials form
# ---------------------------------------------------------------------------

class _CredentialFormParser(HTMLParser):
    """Single-pass parser that collects ``<input>`` name and type attributes.

    Scoped to ``<form>`` elements whose ``action`` contains the configured
    callback path so we only inspect the actual login form.
    """

    def __init__(self, callback_path: str = "/api/auth/callback/credentials") -> None:
        super().__init__()
        self.inputs: list[dict[str, str]] = []
        self._in_credentials_form = False
        # Strip leading slash for substring matching against action attrs
        self._callback_path = callback_path.lstrip("/")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "form":
            action = attr_dict.get("action", "")
            self._in_credentials_form = self._callback_path in action
        elif tag == "input" and self._in_credentials_form:
            name = attr_dict.get("name")
            input_type = attr_dict.get("type", "text")
            if name and input_type not in ("hidden", "submit"):
                self.inputs.append({"name": name, "type": input_type})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._in_credentials_form = False


def _discover_field_names(
    html: str,
    callback_path: str = "/api/auth/callback/credentials",
) -> dict[str, str]:
    """Parse sign-in HTML and return a mapping of role -> field name.

    Returns a dict with ``"email_field"`` and ``"password_field"`` keys.
    Falls back to ``email`` / ``password`` if discovery fails.
    """
    parser = _CredentialFormParser(callback_path)
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        return {"email_field": "email", "password_field": "password"}

    inputs = parser.inputs

    # Heuristic: first text/email-like input is the identifier, first
    # password-type input is the password.  Fall back to positional if types
    # are ambiguous.
    email_field: str | None = None
    password_field: str | None = None

    for inp in inputs:
        if inp["type"] == "password" and password_field is None:
            password_field = inp["name"]
        elif inp["type"] in ("text", "email") and email_field is None:
            email_field = inp["name"]

    # Positional fallback: run when either field is still missing.
    if (not email_field or not password_field) and len(inputs) >= 2:
        for inp in inputs:
            if inp["type"] == "password" and not password_field:
                password_field = inp["name"]
            elif not email_field:
                email_field = inp["name"]

    return {
        "email_field": email_field or "email",
        "password_field": password_field or "password",
    }


# ---------------------------------------------------------------------------
# Session dataclass
# ---------------------------------------------------------------------------

def _make_http_client() -> httpx.Client:
    """Create an httpx.Client with redirect limit."""
    return httpx.Client(timeout=20.0, max_redirects=5)


@dataclass
class _NextAuthSession:
    """Per-account session state maintained by the NextAuth adapter."""

    email: str
    password: str = field(repr=False)
    session_cookie_name: Optional[str] = None
    session_cookie_value: Optional[str] = None
    http_client: httpx.Client = field(default_factory=_make_http_client, repr=False)
    csrf_token: Optional[str] = None
    field_names: dict = field(default_factory=dict)
    last_auth_time: float = 0.0

    def __str__(self) -> str:
        return (
            f"_NextAuthSession(email={self.email!r}, "
            f"password='***', "
            f"session_cookie_name={self.session_cookie_name!r}, "
            f"session_cookie_value={'<set>' if self.session_cookie_value else None})"
        )

    def __repr__(self) -> str:
        return self.__str__()

    def close(self) -> None:
        try:
            self.http_client.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Adapter implementation
# ---------------------------------------------------------------------------

class NextAuthAdapter(AbstractAuthAdapter):
    """NextAuth / Auth.js implementation of :class:`AbstractAuthAdapter`.

    Uses a two-step CSRF + form-encoded credential flow with a persistent
    ``httpx.Client`` per account for cookie-jar continuity.

    Args:
        base_url: Application base URL, e.g. ``https://myapp.example.com``.
            Must include scheme; must NOT have a trailing slash.
        accounts: Mapping of account name to credentials dict, e.g.::

                {
                    "user_a": {"email": "a@example.com", "password": "s3cr3t"},
                }
        csrf_path: Path for the CSRF endpoint.  Defaults to
            ``/api/auth/csrf``.
        signin_path: Path for the sign-in page (HTML form discovery).
            Defaults to ``/api/auth/signin``.
        callback_path: Path for the credential callback POST.  Defaults to
            ``/api/auth/callback/credentials``.
        session_path: Path for the session verification endpoint.  Defaults
            to ``/api/auth/session``.
    """

    # Default Auth.js endpoint paths — overridable via constructor kwargs
    # for deployments that use a custom ``basePath`` or proxy rewrites.
    _DEFAULT_CSRF_PATH = "/api/auth/csrf"
    _DEFAULT_SIGNIN_PATH = "/api/auth/signin"
    _DEFAULT_CALLBACK_PATH = "/api/auth/callback/credentials"
    _DEFAULT_SESSION_PATH = "/api/auth/session"

    def __init__(
        self,
        base_url: str,
        accounts: dict[str, dict],
        *,
        csrf_path: str | None = None,
        signin_path: str | None = None,
        callback_path: str | None = None,
        session_path: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._csrf_path = csrf_path or self._DEFAULT_CSRF_PATH
        self._signin_path = signin_path or self._DEFAULT_SIGNIN_PATH
        self._callback_path = callback_path or self._DEFAULT_CALLBACK_PATH
        self._session_path = session_path or self._DEFAULT_SESSION_PATH

        self._sessions: dict[str, _NextAuthSession] = {
            name: _NextAuthSession(
                email=creds["email"],
                password=creds["password"],
            )
            for name, creds in accounts.items()
        }

        # Cached form field names (shared across accounts -- same app).
        self._field_names_cache: dict | None = None

    # ------------------------------------------------------------------
    # AbstractAuthAdapter implementation
    # ------------------------------------------------------------------

    @property
    def auth_type(self) -> str:
        return "cookie"

    def get_token(self, account_name: str) -> str:
        """NextAuth uses cookie-based auth -- use get_headers() instead.

        Raises:
            NotImplementedError: Always.  NextAuth session cookies are opaque;
                there is no JWT to return.
        """
        raise NotImplementedError(
            "NextAuth uses cookie-based auth -- use get_headers() instead"
        )

    def get_headers(self, account_name: str) -> dict:
        """Return ``{"Cookie": "<name>=<value>; ..."}`` for the named account.

        Signs in on first call; re-authenticates if session is expired.
        Exports all cookies from the session's httpx.Client jar so that
        auxiliary cookies (CSRF, callback tokens) are included.
        """
        self._validate_account(account_name)
        session = self._sessions[account_name]
        if session.session_cookie_value is None or self.is_expired(account_name):
            self._authenticate(account_name)
        # Build Cookie header from cookies scoped to the target URL only.
        # Using CookieJar.cookies_for_request() semantics (domain, path,
        # secure) prevents cross-origin cookie leaks.
        cookies: list[str] = []
        jar: CookieJar = session.http_client.cookies.jar
        # Build a minimal urllib Request so the cookie jar can apply its
        # domain/path/secure policy to filter cookies for base_url.
        cookie_request = _CookieRequest(f"{self._base_url}{self._session_path}")
        jar.add_cookie_header(cookie_request)
        scoped_header = cookie_request.get_header("Cookie") or ""
        if scoped_header:
            cookies = [c.strip() for c in scoped_header.split(";") if c.strip()]
        if session.session_cookie_value:
            # Ensure session cookie is included even if jar was cleared.
            # However, when the session is chunked (name.0, name.1, ...),
            # the jar already carries all chunk keys and never the base key.
            # Appending the reconstructed base cookie alongside the chunks
            # would duplicate the >4KB session value and risk 431 responses.
            chunk_prefix = f"{session.session_cookie_name}."
            has_chunks = any(
                c.split("=", 1)[0].startswith(chunk_prefix)
                and c.split("=", 1)[0][len(chunk_prefix):].isdigit()
                for c in cookies
            )
            if not has_chunks:
                session_cookie = f"{session.session_cookie_name}={session.session_cookie_value}"
                if session_cookie not in cookies:
                    cookies.append(session_cookie)
        # Deduplicate same-name cookie entries.  Many server-side parsers
        # (Express, Next.js) keep the first occurrence of a name, so stale
        # values from earlier in the list would shadow fresh ones.  We keep
        # the *last* occurrence of each name (the most recently appended,
        # which is typically the freshest / most-specific cookie).
        if cookies:
            seen: dict[str, str] = {}
            for entry in cookies:
                cname = entry.split("=", 1)[0]
                seen[cname] = entry  # last wins
            cookies = list(seen.values())
        return {"Cookie": "; ".join(cookies)} if cookies else {}

    def is_expired(self, account_name: str) -> bool:
        """Check the session by hitting the session endpoint.

        Returns ``True`` if the response is empty (``{}`` or no user key),
        meaning the session cookie is expired or invalid.  If the server
        sets a new cookie in the response, the adapter updates its store.

        A 30-second cooldown after successful authentication prevents
        re-auth amplification (multiple callers triggering concurrent
        sign-in flows).
        """
        self._validate_account(account_name)
        session = self._sessions[account_name]
        if session.session_cookie_value is None:
            return True

        # Skip network check if recently authenticated
        if time.time() - session.last_auth_time < 30:
            return False

        try:
            resp = session.http_client.get(
                f"{self._base_url}{self._session_path}",
                timeout=10.0,
            )
        except httpx.HTTPError:
            return True

        # Update cookie if server rolled it.
        self._update_session_cookie_from_response(session, resp)

        if resp.status_code != 200:
            return True

        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            return True

        if not data or "user" not in data:
            return True

        # Session confirmed valid by a real network check: refresh the
        # cooldown anchor so subsequent get_headers() calls within 30s
        # skip the redundant session round-trip.
        session.last_auth_time = time.time()
        return False

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close all per-account httpx clients."""
        for session in self._sessions.values():
            session.close()

    def __enter__(self) -> "NextAuthAdapter":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_account(self, account_name: str) -> None:
        if account_name not in self._sessions:
            raise ValueError(
                f"Unknown account '{account_name}'. "
                f"Valid options: {sorted(self._sessions)}"
            )

    def _authenticate(self, account_name: str) -> None:
        """Full two-step CSRF + credential POST flow."""
        session = self._sessions[account_name]
        client = session.http_client

        # Step 1: Fetch CSRF token.
        csrf_token = self._fetch_csrf(client)
        session.csrf_token = csrf_token

        # Step 1b: Discover form field names (cached). Uses a fresh
        # cookieless client so a stale cookie on the account's persistent
        # client cannot make the server return a session-aware sign-in page.
        field_names = self._get_field_names()
        session.field_names = field_names

        # Step 2: Submit credentials.
        self._submit_credentials(account_name, csrf_token, field_names)

        # Verify session.
        self._verify_session(account_name)

        # Record the success timestamp so is_expired()'s cooldown can
        # short-circuit the session round-trip for the next 30s.
        session.last_auth_time = time.time()

    def _fetch_csrf(self, client: httpx.Client) -> str:
        """GET the CSRF endpoint and return the csrfToken value."""
        url = f"{self._base_url}{self._csrf_path}"
        try:
            resp = client.get(url, timeout=10.0)
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"NextAuth CSRF fetch failed: network error "
                f"({type(exc).__name__})"
            ) from None

        if resp.status_code != 200:
            raise RuntimeError(
                f"NextAuth CSRF fetch failed: HTTP {resp.status_code} -- "
                f"{self._safe_text(resp)[:300]}"
            )

        try:
            data = resp.json()
        except Exception as exc:
            raise RuntimeError(
                f"NextAuth CSRF response is not JSON: {self._safe_text(resp)[:300]}"
            ) from exc

        csrf_token = data.get("csrfToken")
        if not csrf_token:
            raise RuntimeError(
                f"NextAuth CSRF response missing 'csrfToken' key. "
                f"Keys present: {list(data.keys())}"
            )

        return csrf_token

    def _get_field_names(self) -> dict:
        """GET the sign-in page, parse HTML for <input> field names.

        Uses a fresh cookieless httpx.Client so the sign-in page is
        fetched in a clean session state — a stale cookie on an account's
        persistent client could otherwise make the server return an
        "already signed in" page with different (or no) form fields.

        Returns cached result after first successful fetch.
        """
        if self._field_names_cache is not None:
            return self._field_names_cache

        url = f"{self._base_url}{self._signin_path}"
        try:
            with httpx.Client(timeout=10.0, max_redirects=5) as discovery_client:
                resp = discovery_client.get(
                    url,
                    headers={"Accept": "text/html"},
                    follow_redirects=True,
                )
        except httpx.HTTPError:
            logger.warning(
                "NextAuth sign-in page fetch failed; falling back to "
                "default field names (email/password). Not caching — the "
                "next auth attempt will re-attempt discovery."
            )
            # Transient failure: return the fallback WITHOUT caching so a
            # later attempt re-discovers once the sign-in page recovers.
            return {"email_field": "email", "password_field": "password"}

        if resp.status_code != 200:
            logger.warning(
                "NextAuth sign-in page returned HTTP %s; falling back to "
                "default field names (email/password). Not caching — the "
                "next auth attempt will re-attempt discovery.",
                resp.status_code,
            )
            # Transient failure: return the fallback WITHOUT caching.
            return {"email_field": "email", "password_field": "password"}

        html = self._safe_text(resp)
        field_names = _discover_field_names(html, self._callback_path)

        if field_names["email_field"] == "email" and field_names["password_field"] == "password":
            # Check if we actually found inputs or just fell back.
            if "<input" not in html.lower():
                logger.warning(
                    "NextAuth sign-in page has no <input> elements; using "
                    "default field names (email/password). The form may be "
                    "JS-rendered."
                )

        self._field_names_cache = field_names
        return self._field_names_cache

    def _submit_credentials(
        self,
        account_name: str,
        csrf_token: str,
        field_names: dict,
    ) -> None:
        """POST the credential callback endpoint with form-encoded body."""
        session = self._sessions[account_name]
        client = session.http_client
        url = f"{self._base_url}{self._callback_path}"

        form_data = {
            "csrfToken": csrf_token,
            "callbackUrl": self._base_url,
            field_names["email_field"]: session.email,
            field_names["password_field"]: session.password,
            "json": "true",
        }

        try:
            resp = client.post(
                url,
                data=form_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15.0,
                follow_redirects=True,
            )
        except httpx.HTTPError as exc:
            # 'from None' — the httpx exception's request object carries the
            # form body (including the plaintext password); do not chain it.
            raise RuntimeError(
                f"NextAuth credential submit failed for '{account_name}' "
                f"({session.email}): network error ({type(exc).__name__})"
            ) from None

        # CAPTCHA detection. Cloudflare/hCaptcha challenge pages return
        # 403/503; a single class/attribute indicator on those is conclusive.
        # On a 200, require >=2 indicators to avoid false positives from
        # bundled JS that merely references a CAPTCHA library.
        content_type = resp.headers.get("content-type", "")
        if "text/html" in content_type:
            body_lower = self._safe_text(resp).lower()
            is_challenge = resp.status_code in (403, 503)
            matched = [
                ind for ind in _CAPTCHA_INDICATORS if ind.lower() in body_lower
            ]
            if (is_challenge and len(matched) >= 1) or len(matched) >= 2:
                raise CaptchaEnforcedError(
                    f"CAPTCHA enforcement detected for '{account_name}' "
                    f"({session.email}). The target requires CAPTCHA "
                    f"(HTTP {resp.status_code}, indicators: {matched}) which "
                    "headless pentest callers cannot complete."
                )

        # Extract session cookie from the persistent client's cookie jar.
        cookie_name, cookie_value = self._extract_session_cookie(client)
        if not cookie_value:
            raise RuntimeError(
                f"NextAuth credential submit for '{account_name}' did not "
                f"set a session cookie. HTTP {resp.status_code}, "
                f"Content-Type: {content_type}, "
                f"Body: {self._safe_text(resp)[:300]}"
            )

        session.session_cookie_name = cookie_name
        session.session_cookie_value = cookie_value

    def _verify_session(self, account_name: str) -> None:
        """GET the session endpoint to verify the session cookie is valid."""
        session = self._sessions[account_name]
        client = session.http_client

        try:
            resp = client.get(
                f"{self._base_url}{self._session_path}",
                timeout=10.0,
            )
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"NextAuth session verification failed for '{account_name}': "
                f"network error ({type(exc).__name__})"
            ) from None

        if resp.status_code != 200:
            raise RuntimeError(
                f"NextAuth session verification failed for '{account_name}': "
                f"HTTP {resp.status_code}"
            )

        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            raise RuntimeError(
                f"NextAuth session verification for '{account_name}' returned "
                f"non-JSON response: {self._safe_text(resp)[:300]}"
            )

        if not data or "user" not in data:
            raise RuntimeError(
                f"NextAuth session verification for '{account_name}' returned "
                f"empty or userless session: {data}"
            )

        # Update cookie if the server rolled it during verification.
        self._update_session_cookie_from_response(session, resp)

    def _get_cookie_safe(self, client: httpx.Client, name: str) -> str | None:
        """Return the best-match value for ``name`` from the cookie jar.

        ``httpx.Cookies.get()`` raises ``httpx.CookieConflict`` when multiple
        cookies share a name across domains/paths (e.g. a host-only cookie
        plus a parent-domain cookie). That uncaught exception would make auth
        fail. This iterates the raw jar instead and applies a deterministic
        most-specific-wins tie-break:

          1. Only cookies whose domain matches ``self._base_url`` are considered
          2. Only cookies whose path is a prefix of the request URL path
          3. host-only cookies beat domain-scoped cookies
          4. longer path beats shorter path
          5. on a remaining tie, last-set wins (jar iteration order)

        Never raises ``CookieConflict``.
        """
        parsed_url = urlparse(self._base_url)
        target_host = parsed_url.hostname or ""
        # Use the full session endpoint path for cookie path-matching, not
        # just base_url path — session cookies are scoped to the auth path.
        base_path = parsed_url.path or ""
        target_path = f"{base_path}{self._session_path}"
        best: tuple[int, int, int] | None = None
        best_value: str | None = None
        for idx, cookie in enumerate(client.cookies.jar):
            if cookie.name != name:
                continue
            # Filter to cookies that match the target origin's domain.
            cookie_domain = (cookie.domain or "").lstrip(".")
            if not cookie_domain:
                continue
            # host-only: exact match required.
            # domain-scoped: target must equal or be a subdomain of cookie domain.
            is_host_only = not getattr(cookie, "domain_specified", True)
            if is_host_only:
                if cookie_domain.lower() != target_host.lower():
                    continue
            else:
                if (
                    target_host.lower() != cookie_domain.lower()
                    and not target_host.lower().endswith("." + cookie_domain.lower())
                ):
                    continue
            # Filter by path: cookie.path must be a prefix of the request
            # path per RFC 6265 sec 5.1.4 path-match semantics.
            cookie_path = cookie.path or "/"
            if not (
                target_path == cookie_path
                or target_path.startswith(cookie_path.rstrip("/") + "/")
                or cookie_path == "/"
            ):
                continue
            path_len = len(cookie_path)
            # Higher tuple sorts as "more specific"; idx makes last-set win.
            rank = (1 if is_host_only else 0, path_len, idx)
            if best is None or rank > best:
                best = rank
                best_value = cookie.value
        return best_value

    def _extract_session_cookie(
        self, client: httpx.Client
    ) -> tuple[str | None, str | None]:
        """Find the session cookie in the client's cookie jar.

        Prefers v5 cookie names over v4 (tie-breaking for mid-migration
        targets). Uses :meth:`_get_cookie_safe` so duplicate-name cookies
        across domains/paths never raise ``httpx.CookieConflict``.

        Also handles chunked session cookies (e.g.
        ``next-auth.session-token.0``, ``.1``, ...) which NextAuth uses
        when the session JWT exceeds the 4 KB cookie size limit.
        """
        for name in _SESSION_COOKIE_NAMES:
            value = self._get_cookie_safe(client, name)
            if value:
                return name, value

        # Check for chunked cookies: <name>.0, <name>.1, ...
        # Group chunks by (domain, path) scope so we never concatenate
        # fragments from different origins.  Then pick the best-ranked
        # scope (most specific path, then most specific domain) and
        # reassemble only those chunks.
        # Only consider chunks whose domain matches base_url AND whose
        # path is a prefix of the request path (same logic as
        # _get_cookie_safe) to prevent cross-origin chunk leaks.
        parsed_url = urlparse(self._base_url)
        target_host = parsed_url.hostname or ""
        # Use full session endpoint path for path-matching (same as
        # _get_cookie_safe) — not just base_url path.
        base_path = parsed_url.path or ""
        target_path = f"{base_path}{self._session_path}"
        for name in _SESSION_COOKIE_NAMES:
            # scope_key -> list of (chunk_index, value, is_host_only, path_len)
            scoped_chunks: dict[tuple[str, str], list[tuple[int, str]]] = {}
            scope_rank: dict[tuple[str, str], tuple[int, int]] = {}
            for cookie in client.cookies.jar:
                if cookie.name.startswith(f"{name}."):
                    suffix = cookie.name[len(name) + 1:]
                    if suffix.isdigit():
                        domain = cookie.domain or ""
                        path = cookie.path or "/"
                        # Filter by target domain — skip cookies scoped
                        # to unrelated domains.
                        cookie_domain = domain.lstrip(".")
                        if not cookie_domain:
                            continue
                        is_host_only = not getattr(
                            cookie, "domain_specified", True
                        )
                        if is_host_only:
                            if cookie_domain.lower() != target_host.lower():
                                continue
                        else:
                            if (
                                target_host.lower() != cookie_domain.lower()
                                and not target_host.lower().endswith(
                                    "." + cookie_domain.lower()
                                )
                            ):
                                continue
                        # Filter by path: cookie path must be a prefix of
                        # the request path (RFC 6265 sec 5.1.4).
                        if not (
                            target_path == path
                            or target_path.startswith(path.rstrip("/") + "/")
                            or path == "/"
                        ):
                            continue
                        scope_key = (domain, path)
                        scoped_chunks.setdefault(scope_key, []).append(
                            (int(suffix), cookie.value or "")
                        )
                        scope_rank[scope_key] = (
                            1 if is_host_only else 0,
                            len(path),
                        )
            if scoped_chunks:
                # Pick the single best scope: host-only wins, then
                # longest path, then lexicographic domain for stability.
                best_scope = max(
                    scoped_chunks,
                    key=lambda sk: (*scope_rank[sk], sk[0]),
                )
                chunks = scoped_chunks[best_scope]
                chunks.sort(key=lambda c: c[0])
                reassembled = "".join(v for _, v in chunks)
                return name, reassembled

        return None, None

    def _update_session_cookie_from_response(
        self,
        session: _NextAuthSession,
        resp: httpx.Response,
    ) -> None:
        """If the response set a new session cookie, update our stored value."""
        # httpx auto-updates the client cookie jar, so re-extract.
        cookie_name, cookie_value = self._extract_session_cookie(
            session.http_client
        )
        if cookie_value and cookie_value != session.session_cookie_value:
            session.session_cookie_name = cookie_name
            session.session_cookie_value = cookie_value

    @staticmethod
    def _safe_text(resp: httpx.Response) -> str:
        """Extract response text, guarding against encoding issues."""
        try:
            return resp.text
        except Exception:  # noqa: BLE001
            return "<unreadable response body>"
