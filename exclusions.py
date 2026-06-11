"""Shared probe-exclusion filter for the pentest harness.

Single source of truth for the default-on ``exclude_paths`` / ``exclude_tables``
lists and the matching rules every enumeration seam applies:

  - ``tests/conftest.py``  — pytest endpoint/table enumeration helpers
  - ``discover.py``        — source-scan endpoint discovery
  - ``zap/build_runtime_plan.py`` — ZAP requestor injection

``exclude_paths`` covers application-layer endpoint paths ONLY. It does NOT
cover PostgREST table probes (``/rest/v1/<table>?id=eq.<uuid>``) — those are
driven by ``profile.supabase.tables`` and gated by ``exclude_tables``.

The effective list is always ``union(user-supplied, DEFAULT)``: user values
extend the defaults, an empty user list still leaves the defaults enforced,
and there is no way to opt out of a default via the profile.

This module imports nothing from the rest of the harness so any seam
(root modules, ``zap/`` subpackage, ``tests/``) can import it without cycles.
"""

from __future__ import annotations

from typing import Iterable

# Paths that destroy the probing session or test state when hit:
# sign-out endpoints (session invalidation), account deletion, password
# reset, and token-rotation endpoints (refresh-token rotation invalidates
# the session the suite is authenticated with). Path-prefix,
# case-insensitive, segment-boundary matched (see is_excluded_path).
DEFAULT_EXCLUDE_PATHS: tuple[str, ...] = (
    "/logout",
    "/signout",
    "/auth/signout",
    "/api/auth/logout",
    "/api/auth/signout",
    "/auth/v1/logout",
    "/delete-account",
    "/api/user/delete",
    "/reset-password",
    # Token-rotation paths: a refresh-grant probe rotates the refresh token
    # and invalidates the session the adapters signed in with.
    "/auth/v1/token",
    "/oauth/token",
)

# Tables excluded from PostgREST/IDOR table enumeration. Exact-name,
# case-insensitive match against the names listed in profile.supabase.tables.
DEFAULT_EXCLUDE_TABLES: tuple[str, ...] = (
    "auth.users",
)


def _normalize_path(path: str) -> str:
    """Lowercase, ensure a single leading slash, strip trailing slashes."""
    p = str(path).strip().lower()
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") or "/"


def effective_exclude_paths(user_paths: Iterable[str] | None = None) -> list[str]:
    """Return ``union(user_paths, DEFAULT_EXCLUDE_PATHS)``, normalized and sorted."""
    merged = {_normalize_path(p) for p in DEFAULT_EXCLUDE_PATHS}
    for p in user_paths or ():
        if isinstance(p, str) and p.strip():
            merged.add(_normalize_path(p))
    return sorted(merged)


def effective_exclude_tables(user_tables: Iterable[str] | None = None) -> list[str]:
    """Return ``union(user_tables, DEFAULT_EXCLUDE_TABLES)``, lowercased and sorted."""
    merged = {t.lower() for t in DEFAULT_EXCLUDE_TABLES}
    for t in user_tables or ():
        if isinstance(t, str) and t.strip():
            merged.add(t.strip().lower())
    return sorted(merged)


def is_excluded_path(path: str, exclude_paths: Iterable[str] | None = None) -> bool:
    """Return True when *path* matches an exclusion rule.

    A rule matches the path itself or any sub-path below it
    (``/logout`` matches ``/logout`` and ``/logout/all`` but NOT
    ``/logout-stats`` — segment-boundary, not raw string prefix).
    ``exclude_paths`` should be the effective list; ``None`` means
    defaults only.
    """
    if exclude_paths is None:
        exclude_paths = effective_exclude_paths()
    p = _normalize_path(path)
    for rule in exclude_paths:
        r = _normalize_path(rule)
        if p == r or p.startswith(r + "/"):
            return True
    return False


def is_excluded_table(table: str, exclude_tables: Iterable[str] | None = None) -> bool:
    """Return True when *table* (exact name, case-insensitive) is excluded."""
    if exclude_tables is None:
        exclude_tables = effective_exclude_tables()
    t = str(table).strip().lower()
    return any(t == str(rule).strip().lower() for rule in exclude_tables)


def filter_endpoints(
    endpoints: list[dict], exclude_paths: Iterable[str] | None = None
) -> list[dict]:
    """Return *endpoints* minus entries whose ``path`` is excluded.

    Entries without a ``path`` key pass through unchanged — presence
    validation belongs to the caller, not the exclusion filter.
    """
    effective = (
        effective_exclude_paths(None)
        if exclude_paths is None
        else list(exclude_paths)
    )
    result = []
    for ep in endpoints:
        path = ep.get("path") if hasattr(ep, "get") else None
        if path and is_excluded_path(path, effective):
            continue
        result.append(ep)
    return result
