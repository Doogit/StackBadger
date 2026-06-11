"""Offline contract tests for the consolidated test helpers (U1).

These tests do NOT consume the live ``profile`` fixture — they build a profile
object directly via ``load_profile`` on the committed example YAML.  That keeps
them profile-independent: they run identically and add the same count on every
``--profile``, and they exercise the helper contracts the live example suite
structurally cannot (the example hosts are placeholders, so live probes skip).

Covers:
- ``helpers.supabase_headers`` default output + each keyword variant (D3).
- ``conftest.find_rpc`` happy path on the clerk-supabase profile (D4).
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

import pytest

# ---------------------------------------------------------------------------
# Bootstrap sys.path like the other test modules (package root + tests dir).
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
_TESTS_DIR = _Path(__file__).resolve().parent
for _p in (str(_PKG_ROOT), str(_TESTS_DIR)):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

from profile import load_profile  # noqa: E402
from helpers import supabase_headers  # noqa: E402
from conftest import find_rpc  # noqa: E402

_CLERK_PROFILE = "profiles/clerk-supabase-example.yaml"


def _profile():
    return load_profile(str(_PKG_ROOT / _CLERK_PROFILE))


# ---------------------------------------------------------------------------
# supabase_headers — default output (backward-compat snapshot)
# ---------------------------------------------------------------------------


def test_supabase_headers_default_output():
    """Defaults emit exactly apikey + Authorization + Content-Type + Accept."""
    p = _profile()
    anon_key = (p.supabase and p.supabase.anon_key) or ""
    headers = supabase_headers(p)
    # Assert key *order* (not just set membership): the D3 contract is that the
    # default output stays byte-identical to the pre-split implementation, which
    # inserts apikey → Authorization → Content-Type → Accept in that order.
    assert list(headers) == ["apikey", "Authorization", "Content-Type", "Accept"]
    assert headers["apikey"] == anon_key
    assert headers["Authorization"] == f"Bearer {anon_key}"
    assert headers["Authorization"].startswith("Bearer ")
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"


# ---------------------------------------------------------------------------
# supabase_headers — keyword variants
# ---------------------------------------------------------------------------


def test_supabase_headers_include_auth_false_omits_authorization():
    headers = supabase_headers(_profile(), include_auth=False)
    assert "Authorization" not in headers
    assert "apikey" in headers


def test_supabase_headers_accept_without_content_type():
    headers = supabase_headers(
        _profile(), include_content_type=False, include_accept=True
    )
    assert "Accept" in headers
    assert "Content-Type" not in headers


def test_supabase_headers_prefer_header():
    headers = supabase_headers(_profile(), prefer="return=representation")
    assert headers["Prefer"] == "return=representation"


def test_supabase_headers_extra_header_merges():
    headers = supabase_headers(_profile(), **{"x-anon-session": "abc"})
    assert headers["x-anon-session"] == "abc"


def test_supabase_headers_require_key_skips_when_empty():
    """The example profile's structural anon_key is empty → require_key skips."""
    p = _profile()
    anon_key = (p.supabase and p.supabase.anon_key) or ""
    assert anon_key == ""  # precondition: discovered at runtime, empty in YAML
    with pytest.raises(pytest.skip.Exception):
        supabase_headers(p, require_key=True)


# ---------------------------------------------------------------------------
# find_rpc — happy path
# ---------------------------------------------------------------------------


def test_find_rpc_merge_anon_session():
    rpc = find_rpc(_profile(), "client_callable", name_contains=("merge", "anon"))
    assert rpc["name"] == "merge_anon_session"
