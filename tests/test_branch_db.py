"""Unit tests for branch_db.delete_branch error semantics.

The run.sh cleanup trap relies on delete_branch raising on an unexpected HTTP
status so its ``|| warn`` fallback fires (emitting a "manually delete branch"
instruction) rather than silently orphaning a disposable Supabase branch DB.
These tests pin that contract. httpx is stubbed — no network is touched.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parent.parent  # StackBadger/
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

import branch_db  # noqa: E402


class _FakeResp:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


@pytest.fixture
def stub_delete(monkeypatch):
    """Replace httpx.delete with a stub returning a chosen status code."""

    def _install(status_code: int, text: str = ""):
        monkeypatch.setattr(
            branch_db.httpx,
            "delete",
            lambda *a, **k: _FakeResp(status_code, text),
        )

    return _install


@pytest.mark.parametrize("status", [200, 204, 404])
def test_delete_branch_success_statuses_do_not_raise(stub_delete, status):
    """200/204 (deleted) and 404 (already gone) are all treated as success."""
    stub_delete(status)
    # Must not raise.
    assert branch_db.delete_branch("br-1", "proj-ref", "token") is None


@pytest.mark.parametrize("status", [400, 401, 403, 429, 500, 503])
def test_delete_branch_error_statuses_raise(stub_delete, status):
    """Any non-2xx/404 response raises so run.sh's `|| warn` fallback fires
    instead of silently orphaning the branch DB."""
    stub_delete(status, text="error body")
    with pytest.raises(RuntimeError, match=f"HTTP {status}"):
        branch_db.delete_branch("br-1", "proj-ref", "token")
