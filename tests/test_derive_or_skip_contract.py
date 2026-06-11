"""Offline derive-or-skip contract tests (U8).

Pins the contracts the live example-profile suite structurally cannot exercise
(R5, R8): the consolidated helpers and the Item-2 RPC/endpoint derivation must
DERIVE their target from the active profile or SKIP — never silently no-op.

These tests build in-memory profile stubs via ``load_profile`` on a tiny tmp
YAML so they get the real ``_AttrDict`` None-on-missing semantics (a hand-built
object that raised ``AttributeError`` on a missing section would mis-pin the
contract). They do NOT consume the live ``profile`` fixture, so they run
identically and add the same count on every ``--profile``.

Covers:
- R8: ``helpers.netlify_url`` join-equivalence (``"/x"`` == ``"x"``).
- R8: ``first_endpoint`` / ``conftest.upload_path`` / ``find_rpc`` /
  ``supabase_headers(require_key=True)`` each raise ``Skipped`` when their field
  is absent.
- R5 (load-bearing): a profile that declares *differently-named* RPCs / no
  payment endpoint makes every U5-derived selection — and the real U5 test
  bodies — raise ``Skipped`` instead of a false-green no-op.
- The U5 payload-synthesis guards (``_param_names`` / ``_rpc_cross_user_body`` /
  ``_rpc_sqli_body``) that prevent a wrong-shape-422 / no-injection false green.
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
from helpers import netlify_url, supabase_headers  # noqa: E402
from conftest import find_rpc, first_endpoint, upload_path  # noqa: E402
import test_rls_bypass as rls  # noqa: E402
import test_payment_gate as pay  # noqa: E402

# Note on imports: this module imports conftest helpers as ``conftest`` while
# test_rls_bypass imports them as ``tests.conftest`` (two module objects). That
# is intentional and safe here: ``pytest.skip.Exception`` (Skipped) is a single
# class owned by pytest regardless of the import path, so ``pytest.raises(Skipped)``
# catches the skip raised by either copy, and the method-level R5 tests exercise
# the ``tests.conftest`` copy that the real U5 bodies actually call.

# ``pytest.skip(...)`` raises this (i.e. ``_pytest.outcomes.Skipped``).
Skipped = pytest.skip.Exception


# ---------------------------------------------------------------------------
# Stub builders — load_profile on a tiny tmp YAML (real _AttrDict semantics)
# ---------------------------------------------------------------------------

_MINIMAL_YAML = """\
target:
  base_url: "https://real-target.test"
  api_prefix: "/.netlify/functions"
"""

# A profile that DOES declare RPCs and an endpoint, but with names/categories
# matching NONE of U5's derived selectors — the load-bearing R5 case. It carries
# a NON-EMPTY anon_key on purpose: the only skip path through the U5 RPC bodies
# must be `find_rpc` (a name-mismatch), not the require_key guard — otherwise the
# R5 negative control (re-hardcoding a name) could be masked by a require_key
# skip and fail to falsify the test.
_MISMATCH_YAML = """\
target:
  base_url: "https://real-target.test"
  api_prefix: "/api"
supabase:
  anon_key: "eyJhbGciOiJIUzI1NiJ9.FAKE-OFFLINE-STUB.sig"
supabase_rpcs:
  client_callable:
    - name: do_widget_thing
      params: [widget_id]
  server_only:
    - name: rotate_internal_token
      params: [token]
endpoints:
  authenticated:
    - path: /whoami
      method: POST
"""

# Supabase block present but anon_key empty — isolates the require_key skip.
_EMPTY_KEY_YAML = """\
target:
  base_url: "https://real-target.test"
  api_prefix: "/.netlify/functions"
supabase:
  anon_key: ""
"""


def _stub(tmp_path, text, name="stub.yaml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return load_profile(str(path))


@pytest.fixture
def minimal(tmp_path):
    """Profile with only ``target.*`` — every optional section absent (None)."""
    return _stub(tmp_path, _MINIMAL_YAML)


@pytest.fixture
def mismatch(tmp_path):
    """Profile that declares RPCs/endpoints whose names match no U5 selector."""
    return _stub(tmp_path, _MISMATCH_YAML)


@pytest.fixture
def empty_key(tmp_path):
    """Profile with a supabase block but an empty anon_key."""
    return _stub(tmp_path, _EMPTY_KEY_YAML, name="empty_key.yaml")


# ---------------------------------------------------------------------------
# R8 — netlify_url join-equivalence (guards against a Group-A regression)
# ---------------------------------------------------------------------------

def test_netlify_url_join_equivalence(minimal):
    """Slash-prefixed and bare paths must join identically (D1 / R8)."""
    assert netlify_url(minimal, "/list-x") == netlify_url(minimal, "list-x")
    # And the canonical join is actually applied (single separator, no // join).
    assert (
        netlify_url(minimal, "list-x")
        == "https://real-target.test/.netlify/functions/list-x"
    )


# ---------------------------------------------------------------------------
# R8 — first_endpoint / upload_path / supabase_headers(require_key) / find_rpc
#      skip when their profile field is absent
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("category", ["authenticated", "payment", "anonymous"])
def test_first_endpoint_skips_when_category_absent(minimal, category):
    with pytest.raises(Skipped):
        first_endpoint(minimal, category)


def test_upload_path_skips_when_uploads_absent(minimal):
    # Imported from conftest (post-U4 move), not from test_file_upload.
    with pytest.raises(Skipped):
        upload_path(minimal)


def test_supabase_headers_require_key_skips_when_key_empty(empty_key):
    # supabase block present but anon_key empty → require_key must skip.
    with pytest.raises(Skipped):
        supabase_headers(empty_key, require_key=True)


def test_find_rpc_skips_when_no_rpc_section(minimal):
    with pytest.raises(Skipped):
        find_rpc(minimal, "client_callable", name_contains=("merge", "anon"))


# ---------------------------------------------------------------------------
# R5 (load-bearing) — derive-or-skip on a NAME-MISMATCHED profile
# ---------------------------------------------------------------------------

# Mirror of U5's per-site (tier, name_contains) selectors in test_rls_bypass.py.
# The method-level R5 tests below exercise the real U5 code paths (drift-proof);
# this table additionally asserts find_rpc skips for every selector at once.
_U5_RPC_SELECTORS = [
    ("client_callable", ("merge", "anon")),
    ("client_callable", ("update", "record")),
    ("client_callable", ("clear", "record")),
    ("server_only", ("replace", "record")),
    ("server_only", ("chat", "feedback")),
    ("server_only", ("increment", "rate")),
    ("server_only", ("match", "knowledge")),
    ("server_only", ("delete", "upload")),
]


@pytest.mark.parametrize("tier,name_contains", _U5_RPC_SELECTORS)
def test_r5_find_rpc_skips_on_name_mismatch(mismatch, tier, name_contains):
    """Every U5 RPC selector SKIPS when the profile declares only
    differently-named RPCs — proving the false-green no-op is gone."""
    with pytest.raises(Skipped):
        find_rpc(mismatch, tier, name_contains=name_contains)


# (id, invoke) pairs that call the REAL U5-derived test body with the mismatch
# profile and None clients/evidence. Each body's first statement is a profile
# derivation (find_rpc / first_endpoint) that raises Skipped BEFORE any client is
# touched, so None args are safe. This binds EVERY derive-or-skip body to the R5
# contract (not just the find_rpc helper exercised by the table above), closing
# the regression-coverage gap: re-hardcoding a target in any of these bodies
# makes its case here FAIL (the body reaches `None.post(...)` → AttributeError)
# instead of skipping. The live example-profile suite cannot catch that (it skips
# at the placeholder-host guard), so this offline binding is the only guard.
_CC = rls.TestClientCallableRPCAccessControl
_SO = rls.TestServerOnlyRPCInputValidation
_RO = rls.TestReadOnlyRLSProbes
_SQLI = "' OR 1=1 --"

_U5_DERIVE_BODIES = [
    ("cc_merge_anon_call", lambda p: _CC().test_merge_anon_rpc_anon_call_blocked(p, None, None)),
    ("cc_merge_cross_user", lambda p: _CC().test_merge_anon_rpc_cross_user_anon_id(p, None, None)),
    ("cc_update_cross_user", lambda p: _CC().test_client_update_rpc_cross_user(p, None, None)),
    ("cc_clear_cross_user", lambda p: _CC().test_client_clear_rpc_cross_user(p, None, None)),
    ("so_replace_anon", lambda p: _SO().test_server_replace_rpc_anon_blocked(p, None, None)),
    ("so_replace_pk_injection", lambda p: _SO().test_server_replace_rpc_pk_injection(p, None, None)),
    ("so_replace_cross_user", lambda p: _SO().test_server_replace_rpc_cross_user(p, None, None)),
    ("so_feedback_anon", lambda p: _SO().test_server_feedback_rpc_anon_blocked(p, None, None)),
    ("so_feedback_forged", lambda p: _SO().test_server_feedback_rpc_forged_id(p, None, None)),
    ("so_ratelimit_anon", lambda p: _SO().test_server_ratelimit_rpc_anon_blocked(p, None, None)),
    ("so_ratelimit_sqli", lambda p: _SO().test_server_ratelimit_rpc_sqli(_SQLI, p, None, None)),
    ("so_match_anon", lambda p: _SO().test_server_match_rpc_anon_call_ok_or_denied(p, None, None)),
    ("so_match_sqli", lambda p: _SO().test_server_match_rpc_sqli_in_query(_SQLI, p, None, None)),
    ("so_delete_anon", lambda p: _SO().test_server_delete_rpc_anon_blocked(p, None, None)),
    ("so_delete_authed", lambda p: _SO().test_server_delete_rpc_authenticated_blocked(p, None, None)),
    ("so_delete_cross_user", lambda p: _SO().test_server_delete_rpc_cross_user(p, None, None)),
    ("ro_rpc_read_cross_user", lambda p: _RO().test_cross_user_rpc_read_blocked(p, None, None)),
    ("payment_checkout_tamper", lambda p: pay.test_checkout_session_metadata_tampering(
        "tampered_user_id", {"user_id": "x", "upload_id": "y"}, "R5 control", p, None, None)),
]


@pytest.mark.parametrize(
    "invoke", [b[1] for b in _U5_DERIVE_BODIES], ids=[b[0] for b in _U5_DERIVE_BODIES]
)
def test_r5_real_method_body_skips_on_mismatch(mismatch, invoke):
    """Every REAL U5-derived test body SKIPS (not no-ops) on a name-mismatched /
    payment-less profile.

    The ``mismatch`` stub carries a NON-EMPTY anon_key on purpose, so the only
    skip path through each body is the derivation (find_rpc / first_endpoint) —
    not the require_key guard. That is what makes the R5 negative control valid:
    re-hardcoding a target name in any body bypasses the derivation skip and the
    body reaches a ``None`` client (AttributeError), failing this case rather
    than skipping. (Demonstrated during U8 verification on ``cc_merge_anon_call``.)
    """
    with pytest.raises(Skipped):
        invoke(mismatch)


# ---------------------------------------------------------------------------
# U5 payload-synthesis guards (anti-false-green) — unit contracts
# ---------------------------------------------------------------------------

def test_param_names_handles_string_and_mapping_params():
    assert rls._param_names({"params": ["anon_id", "p_x"]}) == ["anon_id", "p_x"]
    assert rls._param_names({"params": [{"name": "p_a"}, {"name": "p_b"}]}) == ["p_a", "p_b"]
    assert rls._param_names({"params": []}) == []
    assert rls._param_names({}) == []


def test_rpc_cross_user_body_none_when_no_params():
    """No declared params → None so the caller SKIPS instead of guessing a
    payload that a real RPC would 422 (a false green)."""
    assert rls._rpc_cross_user_body({"name": "x"}) is None
    assert rls._rpc_cross_user_body({"name": "x", "params": []}) is None


def test_rpc_cross_user_body_synthesizes_from_param_names():
    body = rls._rpc_cross_user_body(
        {"name": "x", "params": ["anon_id", "p_upload_id", "p_action", "p_attestation", "p_message_id"]}
    )
    assert body == {
        "anon_id": rls.UNMERGED_ANON_ID,
        "p_upload_id": rls.USER_B_UPLOAD_ID,
        "p_action": "include",
        "p_attestation": None,
        "p_message_id": rls.USER_B_MESSAGE_ID,
    }


def test_rpc_cross_user_body_branch_precedence():
    """A param name containing two branch substrings resolves to the EARLIER
    branch — pins the elif precedence directly (anon_id before message_id)."""
    body = rls._rpc_cross_user_body({"name": "x", "params": ["anon_id_and_message_id"]})
    assert body["anon_id_and_message_id"] == rls.UNMERGED_ANON_ID


def test_rpc_sqli_body_none_when_no_params():
    assert rls._rpc_sqli_body({"name": "x"}, "' OR 1=1 --") is None


def test_rpc_sqli_body_none_when_no_string_param():
    """All params map to non-string sentinels (attestation→None) → no injection
    target → None, so the SQLi test SKIPS instead of a no-injection false green."""
    assert rls._rpc_sqli_body({"name": "x", "params": ["p_attestation"]}, "' OR 1=1 --") is None


def test_rpc_sqli_body_injects_into_string_params():
    payload = "' OR 1=1 --"
    body = rls._rpc_sqli_body(
        {"name": "x", "params": ["p_identifier", "p_attestation"]}, payload
    )
    assert body["p_identifier"] == payload   # string param received the injection
    assert body["p_attestation"] is None     # non-string param preserved
