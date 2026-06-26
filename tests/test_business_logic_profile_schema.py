"""Tests for the business_logic profile schema (§P2-G probes).

Covers load_profile shape validation and profile_assembler structural
carry-through. The step-sequence and per-user-quota probes
(tests/test_business_logic.py) read every field through this schema, so a
malformed block must fail loud at load time rather than letting a probe silently
skip and overstate coverage. Mirrors tests/test_oauth_profile_schema.py.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from profile import load_profile
from profile_assembler import assemble_profile

TARGET = "https://stub.invalid"


def _write_profile(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "profile.yaml"
    path.write_text(
        'target:\n  base_url: "https://example.com"\n' + extra,
        encoding="utf-8",
    )
    return path


def _empty_discovery() -> dict:
    return {
        "supabase_url": None,
        "supabase_anon_key": None,
        "clerk_publishable_key": None,
        "clerk_fapi_host": None,
        "api_prefix": None,
        "providers": None,
    }


_FULL_BLOCK = (
    "business_logic:\n"
    "  flows:\n"
    "    - name: checkout\n"
    "      gated_step:\n"
    "        path: /checkout/confirm\n"
    "        method: POST\n"
    "        probe_body:\n"
    "          cart_id: abc\n"
    "      reject_statuses:\n"
    "        - 409\n"
    "        - 422\n"
    "      success_signal: order_id\n"
    "  quota:\n"
    "    endpoint:\n"
    "      path: /api/generate\n"
    "      method: POST\n"
    "    burst: 30\n"
    "    limit_statuses:\n"
    "      - 429\n"
)


# ---------------------------------------------------------------------------
# load_profile validation — accepts valid / absent / partial
# ---------------------------------------------------------------------------

def test_load_profile_accepts_full_business_logic_block(tmp_path):
    profile = load_profile(_write_profile(tmp_path, _FULL_BLOCK))
    bl = profile.business_logic
    flow = bl.flows[0]
    assert flow.name == "checkout"
    assert flow.gated_step.path == "/checkout/confirm"
    assert flow.gated_step.probe_body.cart_id == "abc"
    assert list(flow.reject_statuses) == [409, 422]
    assert flow.success_signal == "order_id"
    assert bl.quota.endpoint.path == "/api/generate"
    assert bl.quota.burst == 30
    assert list(bl.quota.limit_statuses) == [429]


def test_load_profile_accepts_absent_business_logic_block(tmp_path):
    profile = load_profile(_write_profile(tmp_path))
    assert profile.business_logic is None


def test_load_profile_accepts_flows_only(tmp_path):
    profile = load_profile(
        _write_profile(
            tmp_path,
            "business_logic:\n  flows:\n    - gated_step:\n        path: /confirm\n",
        )
    )
    assert profile.business_logic.flows[0].gated_step.path == "/confirm"
    assert profile.business_logic.quota is None


def test_load_profile_accepts_quota_only(tmp_path):
    profile = load_profile(
        _write_profile(
            tmp_path,
            "business_logic:\n  quota:\n    endpoint:\n      path: /gen\n",
        )
    )
    assert profile.business_logic.quota.endpoint.path == "/gen"
    assert profile.business_logic.flows is None


def test_load_profile_accepts_burst_minimum_two(tmp_path):
    profile = load_profile(
        _write_profile(
            tmp_path,
            "business_logic:\n  quota:\n    endpoint:\n      path: /gen\n    burst: 2\n",
        )
    )
    assert profile.business_logic.quota.burst == 2


# ---------------------------------------------------------------------------
# load_profile validation — rejects malformed shapes (fail loud at load)
# ---------------------------------------------------------------------------

def test_rejects_non_mapping_business_logic(tmp_path):
    with pytest.raises(ValueError, match="'business_logic' must be a mapping"):
        load_profile(_write_profile(tmp_path, "business_logic: nope\n"))


def test_rejects_non_list_flows(tmp_path):
    with pytest.raises(ValueError, match="business_logic.flows' must be a list"):
        load_profile(_write_profile(tmp_path, "business_logic:\n  flows: nope\n"))


def test_rejects_non_mapping_flow_entry(tmp_path):
    with pytest.raises(ValueError, match="Each entry in 'business_logic.flows'"):
        load_profile(
            _write_profile(tmp_path, "business_logic:\n  flows:\n    - just-a-string\n")
        )


def test_rejects_flow_without_gated_step_path(tmp_path):
    with pytest.raises(ValueError, match="gated_step' must be a mapping with a string 'path'"):
        load_profile(
            _write_profile(tmp_path, "business_logic:\n  flows:\n    - name: x\n")
        )


def test_rejects_gated_step_non_string_method(tmp_path):
    with pytest.raises(ValueError, match="gated_step.method' must be a string"):
        load_profile(
            _write_profile(
                tmp_path,
                "business_logic:\n  flows:\n    - gated_step:\n"
                "        path: /c\n        method: [POST]\n",
            )
        )


def test_rejects_gated_step_non_mapping_probe_body(tmp_path):
    with pytest.raises(ValueError, match="gated_step.probe_body' must be a mapping"):
        load_profile(
            _write_profile(
                tmp_path,
                "business_logic:\n  flows:\n    - gated_step:\n"
                '        path: /c\n        probe_body: "x"\n',
            )
        )


def test_rejects_non_string_flow_name(tmp_path):
    with pytest.raises(ValueError, match="name' must be a string when present"):
        load_profile(
            _write_profile(
                tmp_path,
                "business_logic:\n  flows:\n    - name: [a]\n"
                "      gated_step:\n        path: /c\n",
            )
        )


def test_rejects_non_string_success_signal(tmp_path):
    with pytest.raises(ValueError, match="success_signal' must be a string"):
        load_profile(
            _write_profile(
                tmp_path,
                "business_logic:\n  flows:\n    - gated_step:\n        path: /c\n"
                "      success_signal: [a]\n",
            )
        )


def test_rejects_reject_statuses_with_bool(tmp_path):
    # YAML `true` parses as a bool; a bool must NOT count as an int status code.
    with pytest.raises(ValueError, match="reject_statuses' must be a list of integer"):
        load_profile(
            _write_profile(
                tmp_path,
                "business_logic:\n  flows:\n    - gated_step:\n        path: /c\n"
                "      reject_statuses:\n        - true\n",
            )
        )


def test_rejects_non_mapping_quota(tmp_path):
    with pytest.raises(ValueError, match="business_logic.quota' must be a mapping"):
        load_profile(_write_profile(tmp_path, "business_logic:\n  quota: nope\n"))


def test_rejects_quota_without_endpoint_path(tmp_path):
    with pytest.raises(ValueError, match="business_logic.quota.endpoint' must be a mapping with a string 'path'"):
        load_profile(
            _write_profile(tmp_path, "business_logic:\n  quota:\n    burst: 5\n")
        )


def test_rejects_burst_below_two(tmp_path):
    # A single request can never observe a per-user limit -> burst must be >= 2.
    with pytest.raises(ValueError, match="burst' must be an integer >= 2"):
        load_profile(
            _write_profile(
                tmp_path,
                "business_logic:\n  quota:\n    endpoint:\n      path: /g\n    burst: 1\n",
            )
        )


def test_rejects_burst_bool(tmp_path):
    # `true` is int-like in Python but must be rejected as a burst count.
    with pytest.raises(ValueError, match="burst' must be an integer"):
        load_profile(
            _write_profile(
                tmp_path,
                "business_logic:\n  quota:\n    endpoint:\n      path: /g\n    burst: true\n",
            )
        )


def test_rejects_limit_statuses_with_bool(tmp_path):
    with pytest.raises(ValueError, match="limit_statuses' must be a list of integer"):
        load_profile(
            _write_profile(
                tmp_path,
                "business_logic:\n  quota:\n    endpoint:\n      path: /g\n"
                "    limit_statuses:\n      - false\n",
            )
        )


# ---------------------------------------------------------------------------
# profile_assembler carry-through (the block must survive assembly + the
# assembler re-validation, mirroring the oauth carry-through test)
# ---------------------------------------------------------------------------

@mock.patch("profile_assembler.discover_live")
def test_assembler_carries_yaml_business_logic_block(mock_discover, tmp_path):
    mock_discover.return_value = _empty_discovery()
    yaml_path = _write_profile(tmp_path, _FULL_BLOCK)
    profile = assemble_profile(TARGET, yaml_path=str(yaml_path))
    bl = profile.business_logic
    assert bl.flows[0].gated_step.path == "/checkout/confirm"
    assert bl.quota.endpoint.path == "/api/generate"


@mock.patch("profile_assembler.discover_live")
def test_assembler_no_business_logic_leaves_block_absent(mock_discover, tmp_path):
    mock_discover.return_value = _empty_discovery()
    profile = assemble_profile(TARGET)
    assert profile.business_logic is None
