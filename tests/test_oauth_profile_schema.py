"""Tests for the oauth/delegated_send profile schema (Phase-0 prerequisite).

Covers load_profile shape validation, profile_assembler structural carry-through,
and the OAUTH_AUTHORIZE_URL / OAUTH_TOKEN_ENDPOINT env overrides (staging support
per plan §6). The §P1-B/§P1-D OAuth probes read every field through this schema.
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
    "oauth:\n"
    "  delegated_send:\n"
    "    provider: google\n"
    "    authorize_url: /api/oauth/google/authorize\n"
    "    redirect_uris:\n"
    '      - "https://example.com/api/oauth/google/callback"\n'
    "    token_endpoint: /api/oauth/google/token\n"
    "    required_scopes:\n"
    '      - "https://www.googleapis.com/auth/gmail.send"\n'
    "    send_endpoints:\n"
    "      - path: /api/email/send\n"
    "        method: POST\n"
    "    status_endpoints:\n"
    "      - path: /api/oauth/google/status\n"
    "        method: GET\n"
)


# ---------------------------------------------------------------------------
# load_profile validation — accepts valid / absent
# ---------------------------------------------------------------------------

def test_load_profile_accepts_full_oauth_block(tmp_path):
    profile = load_profile(_write_profile(tmp_path, _FULL_BLOCK))
    ds = profile.oauth.delegated_send
    assert ds.provider == "google"
    assert ds.authorize_url == "/api/oauth/google/authorize"
    assert ds.token_endpoint == "/api/oauth/google/token"
    assert list(ds.redirect_uris) == ["https://example.com/api/oauth/google/callback"]
    assert list(ds.required_scopes) == ["https://www.googleapis.com/auth/gmail.send"]
    assert ds.send_endpoints[0].path == "/api/email/send"
    assert ds.status_endpoints[0].method == "GET"


def test_load_profile_accepts_absent_oauth_block(tmp_path):
    profile = load_profile(_write_profile(tmp_path))
    assert profile.oauth is None


def test_load_profile_accepts_empty_delegated_send(tmp_path):
    # oauth present but delegated_send absent — still valid (probes skip).
    profile = load_profile(_write_profile(tmp_path, "oauth:\n  delegated_send:\n"))
    assert profile.oauth is not None
    assert profile.oauth.delegated_send is None


def test_load_profile_accepts_partial_block(tmp_path):
    # Only authorize_url present — the scope/token probes skip, the state/PKCE
    # probe still runs. A partial block must load.
    profile = load_profile(
        _write_profile(
            tmp_path,
            "oauth:\n  delegated_send:\n    authorize_url: /api/oauth/start\n",
        )
    )
    assert profile.oauth.delegated_send.authorize_url == "/api/oauth/start"
    assert profile.oauth.delegated_send.required_scopes is None


# ---------------------------------------------------------------------------
# load_profile validation — rejects malformed shapes
# ---------------------------------------------------------------------------

def test_load_profile_rejects_non_mapping_oauth(tmp_path):
    with pytest.raises(ValueError, match="'oauth' must be a mapping"):
        load_profile(_write_profile(tmp_path, "oauth: nope\n"))


def test_load_profile_rejects_non_mapping_delegated_send(tmp_path):
    with pytest.raises(ValueError, match="'oauth.delegated_send' must be a mapping"):
        load_profile(_write_profile(tmp_path, "oauth:\n  delegated_send: nope\n"))


def test_load_profile_rejects_non_string_authorize_url(tmp_path):
    with pytest.raises(ValueError, match="authorize_url' must be a string"):
        load_profile(
            _write_profile(
                tmp_path, "oauth:\n  delegated_send:\n    authorize_url: [a, b]\n"
            )
        )


def test_load_profile_rejects_non_list_required_scopes(tmp_path):
    with pytest.raises(ValueError, match="required_scopes' must be a list of strings"):
        load_profile(
            _write_profile(
                tmp_path, "oauth:\n  delegated_send:\n    required_scopes: gmail.send\n"
            )
        )


def test_load_profile_rejects_non_string_scope_item(tmp_path):
    with pytest.raises(ValueError, match="required_scopes' must be a list of strings"):
        load_profile(
            _write_profile(
                tmp_path,
                "oauth:\n  delegated_send:\n    required_scopes:\n      - 123\n",
            )
        )


def test_load_profile_rejects_send_endpoint_without_path(tmp_path):
    with pytest.raises(ValueError, match="send_endpoints'"):
        load_profile(
            _write_profile(
                tmp_path,
                "oauth:\n  delegated_send:\n    send_endpoints:\n      - method: POST\n",
            )
        )


def test_load_profile_rejects_non_list_status_endpoints(tmp_path):
    with pytest.raises(ValueError, match="status_endpoints' must be a list"):
        load_profile(
            _write_profile(
                tmp_path,
                "oauth:\n  delegated_send:\n    status_endpoints: /api/status\n",
            )
        )


def test_load_profile_rejects_non_list_send_endpoints(tmp_path):
    with pytest.raises(ValueError, match="send_endpoints' must be a list"):
        load_profile(
            _write_profile(
                tmp_path,
                "oauth:\n  delegated_send:\n    send_endpoints: /api/send\n",
            )
        )


def test_load_profile_rejects_non_string_method(tmp_path):
    with pytest.raises(ValueError, match="method in 'oauth.delegated_send.send_endpoints'"):
        load_profile(
            _write_profile(
                tmp_path,
                "oauth:\n  delegated_send:\n    send_endpoints:\n"
                "      - path: /api/send\n        method: [POST]\n",
            )
        )


def test_load_profile_accepts_send_endpoint_probe_body(tmp_path):
    # probe_body is an operator-supplied mapping the §P1-D write-probe sends; it
    # must load without error.
    profile = load_profile(
        _write_profile(
            tmp_path,
            "oauth:\n  delegated_send:\n    send_endpoints:\n"
            "      - path: /api/send\n        method: POST\n"
            "        probe_body:\n          to: sink@example.com\n",
        )
    )
    ep = profile.oauth.delegated_send.send_endpoints[0]
    assert ep.path == "/api/send"
    assert ep.probe_body.to == "sink@example.com"


def test_load_profile_rejects_non_mapping_probe_body(tmp_path):
    # A bare-string probe_body would be silently coerced to {} downstream and
    # skip the only live delegated-send leak check — reject it at load time.
    with pytest.raises(ValueError, match="probe_body in 'oauth.delegated_send.send_endpoints'"):
        load_profile(
            _write_profile(
                tmp_path,
                "oauth:\n  delegated_send:\n    send_endpoints:\n"
                '      - path: /api/send\n        probe_body: "sink@example.com"\n',
            )
        )


# ---------------------------------------------------------------------------
# profile_assembler carry-through + env overrides
# ---------------------------------------------------------------------------

_OAUTH_ENV = ("OAUTH_AUTHORIZE_URL", "OAUTH_TOKEN_ENDPOINT")
_DISCOVERY_ENV = (
    "TARGET_BASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_PROJECT_URL", "CLERK_FAPI_HOST",
)


def _clear_env(monkeypatch):
    for var in _DISCOVERY_ENV + _OAUTH_ENV:
        monkeypatch.delenv(var, raising=False)


@mock.patch("profile_assembler.discover_live")
def test_assembler_carries_yaml_oauth_block(mock_discover, monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    mock_discover.return_value = _empty_discovery()
    yaml_path = _write_profile(tmp_path, _FULL_BLOCK)
    profile = assemble_profile(TARGET, yaml_path=str(yaml_path))
    assert profile.oauth.delegated_send.authorize_url == "/api/oauth/google/authorize"


@mock.patch("profile_assembler.discover_live")
def test_assembler_oauth_env_overrides_yaml(mock_discover, monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    monkeypatch.setenv("OAUTH_AUTHORIZE_URL", "https://staging.example.com/oauth/start")
    monkeypatch.setenv("OAUTH_TOKEN_ENDPOINT", "https://staging.example.com/oauth/token")
    mock_discover.return_value = _empty_discovery()
    yaml_path = _write_profile(tmp_path, _FULL_BLOCK)
    profile = assemble_profile(TARGET, yaml_path=str(yaml_path))
    ds = profile.oauth.delegated_send
    assert ds.authorize_url == "https://staging.example.com/oauth/start"
    assert ds.token_endpoint == "https://staging.example.com/oauth/token"
    # Non-overridden structural fields survive the merge.
    assert list(ds.required_scopes) == ["https://www.googleapis.com/auth/gmail.send"]


@mock.patch("profile_assembler.discover_live")
def test_assembler_no_oauth_env_leaves_block_absent(mock_discover, monkeypatch):
    _clear_env(monkeypatch)
    mock_discover.return_value = _empty_discovery()
    profile = assemble_profile(TARGET)
    # No YAML, no env → no spurious oauth block grafted on.
    assert profile.oauth is None
