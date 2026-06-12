"""Tests for the default-on probe exclusions (U3).

Covers the shared filter (exclusions.py) and every seam that must honor it:
pytest enumeration (conftest helpers), source discovery (discover.py), and
ZAP requestor injection (zap/build_runtime_plan.py) — plus profile validation
and assembler default-injection.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import profile_assembler
from discover import detect_stack, discover_endpoints
from exclusions import (
    DEFAULT_EXCLUDE_PATHS,
    DEFAULT_EXCLUDE_TABLES,
    effective_exclude_paths,
    effective_exclude_tables,
    is_excluded_path,
    is_excluded_table,
)
from profile import Profile, load_profile
from tests.conftest import all_tables, endpoints_for_category
from zap.build_runtime_plan import (
    build_requestor_requests,
    inject_into_plan,
    zap_exclude_regexes,
)


# ---------------------------------------------------------------------------
# Shared filter semantics
# ---------------------------------------------------------------------------

def test_effective_paths_is_union_of_user_and_defaults():
    effective = effective_exclude_paths(["/custom-wipe"])
    assert "/custom-wipe" in effective
    for default in DEFAULT_EXCLUDE_PATHS:
        assert default in effective


def test_empty_user_list_still_enforces_defaults():
    assert set(effective_exclude_paths([])) == set(effective_exclude_paths(None))
    assert set(effective_exclude_tables([])) == set(effective_exclude_tables(None))


def test_path_match_is_case_insensitive_prefix_with_segment_boundary():
    assert is_excluded_path("/logout")
    assert is_excluded_path("/LOGOUT")
    assert is_excluded_path("/logout/all")           # sub-path
    assert not is_excluded_path("/logout-stats")     # not a raw string prefix
    assert not is_excluded_path("/profile")


def test_token_rotation_paths_excluded_by_default():
    assert is_excluded_path("/auth/v1/token")
    assert is_excluded_path("/oauth/token")


def test_query_and_fragment_stripped_before_match():
    assert is_excluded_path("/logout?all=1")
    assert is_excluded_path("/logout#section")
    assert is_excluded_path("/auth/v1/token?grant_type=refresh_token")


def test_table_match_is_exact_and_case_insensitive():
    assert is_excluded_table("auth.users")
    assert is_excluded_table("AUTH.USERS")
    assert not is_excluded_table("users")            # exact-name only
    assert is_excluded_table("Documents", effective_exclude_tables(["documents"]))


# ---------------------------------------------------------------------------
# Seam: pytest enumeration (conftest helpers)
# ---------------------------------------------------------------------------

def _profile_with(endpoints=None, tables=None, **extra) -> Profile:
    data = {"target": {"base_url": "https://example.test"}}
    if endpoints is not None:
        data["endpoints"] = endpoints
    if tables is not None:
        data["supabase"] = {"tables": {"user_facing": tables}}
    data.update(extra)
    return Profile(data)


def test_endpoints_for_category_drops_default_excluded_paths():
    profile = _profile_with(endpoints={
        "authenticated": [
            {"path": "/logout", "method": "POST"},
            {"path": "/list-documents", "method": "GET"},
        ],
    })
    paths = [ep["path"] for ep in endpoints_for_category(profile, "authenticated")]
    assert paths == ["/list-documents"]


def test_endpoints_for_category_honors_user_exclude_paths():
    profile = _profile_with(
        endpoints={"authenticated": [
            {"path": "/admin/reset-demo", "method": "POST"},
            {"path": "/list-documents", "method": "GET"},
        ]},
        exclude_paths=["/admin/reset-demo"],
    )
    paths = [ep["path"] for ep in endpoints_for_category(profile, "authenticated")]
    assert paths == ["/list-documents"]


def test_all_tables_drops_excluded_tables():
    profile = _profile_with(
        tables=["documents", "auth.users", "projects"],
        exclude_tables=["documents"],
    )
    assert all_tables(profile, "user_facing") == ["projects"]


def test_all_tables_default_excludes_auth_users():
    profile = _profile_with(tables=["auth.users", "projects"])
    assert all_tables(profile, "user_facing") == ["projects"]


# ---------------------------------------------------------------------------
# Seam: source discovery (discover.py)
# ---------------------------------------------------------------------------

def test_discover_endpoints_skips_excluded_paths(tmp_path):
    (tmp_path / "netlify.toml").write_text("[build]\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@clerk/clerk-js": "5.0.0"}}', encoding="utf-8"
    )
    funcs = tmp_path / "netlify" / "functions"
    funcs.mkdir(parents=True)
    (funcs / "logout.js").write_text("export default verifyAuth(handler)", encoding="utf-8")
    (funcs / "get-data.js").write_text("export default verifyAuth(handler)", encoding="utf-8")

    stack = detect_stack(tmp_path)
    endpoints = discover_endpoints(tmp_path, stack)
    all_paths = [ep["path"] for group in endpoints.values() for ep in group]
    assert "/get-data" in all_paths
    assert "/logout" not in all_paths


# ---------------------------------------------------------------------------
# Seam: ZAP requestor injection (zap/build_runtime_plan.py)
# ---------------------------------------------------------------------------

def test_zap_plan_skips_default_excluded_paths():
    data = {
        "target": {"api_prefix": "/.netlify/functions"},
        "endpoints": {
            "authenticated": [
                {"path": "/logout", "method": "POST"},
                {"path": "/list-documents", "method": "GET"},
            ],
            "anonymous": [{"path": "/signout", "method": "POST"}],
        },
    }
    urls = [r["url"] for r in build_requestor_requests(data)]
    assert any("/list-documents" in u for u in urls)
    assert not any("/logout" in u for u in urls)
    assert not any("/signout" in u for u in urls)


def test_zap_plan_honors_user_exclude_paths_and_uploads():
    data = {
        "endpoints": {"authenticated": [{"path": "/custom-wipe", "method": "POST"}]},
        "uploads": {"endpoint": "/upload-csv"},
        "exclude_paths": ["/custom-wipe", "/upload-csv"],
    }
    assert build_requestor_requests(data) == []


def test_zap_context_exclude_regexes_cover_default_paths():
    regexes = zap_exclude_regexes({})
    # Keeps the ${TARGET_BASE_URL} token literal for scan-time substitution
    # (after the case-insensitive flag).
    assert all(r.startswith("(?i)${TARGET_BASE_URL}") for r in regexes)
    joined = "\n".join(regexes)
    assert "/logout" in joined
    assert "/auth/v1/token" in joined


def test_inject_into_plan_adds_exclude_paths_to_every_context():
    plan = {
        "env": {"contexts": [
            {"name": "target-authed", "excludePaths": ["${TARGET_BASE_URL}/.*\\.png"]},
            {"name": "target-anon", "excludePaths": []},
        ]},
        "jobs": [{"type": "requestor", "requests": []}],
    }
    import re as _re
    regexes = zap_exclude_regexes({"exclude_paths": ["/custom-wipe"]})
    inject_into_plan(plan, [], regexes)
    for context in plan["env"]["contexts"]:
        patterns = [
            r.replace("${TARGET_BASE_URL}", "https://site.com")
            for r in context["excludePaths"]
        ]
        # Both the default (/logout) and user path (/custom-wipe) are excluded.
        assert any(_re.fullmatch(p, "https://site.com/logout") for p in patterns)
        assert any(_re.fullmatch(p, "https://site.com/custom-wipe") for p in patterns)
    # Static-asset exclusion preserved on the context that had one.
    assert any(".png" in r for r in plan["env"]["contexts"][0]["excludePaths"])


def test_inject_exclude_paths_is_idempotent():
    plan = {
        "env": {"contexts": [{"name": "c", "excludePaths": []}]},
        "jobs": [{"type": "requestor", "requests": []}],
    }
    regexes = zap_exclude_regexes({})
    inject_into_plan(plan, [], regexes)
    first = list(plan["env"]["contexts"][0]["excludePaths"])
    inject_into_plan(plan, [], regexes)
    assert plan["env"]["contexts"][0]["excludePaths"] == first


def test_zap_exclude_regex_respects_segment_boundary():
    import re as _re
    regexes = zap_exclude_regexes({"exclude_paths": ["/reset-password"]})
    rx = next(r for r in regexes if "reset" in r)
    # Substitute the literal token with a concrete base, then full-match URLs.
    pattern = rx.replace("${TARGET_BASE_URL}", "https://site.com")
    assert _re.fullmatch(pattern, "https://site.com/reset-password")
    assert _re.fullmatch(pattern, "https://site.com/reset-password?token=x")
    assert _re.fullmatch(pattern, "https://site.com/reset-password/confirm")
    # Anchored at the base: a sibling segment is NOT over-excluded...
    assert not _re.fullmatch(pattern, "https://site.com/reset-password-help")
    # ...and a nested endpoint that merely contains the path is NOT excluded,
    # matching exclusions.is_excluded_path("/api/reset-password", ["/reset-password"]).
    assert not _re.fullmatch(pattern, "https://site.com/api/reset-password")
    assert not is_excluded_path(
        "/api/reset-password", effective_exclude_paths(["/reset-password"])
    )


def test_zap_exclude_regex_is_case_insensitive():
    import re as _re
    rx = next(r for r in zap_exclude_regexes({}) if "logout" in r and "auth" not in r)
    pattern = rx.replace("${TARGET_BASE_URL}", "https://site.com")
    # ZAP matches case-sensitively; the (?i) flag must make /Logout match the
    # lowercased exclusion (the spider crawls real-cased links).
    assert _re.fullmatch(pattern, "https://site.com/Logout")
    assert _re.fullmatch(pattern, "https://site.com/LOGOUT/all")


def test_zap_exclude_regex_skips_root_path():
    # A "/" exclude_path would compile to a catch-all; it must be dropped so the
    # scan is not silently disabled.
    regexes = zap_exclude_regexes({"exclude_paths": ["/"]})
    import re as _re
    for rx in regexes:
        pattern = rx.replace("${TARGET_BASE_URL}", "https://site.com")
        assert not _re.fullmatch(pattern, "https://site.com/dashboard")


# ---------------------------------------------------------------------------
# Profile validation + assembler injection
# ---------------------------------------------------------------------------

def test_load_profile_rejects_non_list_exclude_fields(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "target:\n  base_url: https://example.test\nexclude_paths: not-a-list\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exclude_paths"):
        load_profile(bad)


def test_load_profile_accepts_string_lists(tmp_path):
    ok = tmp_path / "ok.yaml"
    ok.write_text(
        "target:\n  base_url: https://example.test\n"
        "exclude_paths:\n  - /custom\nexclude_tables:\n  - audit\n",
        encoding="utf-8",
    )
    profile = load_profile(ok)
    assert profile.exclude_paths == ["/custom"]


def test_assemble_profile_bakes_effective_lists(monkeypatch):
    monkeypatch.setattr(profile_assembler, "discover_live", lambda url: {})
    profile = profile_assembler.assemble_profile("https://example.test")
    raw = profile.raw()
    assert set(DEFAULT_EXCLUDE_PATHS) <= set(raw["exclude_paths"])
    assert set(t.lower() for t in DEFAULT_EXCLUDE_TABLES) <= set(raw["exclude_tables"])


def test_assemble_profile_unions_yaml_excludes(monkeypatch, tmp_path):
    monkeypatch.setattr(profile_assembler, "discover_live", lambda url: {})
    yaml_path = tmp_path / "site.yaml"
    yaml_path.write_text(
        yaml.safe_dump({
            "target": {"base_url": "https://example.test"},
            "exclude_paths": ["/admin/reset-demo"],
            "exclude_tables": ["legacy_audit"],
        }),
        encoding="utf-8",
    )
    raw = profile_assembler.assemble_profile(
        "https://example.test", yaml_path=str(yaml_path)
    ).raw()
    assert "/admin/reset-demo" in raw["exclude_paths"]
    assert set(DEFAULT_EXCLUDE_PATHS) <= set(raw["exclude_paths"])
    assert "legacy_audit" in raw["exclude_tables"]
    assert set(t.lower() for t in DEFAULT_EXCLUDE_TABLES) <= set(raw["exclude_tables"])
