"""Tests for discover.detect_auth_provider (U4) — layered source detection.

Each test builds a tiny fixture repo in tmp_path. The five plan scenarios:
Supabase-only, Clerk + Supabase-DB, dual active (ambiguous), prose conflict,
and source absent — plus the assemble_profile integration (no silent Clerk
default for a Supabase-Auth repo).
"""

from __future__ import annotations

import json
from pathlib import Path

from discover import assemble_profile, detect_auth_provider


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _package_json(root: Path, deps: dict[str, str]) -> None:
    _write(root, "package.json", json.dumps({"name": "fixture", "dependencies": deps}))


# ---------------------------------------------------------------------------
# Plan scenarios
# ---------------------------------------------------------------------------

def test_supabase_only_repo_resolves_supabase_auth_high(tmp_path):
    _package_json(tmp_path, {"@supabase/supabase-js": "^2.0.0", "@supabase/ssr": "^0.10.0"})
    _write(tmp_path, "middleware.ts", (
        'import { createServerClient } from "@supabase/ssr";\n'
        "const { data } = await supabase.auth.getUser();\n"
    ))
    verdict = detect_auth_provider(tmp_path)
    assert verdict["provider"] == "supabase-auth"
    assert verdict["confidence"] == "high"
    assert any("supabase-auth" in line for line in verdict["evidence"])


def test_supabase_dep_without_usage_still_wins_as_sole_auth_lib(tmp_path):
    # No detectable auth API usage, but nothing else could be doing auth.
    _package_json(tmp_path, {"@supabase/supabase-js": "^2.0.0"})
    _write(tmp_path, "src/db.ts", 'const rows = await supabase.from("docs").select();\n')
    verdict = detect_auth_provider(tmp_path)
    assert verdict["provider"] == "supabase-auth"
    assert verdict["confidence"] == "high"
    assert any("sole auth-capable" in line for line in verdict["evidence"])


def test_clerk_plus_supabase_db_resolves_clerk_high(tmp_path):
    _package_json(tmp_path, {"@clerk/nextjs": "^5.0.0", "@supabase/supabase-js": "^2.0.0"})
    _write(tmp_path, "middleware.ts", 'import { clerkMiddleware } from "@clerk/nextjs/server";\n')
    _write(tmp_path, "src/db.ts", 'const rows = await supabase.from("docs").select();\n')
    verdict = detect_auth_provider(tmp_path)
    assert verdict["provider"] == "clerk"
    assert verdict["confidence"] == "high"
    # Supabase noted as DB-only, not a candidate.
    assert any("database/storage use only" in line for line in verdict["evidence"])


def test_dual_active_libs_is_ambiguous_with_evidence(tmp_path):
    _package_json(tmp_path, {"@clerk/nextjs": "^5.0.0", "@supabase/ssr": "^0.10.0"})
    _write(tmp_path, "middleware.ts", (
        'import { createServerClient } from "@supabase/ssr";\n'
        "await supabase.auth.getSession();\n"
    ))
    _write(tmp_path, "src/app.tsx", 'import { ClerkProvider } from "@clerk/nextjs";\n')
    verdict = detect_auth_provider(tmp_path)
    assert verdict["provider"] is None
    assert verdict["confidence"] == "ambiguous"
    joined = "\n".join(verdict["evidence"])
    assert "AMBIGUOUS" in joined
    assert "clerk" in joined and "supabase-auth" in joined


def test_prose_conflict_code_wins_and_is_noted(tmp_path):
    _package_json(tmp_path, {"@clerk/nextjs": "^5.0.0"})
    _write(tmp_path, "CLAUDE.md", "## Stack\nAuth is handled by Supabase Auth (GoTrue).\n")
    verdict = detect_auth_provider(tmp_path)
    assert verdict["provider"] == "clerk"  # code wins
    assert verdict["confidence"] == "high"
    assert any("CONFLICT" in line and "supabase-auth" in line for line in verdict["evidence"])


def test_prose_corroboration_is_recorded(tmp_path):
    _package_json(tmp_path, {"next-auth": "^4.0.0"})
    _write(tmp_path, "AGENTS.md", "Auth: next-auth credentials provider.\n")
    verdict = detect_auth_provider(tmp_path)
    assert verdict["provider"] == "nextauth"
    assert any("corroborated" in line for line in verdict["evidence"])


def test_no_source_signals_returns_none(tmp_path):
    _write(tmp_path, "README.md", "empty project\n")
    verdict = detect_auth_provider(tmp_path)
    assert verdict["provider"] is None
    assert verdict["confidence"] == "none"
    assert any("no auth-capable library" in line for line in verdict["evidence"])


def test_firebase_dual_purpose_requires_usage_when_not_sole(tmp_path):
    # firebase dep + clerk dep, firebase used only for firestore -> clerk wins.
    _package_json(tmp_path, {"firebase": "^10.0.0", "@clerk/nextjs": "^5.0.0"})
    _write(tmp_path, "src/db.ts", 'import { getFirestore } from "firebase/firestore";\n')
    _write(tmp_path, "src/auth.ts", 'import { useAuth } from "@clerk/nextjs";\n')
    verdict = detect_auth_provider(tmp_path)
    assert verdict["provider"] == "clerk"
    assert verdict["confidence"] == "high"


def test_firebase_auth_usage_makes_it_a_candidate(tmp_path):
    _package_json(tmp_path, {"firebase": "^10.0.0", "@clerk/nextjs": "^5.0.0"})
    _write(tmp_path, "src/auth.ts", (
        'import { getAuth, signInWithEmailAndPassword } from "firebase/auth";\n'
    ))
    _write(tmp_path, "src/app.tsx", 'import { ClerkProvider } from "@clerk/nextjs";\n')
    verdict = detect_auth_provider(tmp_path)
    assert verdict["confidence"] == "ambiguous"


# ---------------------------------------------------------------------------
# Integration: assemble_profile surfaces the verdict
# ---------------------------------------------------------------------------

def test_assemble_profile_sets_supabase_auth_not_clerk(tmp_path, capsys):
    _package_json(tmp_path, {"@supabase/supabase-js": "^2.0.0", "@supabase/ssr": "^0.10.0"})
    _write(tmp_path, "middleware.ts", "await supabase.auth.getUser();\n")
    profile = assemble_profile(tmp_path)
    assert profile["stack"]["auth"] == "supabase-auth"
    err = capsys.readouterr().err
    assert "[detect-auth] provider=supabase-auth confidence=high" in err
    assert "[detect-auth-json]" in err


def test_assemble_profile_ambiguous_refuses_silent_pick(tmp_path, capsys):
    _package_json(tmp_path, {"@clerk/nextjs": "^5.0.0", "@supabase/ssr": "^0.10.0"})
    _write(tmp_path, "middleware.ts", "await supabase.auth.getSession();\n")
    _write(tmp_path, "src/app.tsx", 'import { ClerkProvider } from "@clerk/nextjs";\n')
    profile = assemble_profile(tmp_path)
    # Loud placeholder, NOT a silent clerk default. An unsupported value also
    # fails create_adapter fast instead of probing with the wrong adapter.
    assert profile["stack"]["auth"].startswith("CONFIRM")
    assert "stack.auth was NOT set" in capsys.readouterr().err


def test_assemble_profile_clerk_repo_unchanged(tmp_path):
    _package_json(tmp_path, {"@clerk/nextjs": "^5.0.0"})
    _write(tmp_path, "src/app.tsx", 'import { ClerkProvider } from "@clerk/nextjs";\n')
    profile = assemble_profile(tmp_path)
    assert profile["stack"]["auth"] == "clerk"
    assert "clerk" in profile  # frontend_api TODO block still emitted


def test_assemble_profile_confidence_none_clears_loose_clerk_substring(tmp_path):
    # detect_stack's loose r"clerk" substring regex sets auth='clerk' for ANY
    # dependency name containing "clerk"; the verdict (no @clerk/* dep ->
    # confidence=none) must clear it so the profile matches the printed verdict.
    _package_json(tmp_path, {"clerk-stub-utils": "^1.0.0"})
    profile = assemble_profile(tmp_path)
    assert "auth" not in profile["stack"]
    assert "clerk" not in profile  # no spurious clerk TODO block either


# ---------------------------------------------------------------------------
# Truncated usage scan must not demote a dual-purpose lib to DB-only
# ---------------------------------------------------------------------------

def test_truncated_scan_keeps_dual_purpose_lib_as_candidate(tmp_path):
    # Clerk + Supabase deps; Supabase HAS auth usage, but the scan budget is
    # too small to see it. Demoting Supabase to DB-only would yield a
    # confident WRONG 'clerk' pick — instead the verdict must stay ambiguous.
    _package_json(tmp_path, {"@clerk/nextjs": "^5.0.0", "@supabase/ssr": "^0.10.0"})
    _write(tmp_path, "src/a.ts", 'import { ClerkProvider } from "@clerk/nextjs";\n')
    _write(tmp_path, "src/z-middleware.ts", "await supabase.auth.getSession();\n")
    verdict = detect_auth_provider(tmp_path, max_usage_files=0)
    assert verdict["confidence"] == "ambiguous"
    assert any("TRUNCATED" in line for line in verdict["evidence"])


def test_untruncated_scan_behaves_as_before(tmp_path):
    _package_json(tmp_path, {"@clerk/nextjs": "^5.0.0", "@supabase/supabase-js": "^2.0.0"})
    _write(tmp_path, "src/a.ts", 'import { ClerkProvider } from "@clerk/nextjs";\n')
    _write(tmp_path, "src/db.ts", 'const rows = await supabase.from("docs").select();\n')
    verdict = detect_auth_provider(tmp_path)  # default budget, not truncated
    assert verdict["provider"] == "clerk"
    assert verdict["confidence"] == "high"


# ---------------------------------------------------------------------------
# [RX-TEST] usage-pattern vectors — the load-bearing no-match case is a
# Supabase DB call, which must NOT count as auth usage.
# ---------------------------------------------------------------------------

def test_rx_supabase_auth_usage_pattern_vectors():
    import re

    from discover import _AUTH_USAGE_PATTERNS

    pattern = _AUTH_USAGE_PATTERNS["supabase-auth"]
    assert re.search(pattern, "await supabase.auth.getUser();")
    assert re.search(pattern, 'import { createServerClient } from "@supabase/ssr";')
    assert not re.search(pattern, 'const rows = await supabase.from("docs").select();')
    assert not re.search(pattern, 'import { createClient } from "@supabase/supabase-js";')


def test_rx_clerk_usage_pattern_vectors():
    import re

    from discover import _AUTH_USAGE_PATTERNS

    pattern = _AUTH_USAGE_PATTERNS["clerk"]
    assert re.search(pattern, 'import { clerkMiddleware } from "@clerk/nextjs/server";')
    assert not re.search(pattern, "// mentions clerk in a comment only")
