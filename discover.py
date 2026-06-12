"""Auto-discover a project's stack, endpoints, and Supabase resources.

Usage:
    python discover.py /path/to/project [--output profile.yaml]

Outputs a complete profile YAML to stdout (or --output file) following the
schema in profiles/clerk-supabase-example.yaml.

Dependencies: stdlib only + pyyaml (already in pyproject.toml dependencies).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import warnings
from pathlib import Path
from typing import Any

import yaml

from exclusions import is_excluded_path
from providers import ProviderManifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Directories to skip during any recursive walk to avoid noise from worktrees,
# build artefacts, and dependency trees.
_SKIP_DIRS = {
    ".git", ".claude", "node_modules", "__pycache__", ".venv", "venv",
    ".next", ".nuxt", "dist", "build", ".turbo", ".vercel",
}


def _walk_files(root: Path) -> list[Path]:
    """Recursively yield files under root, skipping _SKIP_DIRS."""
    results: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except PermissionError:
            continue
        for entry in sorted(entries):
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    stack.append(entry)
            elif entry.is_file():
                results.append(entry)
    return results


def _glob_first(root: Path, *patterns: str) -> Path | None:
    """Return the first file matching any of the given glob patterns, skipping _SKIP_DIRS."""
    all_files = _walk_files(root)
    import fnmatch
    for pattern in patterns:
        for f in all_files:
            try:
                rel = str(f.relative_to(root)).replace("\\", "/")
            except ValueError:
                continue
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(f.name, pattern.lstrip("*/")):
                return f
    return None


def _grep_files(
    root: Path,
    pattern: str,
    glob: str = "**/*",
    max_files: int = 2000,
) -> list[tuple[Path, str]]:
    """Return (path, matched_line) pairs for files under root that contain pattern.

    Uses _walk_files to skip worktrees, node_modules, and other noise dirs.
    The ``glob`` parameter is used only for suffix filtering when it ends with
    a simple extension pattern (e.g. ``**/*.{js,ts}``).
    """
    import fnmatch as _fnmatch
    regex = re.compile(pattern)

    # Extract extension filter from glob pattern if present (e.g. *.js,ts,mjs)
    ext_filter: set[str] | None = None
    ext_match = re.search(r"\*\.(\{[^}]+\}|\w+)$", glob)
    if ext_match:
        raw = ext_match.group(1).strip("{}")
        ext_filter = {"." + e.strip() for e in raw.split(",")}

    results: list[tuple[Path, str]] = []
    count = 0
    for path in _walk_files(root):
        if ext_filter and path.suffix not in ext_filter:
            continue
        count += 1
        if count > max_files:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            if regex.search(line):
                results.append((path, line.strip()))
    return results


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Step 1: Stack detection
# ---------------------------------------------------------------------------

def detect_stack(root: Path) -> dict[str, str]:
    stack: dict[str, str] = {}

    all_files = _walk_files(root)
    all_names = {f.name: f for f in all_files}  # last-wins; fine for hosting detection

    # Hosting
    if "netlify.toml" in all_names:
        stack["hosting"] = "netlify"
    elif "vercel.json" in all_names:
        stack["hosting"] = "vercel"
    elif "wrangler.toml" in all_names:
        stack["hosting"] = "cloudflare"

    # Collect all package.json dependency strings
    dep_text = ""
    for f in all_files:
        if f.name == "package.json":
            dep_text += _read_text(f)

    # Collect requirements.txt
    for f in all_files:
        if f.name == "requirements.txt":
            dep_text += _read_text(f)

    if re.search(r'"@clerk/', dep_text) or re.search(r"clerk", dep_text, re.IGNORECASE):
        stack["auth"] = "clerk"

    if re.search(r'"@supabase/supabase-js"', dep_text) or re.search(r"supabase", dep_text, re.IGNORECASE):
        stack["database"] = "supabase"
        stack["storage"] = "supabase"

    if re.search(r'"stripe"', dep_text) or re.search(r"\bstripe\b", dep_text, re.IGNORECASE):
        stack["payments"] = "stripe"

    return stack


# ---------------------------------------------------------------------------
# Step 1b: Auth-provider detection (source-scan accelerator)
# ---------------------------------------------------------------------------
# Why this exists: a deployed-bundle scan cannot distinguish Supabase-Auth
# from Clerk-auth-on-Supabase-DB (supabase-js statically bundles GoTrue even
# for database-only use — supabase-js#151), so black-box discovery defaults
# auth away from supabase-auth. Source CAN resolve it: dependency presence is
# deterministic, and active-usage signals separate "uses the auth product"
# from "uses the same vendor's database". This is an opt-in accelerator —
# black-box bundle discovery stays the zero-config default.

# Auth-capable libraries and how to spot them in package.json dependencies.
# "dedicated" libs exist only to do auth — presence alone is auth intent.
# "dual-purpose" libs (Supabase, Firebase) also serve DB/storage roles, so
# presence alone is NOT auth intent; active usage must corroborate.
_AUTH_DEP_PATTERNS: dict[str, tuple[re.Pattern, bool]] = {
    # provider -> (dependency-name regex, dedicated_auth_lib)
    "clerk": (re.compile(r"^@clerk/"), True),
    "nextauth": (re.compile(r"^(next-auth|@auth/)"), True),
    "supabase-auth": (re.compile(r"^@supabase/(supabase-js|ssr|auth-helpers)"), False),
    "firebase": (re.compile(r"^(firebase|firebase-admin)$"), False),
}

# Active-usage signals per provider, run over .js/.ts/.mjs source. The
# Supabase patterns deliberately target the auth product (GoTrue calls and
# @supabase/ssr session plumbing), not generic client construction — a
# Clerk + Supabase-DB repo creates Supabase clients but never calls
# supabase.auth.* or mints sessions in middleware.
_AUTH_USAGE_PATTERNS: dict[str, str] = {
    "clerk": r"""from\s+['"]@clerk/|require\(['"]@clerk/|clerkMiddleware\s*\(|<ClerkProvider""",
    "nextauth": r"""from\s+['"]next-auth|from\s+['"]@auth/|NextAuth\s*\(|getServerSession\s*\(""",
    "supabase-auth": (
        r"\.auth\.(signInWithPassword|signInWithOtp|signInWithOAuth|signUp|"
        r"getUser|getSession|onAuthStateChange|exchangeCodeForSession|setSession|"
        r"verifyOtp|admin)\b"
        r"""|from\s+['"]@supabase/ssr['"]"""
        r"|createServerClient\s*\(|createBrowserClient\s*\(|createMiddlewareClient\s*\("
    ),
    "firebase": (
        r"""from\s+['"]firebase/auth['"]"""
        r"|getAuth\s*\(|signInWithEmailAndPassword\s*\(|onAuthStateChanged\s*\("
    ),
}

# Provider keywords for the CLAUDE.md / AGENTS.md prose layer.
_AUTH_PROSE_PATTERNS: dict[str, str] = {
    "clerk": r"\bclerk\b",
    "nextauth": r"\bnext-?auth\b|\bauth\.js\b",
    "supabase-auth": r"\bsupabase[ -]auth\b|\bgotrue\b",
    "firebase": r"\bfirebase[ -]auth\b",
}


def _auth_deps_present(root: Path) -> dict[str, str]:
    """Return {provider: evidence} for auth-capable deps in any package.json."""
    found: dict[str, str] = {}
    for f in _walk_files(root):
        if f.name != "package.json":
            continue
        try:
            pkg = json.loads(_read_text(f))
        except (ValueError, TypeError):
            continue
        if not isinstance(pkg, dict):
            continue
        dep_names: list[str] = []
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            block = pkg.get(section)
            if isinstance(block, dict):
                dep_names.extend(block.keys())
        rel = str(f.relative_to(root)).replace("\\", "/")
        for provider, (pattern, _dedicated) in _AUTH_DEP_PATTERNS.items():
            if provider in found:
                continue
            for name in dep_names:
                if pattern.match(name):
                    found[provider] = f"dependency '{name}' in {rel}"
                    break
    return found


def _auth_usage_evidence(
    root: Path, max_files: int = 2000
) -> tuple[dict[str, list[str]], bool]:
    """Return ({provider: [evidence lines]}, scan_truncated) for active auth usage.

    ``scan_truncated`` is True when the repo has more candidate source files
    than the grep budget — absence of usage evidence is then NOT evidence of
    absence, and the caller must not demote a dual-purpose library to
    "database-only" on that basis.
    """
    _USAGE_EXTS = {".js", ".ts", ".mjs", ".jsx", ".tsx"}
    candidate_count = sum(1 for f in _walk_files(root) if f.suffix in _USAGE_EXTS)
    truncated = candidate_count > max_files

    usage: dict[str, list[str]] = {}
    for provider, pattern in _AUTH_USAGE_PATTERNS.items():
        hits = _grep_files(root, pattern, "**/*.{js,ts,mjs,jsx,tsx}", max_files=max_files)
        lines: list[str] = []
        for path, line in hits[:3]:  # a few concrete examples beat a flood
            try:
                rel = str(path.relative_to(root)).replace("\\", "/")
            except ValueError:
                rel = path.name
            marker = " [middleware]" if path.stem == "middleware" else ""
            lines.append(f"{rel}{marker}: {line[:120]}")
        if lines:
            if len(hits) > 3:
                lines.append(f"(+{len(hits) - 3} more matches)")
            usage[provider] = lines
    return usage, truncated


def _auth_prose_claims(root: Path) -> dict[str, str]:
    """Read the target's CLAUDE.md / AGENTS.md for auth-provider claims.

    Corroboration ONLY — prose never overrides what the code shows. Returns
    {provider: evidence line}.
    """
    claims: dict[str, str] = {}
    for name in ("CLAUDE.md", "AGENTS.md", ".claude/CLAUDE.md"):
        doc = root / name
        if not doc.is_file():
            continue
        for line in _read_text(doc).splitlines():
            lowered = line.lower()
            if "auth" not in lowered:
                continue
            for provider, pattern in _AUTH_PROSE_PATTERNS.items():
                if provider not in claims and re.search(pattern, lowered):
                    claims[provider] = f"{name}: {line.strip()[:120]}"
    return claims


def detect_auth_provider(root: Path, max_usage_files: int = 2000) -> dict[str, Any]:
    """Detect the project's ACTIVE auth provider from source, with a verdict.

    Layered signals, strongest first:
      1. Dependency presence (package.json) — deterministic for *presence*.
      2. Active usage — `supabase.auth.*` / `@supabase/ssr` session plumbing
         vs `@clerk/*` imports etc. Separates the auth product from a
         dual-purpose vendor's DB/storage use.
      3. `CLAUDE.md` / `AGENTS.md` prose — corroboration only; on conflict
         the code wins and the conflict is surfaced as evidence.

    Returns ``{"provider": str | None, "confidence": "high" | "ambiguous" |
    "none", "evidence": list[str]}``. ``provider`` uses ``stack.auth`` values
    (``clerk`` / ``firebase`` / ``nextauth`` / ``supabase-auth``). One
    candidate -> ``high``; two or more -> ``ambiguous`` (the caller MUST
    confirm with a human — never silently pick); none -> ``none``.
    """
    deps = _auth_deps_present(root)
    usage, scan_truncated = _auth_usage_evidence(root, max_files=max_usage_files)
    prose = _auth_prose_claims(root)

    evidence: list[str] = []
    candidates: list[str] = []
    if scan_truncated:
        evidence.append(
            f"usage scan TRUNCATED (more than {max_usage_files} source files) — "
            "absence of usage evidence is not evidence of absence"
        )
    for provider, dep_evidence in deps.items():
        dedicated = _AUTH_DEP_PATTERNS[provider][1]
        used = provider in usage
        if dedicated or used:
            candidates.append(provider)
            evidence.append(f"{provider}: {dep_evidence}")
            for line in usage.get(provider, []):
                evidence.append(f"{provider} usage: {line}")
        elif len(deps) == 1:
            # Sole auth-capable lib in the repo: nothing else could be doing
            # auth, so a dual-purpose lib counts even without usage hits.
            candidates.append(provider)
            evidence.append(
                f"{provider}: {dep_evidence} (sole auth-capable library; no "
                "auth API usage detected)"
            )
        elif scan_truncated:
            # A truncated scan may simply not have REACHED this library's
            # auth calls. Demoting it to "database-only" here could flip an
            # honest ambiguous verdict into a confident wrong pick, so keep
            # it as a candidate and let the confirm step decide.
            candidates.append(provider)
            evidence.append(
                f"{provider}: {dep_evidence} — no auth API usage found, but "
                "the usage scan was truncated; kept as a candidate"
            )
        else:
            evidence.append(
                f"{provider}: {dep_evidence} — no auth API usage found; "
                "treated as database/storage use only"
            )

    if not candidates:
        provider, confidence = None, "none"
        evidence.append("no auth-capable library detected in package.json")
    elif len(candidates) == 1:
        provider, confidence = candidates[0], "high"
    else:
        provider, confidence = None, "ambiguous"
        evidence.append(
            "AMBIGUOUS: multiple active auth candidates "
            f"({', '.join(sorted(candidates))}) — confirm with the site owner "
            "before picking stack.auth"
        )

    # Layer 3: prose. Never changes the pick; corroborates or flags conflict.
    for claimed, line in prose.items():
        if claimed == provider:
            evidence.append(f"corroborated by {line}")
        elif provider is not None:
            evidence.append(
                f"CONFLICT: prose claims '{claimed}' ({line}) but code "
                f"evidence says '{provider}' — code wins"
            )
        else:
            evidence.append(f"prose mentions '{claimed}' ({line})")

    return {"provider": provider, "confidence": confidence, "evidence": evidence}


def _report_auth_verdict(verdict: dict[str, Any]) -> None:
    """Print the detection verdict to stderr (human lines + one JSON line)."""
    print(
        f"[detect-auth] provider={verdict['provider'] or '<none>'} "
        f"confidence={verdict['confidence']}",
        file=sys.stderr,
    )
    for line in verdict["evidence"]:
        print(f"[detect-auth]   {line}", file=sys.stderr)
    if verdict["confidence"] == "ambiguous":
        print(
            "[detect-auth] stack.auth was NOT set — review the evidence above, "
            "confirm the active provider with the site owner, and set "
            "stack.auth in the profile explicitly.",
            file=sys.stderr,
        )
    print(f"[detect-auth-json] {json.dumps(verdict)}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Step 2: Endpoint discovery
# ---------------------------------------------------------------------------

def _classify_auth(text: str, file_path: Path) -> str:
    """Return the auth classification string for a function file's contents."""
    # Webhook patterns take precedence
    if re.search(r"webhook|svix\.verify|stripe\.webhooks\.constructEvent", text, re.IGNORECASE):
        return "webhook"
    # Payment
    if re.search(r"checkout|createCheckoutSession", text, re.IGNORECASE):
        return "payment"
    # Internal
    if re.search(r"verifyInternalCall|x-internal-secret", text, re.IGNORECASE):
        return "internal"
    # Anonymous (must come before authenticated so optional auth is caught first)
    if re.search(r"verifyAuthOrAnon|verifyOptionalAuth", text, re.IGNORECASE):
        return "anonymous"
    # Authenticated
    if re.search(r"verifyAuth|requireAuth|verifyToken", text, re.IGNORECASE):
        return "authenticated"
    # Unknown
    return f"unknown  # {file_path}"


def _extract_method(text: str) -> str:
    """Guess the HTTP method from handler source; defaults to POST."""
    m = re.search(r"""method\s*[=:]\s*["']([A-Z]+)["']""", text)
    if m:
        return m.group(1)
    if re.search(r"\bGET\b", text):
        return "GET"
    return "POST"


def _endpoint_path(func_file: Path, root: Path, hosting: str) -> str:
    """Derive the API endpoint path from a function file.

    Netlify: flat namespace — ``netlify/functions/foo.js`` → ``/foo``.
    Vercel: nested namespace — ``api/foo/bar.ts`` → ``/foo/bar``.
    Fallback: flat namespace from stem.
    """
    if hosting == "vercel":
        rel = func_file.relative_to(root)
        # Strip the leading "api/" directory and the file extension.
        parts = rel.with_suffix("").parts
        if parts and parts[0] == "api":
            parts = parts[1:]
        return "/" + "/".join(parts)
    # Netlify and fallback: flat namespace from file stem.
    return f"/{func_file.stem}"


def discover_endpoints(root: Path, stack: dict[str, str]) -> dict[str, list[dict[str, Any]]]:
    """Return an endpoints dict grouped by auth category."""
    hosting = stack.get("hosting", "")

    all_files = _walk_files(root)
    js_exts = {".js", ".ts", ".mjs"}

    function_files: list[Path] = []

    if hosting == "netlify":
        # Match files whose parent directory is named "functions" and whose
        # grandparent is named "netlify"
        for f in all_files:
            if f.suffix in js_exts and f.parent.name == "functions" and f.parent.parent.name == "netlify":
                function_files.append(f)
    elif hosting == "vercel":
        # Match files under any directory named "api"
        for f in all_files:
            if f.suffix in js_exts:
                parts = f.relative_to(root).parts
                if parts and parts[0] == "api":
                    function_files.append(f)
    else:
        # Best-effort fallback
        for f in all_files:
            if f.suffix in js_exts and f.parent.name in ("functions", "api"):
                function_files.append(f)

    # Deduplicate by resolved path (handles any remaining symlink edge cases)
    seen: set[Path] = set()
    deduped: list[Path] = []
    for f in function_files:
        key = f.resolve()
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Group into auth categories
    groups: dict[str, list[dict[str, Any]]] = {
        "authenticated": [],
        "anonymous": [],
        "webhook": [],
        "internal": [],
        "payment": [],
    }
    unknown: list[dict[str, Any]] = []

    for func_file in deduped:
        text = _read_text(func_file)
        path = _endpoint_path(func_file, root, hosting)
        # Default-on probe exclusions (session/state-destroying endpoints,
        # e.g. /logout): never emit them into a generated profile, so no
        # downstream seam can probe them. See exclusions.py.
        if is_excluded_path(path):
            continue
        method = _extract_method(text)
        auth = _classify_auth(text, func_file)

        ep: dict[str, Any] = {"path": path, "method": method}

        if auth.startswith("unknown"):
            ep["auth"] = auth
            unknown.append(ep)
        elif auth == "webhook":
            # Detect signature type
            if re.search(r"svix", text, re.IGNORECASE):
                ep["signature"] = "svix"
            elif re.search(r"stripe\.webhooks", text, re.IGNORECASE):
                ep["signature"] = "stripe"
            groups["webhook"].append(ep)
        elif auth == "payment":
            groups["payment"].append(ep)
        elif auth == "internal":
            groups["internal"].append(ep)
        elif auth == "anonymous":
            groups["anonymous"].append(ep)
        else:
            groups["authenticated"].append(ep)

    # Attach unknowns under a separate key if any
    result = {k: v for k, v in groups.items() if v}
    if unknown:
        result["unknown"] = unknown
    return result


# ---------------------------------------------------------------------------
# Step 3: Source file map
# ---------------------------------------------------------------------------

def build_source_file_map(
    root: Path,
    endpoints: dict[str, list[dict[str, Any]]],
    stack: dict[str, str],
) -> dict[str, str]:
    """Map endpoint paths to relative source file paths."""
    hosting = stack.get("hosting", "")
    sfm: dict[str, str] = {}
    js_exts = {".js", ".ts", ".mjs"}

    # Build a map from derived endpoint path → source file.
    # Uses the same _endpoint_path() logic as discover_endpoints() so
    # nested Vercel routes (api/foo/bar.ts → /foo/bar) map correctly.
    path_to_file: dict[str, Path] = {}
    for f in _walk_files(root):
        if f.suffix not in js_exts:
            continue
        if hosting == "netlify":
            if f.parent.name == "functions" and f.parent.parent.name == "netlify":
                ep_path = _endpoint_path(f, root, hosting)
                path_to_file[ep_path] = f
        else:
            parts = f.relative_to(root).parts
            if parts and parts[0] == "api":
                ep_path = _endpoint_path(f, root, hosting)
                path_to_file[ep_path] = f

    for group_eps in endpoints.values():
        for ep in group_eps:
            path = ep.get("path", "")
            if path in path_to_file:
                rel = path_to_file[path].relative_to(root)
                sfm[path] = str(rel).replace("\\", "/")

    return sfm


# ---------------------------------------------------------------------------
# Step 4: Supabase discovery
# ---------------------------------------------------------------------------

def discover_supabase(root: Path) -> dict[str, Any]:
    """Discover Supabase tables, RPCs, and storage buckets via grep."""
    result: dict[str, Any] = {
        "project_url": "https://YOUR_PROJECT.supabase.co  # TODO: fill in",
        "anon_key": "eyJ...  # TODO: fill in",
    }

    # Tables: .from("table_name")
    table_hits = _grep_files(root, r'\.from\("([^"]+)"\)', "**/*.{js,ts,mjs,py}")
    table_names: set[str] = set()
    for _, line in table_hits:
        m = re.search(r'\.from\("([^"]+)"\)', line)
        if m:
            name = m.group(1)
            # Exclude storage bucket names (detected separately)
            table_names.add(name)

    # Storage buckets: .storage.from("bucket_name")
    storage_hits = _grep_files(root, r'\.storage\.from\("([^"]+)"\)', "**/*.{js,ts,mjs,py}")
    bucket_names: set[str] = set()
    for _, line in storage_hits:
        m = re.search(r'\.storage\.from\("([^"]+)"\)', line)
        if m:
            bucket_names.add(m.group(1))

    # Remove bucket names from table names
    table_names -= bucket_names

    if table_names:
        result["tables"] = {"user_facing": sorted(table_names)}
    if bucket_names:
        result["storage_buckets"] = sorted(bucket_names)

    # Table PKs: grep migration files for common PK patterns
    table_pks: dict[str, str] = {}
    for mig_file in _walk_files(root):
        if mig_file.suffix != ".sql" or mig_file.parent.name != "migrations":
            continue
        text = _read_text(mig_file)
        # CREATE TABLE tname ( col ... PRIMARY KEY
        for m in re.finditer(
            r"CREATE TABLE\s+(?:\w+\.)?(\w+)\s*\((.+?)(?:PRIMARY KEY|;)",
            text,
            re.DOTALL | re.IGNORECASE,
        ):
            tbl = m.group(1)
            cols_block = m.group(2)
            # Look for column with PRIMARY KEY inline
            pk_m = re.search(r"(\w+)\s+\w+.*?PRIMARY KEY", cols_block, re.IGNORECASE)
            if pk_m:
                table_pks[tbl] = pk_m.group(1)

    if table_pks:
        result["table_pks"] = table_pks

    # RPCs: .rpc("function_name")
    rpc_hits = _grep_files(root, r'\.rpc\("([^"]+)"', "**/*.{js,ts,mjs,py}")
    client_rpcs: list[dict[str, Any]] = []
    seen_rpcs: set[str] = set()
    for path, line in rpc_hits:
        m = re.search(r'\.rpc\("([^"]+)"', line)
        if m:
            name = m.group(1)
            if name not in seen_rpcs:
                seen_rpcs.add(name)
                client_rpcs.append({"name": name, "risk": "unknown"})

    if client_rpcs:
        result["client_callable"] = client_rpcs

    return result


# ---------------------------------------------------------------------------
# Step 5: Feature flags
# ---------------------------------------------------------------------------

def detect_features(root: Path) -> dict[str, Any]:
    features: dict[str, Any] = {}

    anon_hits = _grep_files(root, r"anon_session|x-anon-session", "**/*.{js,ts,mjs,py}")
    if anon_hits:
        features["anon_sessions"] = True

    return features


# ---------------------------------------------------------------------------
# Step 6: Assemble profile YAML
# ---------------------------------------------------------------------------

def assemble_profile(root: Path) -> dict[str, Any]:
    """Run all discovery steps and return a complete profile dict."""
    stack = detect_stack(root)

    # Auth provider: detect_stack's dependency regexes can only see library
    # PRESENCE (and never emit supabase-auth at all). detect_auth_provider
    # layers deps -> active usage -> CLAUDE.md/AGENTS.md and is authoritative
    # here. High confidence sets stack.auth; ambiguity refuses to pick and
    # leaves a loud CONFIRM placeholder instead of silently defaulting.
    auth_verdict = detect_auth_provider(root)
    _report_auth_verdict(auth_verdict)
    if auth_verdict["confidence"] == "high":
        stack["auth"] = auth_verdict["provider"]
    elif auth_verdict["confidence"] == "ambiguous":
        stack["auth"] = (
            "CONFIRM  # TODO: ambiguous — multiple active auth libraries "
            "detected; see the [detect-auth] evidence and set explicitly"
        )
    else:
        # No auth-capable dependency found. detect_stack's loose substring
        # regex can still have set auth='clerk' (e.g. any package name
        # containing "clerk"); leaving it would emit a profile that
        # contradicts the printed verdict — the silent default U4 removes.
        stack.pop("auth", None)

    endpoints = discover_endpoints(root, stack)
    sfm = build_source_file_map(root, endpoints, stack)

    profile: dict[str, Any] = {}

    # target — we can only infer base_url shape, not the actual URL
    profile["target"] = {
        "base_url": "https://YOUR_DOMAIN.com  # TODO: fill in",
    }
    hosting = stack.get("hosting")
    if hosting == "netlify":
        profile["target"]["api_prefix"] = "/.netlify/functions"
    elif hosting == "vercel":
        profile["target"]["api_prefix"] = "/api"

    profile["stack"] = stack

    if stack.get("database") == "supabase":
        sb = discover_supabase(root)
        # Separate top-level supabase block from RPCs
        supabase_block: dict[str, Any] = {
            k: v for k, v in sb.items()
            if k not in ("client_callable",)
        }
        profile["supabase"] = supabase_block

        if "client_callable" in sb:
            profile["supabase_rpcs"] = {
                "client_callable": sb["client_callable"],
            }

    if stack.get("auth") == "clerk":
        profile["clerk"] = {
            "frontend_api": "https://YOUR_CLERK_INSTANCE.clerk.accounts.dev  # TODO: fill in",
        }

    if endpoints:
        profile["endpoints"] = endpoints

    if sfm:
        profile["source_file_map"] = sfm

    features = detect_features(root)
    if features:
        profile["features"] = features

    profile["test_accounts"] = {
        "user_a": {"email": "pentest-a@example.com"},
        "user_b": {"email": "pentest-b@example.com"},
    }

    return profile


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a project directory and auto-generate a pentest harness "
            "profile YAML. Outputs to stdout by default."
        ),
    )
    parser.add_argument(
        "project_dir",
        help="Root directory of the target project to scan.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write output to FILE instead of stdout.",
    )
    args = parser.parse_args()

    root = Path(args.project_dir).resolve()

    if not root.exists():
        print(f"error: directory does not exist: {root}", file=sys.stderr)
        return 1

    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 1

    # Check the directory is non-empty
    try:
        next(root.iterdir())
    except StopIteration:
        print(f"error: directory is empty: {root}", file=sys.stderr)
        return 1

    pkg_json = _glob_first(root, "package.json", "**/package.json")
    req_txt = _glob_first(root, "requirements.txt", "**/requirements.txt")
    if not pkg_json and not req_txt:
        warnings.warn(
            "No package.json or requirements.txt found. "
            "Stack detection will be limited.",
            stacklevel=1,
        )

    profile = assemble_profile(root)

    output_text = yaml.dump(
        profile,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_text, encoding="utf-8")
        print(f"Profile written to: {out_path.resolve()}", file=sys.stderr)
    else:
        print(output_text, end="")

    return 0


if __name__ == "__main__":
    sys.exit(main())


# ---------------------------------------------------------------------------
# Live bundle discovery — external attacker perspective
# ---------------------------------------------------------------------------

import base64
import binascii
from html.parser import HTMLParser
from urllib.parse import urljoin


_LIVE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# WAF challenge markers that indicate the page is a bot-challenge, not real HTML.
_WAF_MARKERS: list[str] = [
    "cf-chl-bypass",         # Cloudflare challenge
    "cf_chl_opt",            # Cloudflare JS challenge
    "x-amzn-waf-action",     # AWS WAF response header key (checked in headers too)
    "__cf_chl_f_tk",         # Cloudflare turnstile
    "challenge-platform",    # Generic Cloudflare challenge script
    "aws-waf-token",         # AWS WAF managed rule group token
]

# Regex patterns for key material in JS bundles.
_RE_SUPABASE_URL = re.compile(r"https://[a-z0-9]+\.supabase\.co")
_RE_JWT = re.compile(r"eyJhbGci[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_RE_CLERK_PK = re.compile(r"pk_(test|live)_[A-Za-z0-9+/=$]+")
_RE_API_PREFIX = re.compile(r"(/\.netlify/functions/|/api/)")


class _ScriptSrcParser(HTMLParser):
    """Collect <script src="..."> values from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple]) -> None:
        if tag == "script":
            for name, value in attrs:
                if name == "src" and value:
                    self.srcs.append(value)


def _is_waf_challenge(status_code: int, headers: dict, body: str) -> bool:
    """Return True if the response looks like a WAF bot-challenge page."""
    # AWS WAF sets a custom header
    for header_key in headers:
        if "x-amzn-waf" in header_key.lower():
            return True
    # Cloudflare challenge pages use status 403 or 429 and embed specific JS
    body_lower = body[:4096].lower()
    for marker in _WAF_MARKERS:
        if marker in body_lower:
            return True
    return False


def _decode_clerk_fapi_host(publishable_key: str) -> str | None:
    """Derive the Clerk FAPI hostname from a publishable key.

    Clerk encodes the FAPI hostname as base64 in the suffix after
    ``pk_test_`` or ``pk_live_``.  The encoded value ends with a ``$``
    sentinel that must be stripped before decoding.

    Returns the hostname string, or None if decoding fails or the result
    is obviously malformed.
    """
    for prefix in ("pk_test_", "pk_live_"):
        if publishable_key.startswith(prefix):
            encoded = publishable_key[len(prefix):]
            break
    else:
        return None

    # Strip trailing dollar-sign sentinel used by Clerk
    encoded = encoded.rstrip("$")

    # Add padding if needed
    padding = 4 - (len(encoded) % 4)
    if padding != 4:
        encoded += "=" * padding

    try:
        decoded = base64.b64decode(encoded).decode("utf-8").strip().rstrip("$")
    except (binascii.Error, UnicodeDecodeError) as exc:
        print(
            f"[warn] discover_live: failed to base64-decode Clerk publishable key suffix: {exc}",
            file=sys.stderr,
        )
        return None

    # Validate: must contain at least one dot, no whitespace
    if "." not in decoded or any(c in decoded for c in (" ", "\t", "\n", "\r")):
        print(
            f"[warn] discover_live: decoded Clerk FAPI host looks malformed: {decoded!r}",
            file=sys.stderr,
        )
        return None

    return decoded


# ---------------------------------------------------------------------------
# Provider fingerprinting — regex patterns for bundle scanning
# ---------------------------------------------------------------------------

_RE_FIREBASE_API_KEY = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
_RE_SUPABASE_URL_BROAD = re.compile(r"https://([a-z0-9]{20})\.supabase\.co")
_RE_COGNITO_USER_POOL = re.compile(r"\b(us|eu|ap|ca|me|af|sa)-[a-z]+-\d_[A-Za-z0-9]{9}\b")
_RE_NEXTAUTH_CSRF = re.compile(r"/api/auth/csrf")
_RE_NEXTAUTH_CALLBACK = re.compile(r"/api/auth/callback/credentials")
_RE_PADDLE_CDN = re.compile(r"cdn\.paddle\.com")
_RE_PADDLE_SETUP = re.compile(r"paddle\.Setup", re.IGNORECASE)
_RE_LEMONSQUEEZY = re.compile(r"lemonsqueezy\.com|lmsqueezy\.com")
_RE_S3 = re.compile(r"s3\.amazonaws\.com|X-Amz-Algorithm")
_RE_R2 = re.compile(r"r2\.cloudflarestorage\.com")
_RE_SERVICE_ROLE_PREFIX = re.compile(r"sb_secret_")
_RE_SERVICE_ROLE_JWT = re.compile(r'"role"\s*:\s*"service_role"')
_RE_FIREBASE_PROJECT_ID = re.compile(
    r'["\']?projectId["\']?\s*[:=]\s*["\']([a-z0-9-]+)["\']'
)


def detect_providers(bundle_text: str) -> ProviderManifest:
    """Detect provider fingerprints from a single JS bundle's text.

    Applies regex patterns against ``bundle_text`` and returns a
    :class:`ProviderManifest` with all detected signals.  Priority rules:

    - Clerk PK found -> ``auth = "clerk"`` regardless of Firebase AIza presence.
    - Firebase AIza key sets ``database = "firestore"`` only when no Supabase
      URL is detected.
    - Ambiguity (both Firebase and Supabase signals) logs a warning.

    Args:
        bundle_text: Raw text content of a JS bundle.

    Returns:
        A :class:`ProviderManifest` populated with detected signals.
    """
    manifest = ProviderManifest()
    extracted: dict = {}
    signals: list[str] = []  # for ambiguity logging

    # --- Firebase ---
    firebase_key_match = _RE_FIREBASE_API_KEY.search(bundle_text)
    if firebase_key_match:
        extracted["firebase_api_key"] = firebase_key_match.group(0)
        signals.append("firebase_api_key")

    project_id_match = _RE_FIREBASE_PROJECT_ID.search(bundle_text)
    if project_id_match:
        extracted["firebase_project_id"] = project_id_match.group(1)

    # --- Supabase ---
    supabase_url_match = _RE_SUPABASE_URL_BROAD.search(bundle_text)
    if supabase_url_match:
        extracted["supabase_project_ref"] = supabase_url_match.group(1)
        signals.append("supabase_url")

    # --- Clerk ---
    clerk_pk_match = _RE_CLERK_PK.search(bundle_text)
    if clerk_pk_match:
        signals.append("clerk_pk")

    # --- Cognito ---
    cognito_match = _RE_COGNITO_USER_POOL.search(bundle_text)
    if cognito_match:
        extracted["cognito_user_pool_id"] = cognito_match.group(0)
        signals.append("cognito_user_pool")

    # --- NextAuth ---
    nextauth_match = bool(
        _RE_NEXTAUTH_CSRF.search(bundle_text)
        or _RE_NEXTAUTH_CALLBACK.search(bundle_text)
    )
    if nextauth_match:
        signals.append("nextauth")

    # --- Paddle ---
    if _RE_PADDLE_CDN.search(bundle_text) or _RE_PADDLE_SETUP.search(bundle_text):
        if "paddle" not in manifest.payments:
            manifest.payments.append("paddle")
        # Try to extract client token (Paddle.Setup({ token: "..." }))
        paddle_token_match = re.search(
            r'(?:token|client)\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            bundle_text,
        )
        if paddle_token_match:
            extracted["paddle_client_token"] = paddle_token_match.group(1)
        signals.append("paddle")

    # --- LemonSqueezy ---
    if _RE_LEMONSQUEEZY.search(bundle_text):
        if "lemonsqueezy" not in manifest.payments:
            manifest.payments.append("lemonsqueezy")
        signals.append("lemonsqueezy")

    # --- S3 ---
    s3_match = bool(_RE_S3.search(bundle_text))
    if s3_match:
        manifest.s3_compatible = True
        signals.append("s3")

    # --- R2 ---
    r2_match = bool(_RE_R2.search(bundle_text))
    if r2_match:
        manifest.s3_compatible = True
        signals.append("r2")

    # --- Service role key ---
    service_role_found = bool(
        _RE_SERVICE_ROLE_PREFIX.search(bundle_text)
        or _RE_SERVICE_ROLE_JWT.search(bundle_text)
    )
    extracted["service_role_key_found"] = service_role_found
    if service_role_found:
        signals.append("service_role_key")

    # --- Resolve auth/database/storage via the SAME precedence tables used
    # by _merge_manifests, so single-bundle detection and cross-bundle merge
    # cannot drift. (Previously detect_providers used ad-hoc
    # `if manifest.x is None` guards that, e.g., let an earlier NextAuth
    # signal block Firebase even though firebase outranks nextauth.) ---
    auth_candidates: list[str | None] = []
    if clerk_pk_match:
        auth_candidates.append("clerk")
    if firebase_key_match:
        auth_candidates.append("firebase")
    if nextauth_match:
        auth_candidates.append("nextauth")
    manifest.auth = _priority_winner(auth_candidates, _AUTH_PRIORITY)

    # Supabase URL => supabase DB; Firebase key => firestore. When both are
    # present, _DATABASE_PRIORITY resolves to supabase (matches the prior
    # "firestore only if no Supabase URL" rule and the ambiguity warning).
    database_candidates: list[str | None] = []
    if supabase_url_match:
        database_candidates.append("supabase")
    if firebase_key_match:
        database_candidates.append("firestore")
    manifest.database = _priority_winner(database_candidates, _DATABASE_PRIORITY)

    # Supabase storage, S3, R2, and Firebase Storage all resolved by the
    # shared table (supabase > firebase > s3 > r2). Adding "firebase"
    # unconditionally is safe: supabase outranks it, reproducing the old
    # "firebase storage only if no Supabase URL" behaviour.
    storage_candidates: list[str | None] = []
    if supabase_url_match:
        storage_candidates.append("supabase")
    if s3_match:
        storage_candidates.append("s3")
    if r2_match:
        storage_candidates.append("r2")
    if firebase_key_match:
        storage_candidates.append("firebase")
    manifest.storage = _priority_winner(storage_candidates, _STORAGE_PRIORITY)

    # Ambiguity warning: both Firebase and Supabase signals present
    if firebase_key_match and supabase_url_match:
        warnings.warn(
            f"Ambiguous provider signals detected: {signals}. "
            f"Firebase API key and Supabase URL both found — "
            f"database resolved to 'supabase' (Supabase takes priority).",
            stacklevel=2,
        )

    manifest.extracted_config = extracted
    return manifest


# ---------------------------------------------------------------------------
# Provider precedence tables — shared by detect_providers and _merge_manifests
# so the two functions cannot drift out of sync.
# ---------------------------------------------------------------------------

# Higher index = higher priority.  The winner is the value with the highest
# index found across all candidate values (None is always lowest priority).
_AUTH_PRIORITY: list[str] = ["nextauth", "firebase", "supabase-auth", "clerk"]
_DATABASE_PRIORITY: list[str] = ["firestore", "supabase"]
_STORAGE_PRIORITY: list[str] = ["r2", "s3", "firebase", "supabase"]


def _priority_winner(candidates: list[str | None], priority: list[str]) -> str | None:
    """Return the highest-priority non-None value from *candidates*.

    Priority is determined by position in *priority*: later entries beat
    earlier ones.  Values not present in *priority* are treated as having
    priority -1 (below all known values, but above None).

    Args:
        candidates: Values collected from multiple bundles (may include None).
        priority: Ordered list from lowest to highest priority.

    Returns:
        The winning value, or None if all candidates are None.
    """
    winner: str | None = None
    winner_rank: int = -2  # below "unknown non-None" rank of -1

    for val in candidates:
        if val is None:
            continue
        rank = priority.index(val) if val in priority else -1
        if rank > winner_rank:
            winner = val
            winner_rank = rank

    return winner


def _merge_manifests(manifests: list[ProviderManifest]) -> ProviderManifest:
    """Combine :class:`ProviderManifest` results from multiple JS bundles.

    Scalar fields (``auth``, ``database``, ``storage``) are resolved using
    the same provider precedence as :func:`detect_providers` — strongest
    signal wins regardless of bundle order:

    - auth:     clerk > supabase-auth > firebase > nextauth
    - database: supabase > firestore
    - storage:  supabase > firebase > s3 > r2

    List fields (``payments``) are unioned.  ``s3_compatible`` is True if
    any manifest set it.  ``extracted_config`` dicts are merged (first writer
    wins per key; ``service_role_key_found=True`` wins over False).

    Args:
        manifests: List of per-bundle manifests.

    Returns:
        A single merged :class:`ProviderManifest`.
    """
    if not manifests:
        return ProviderManifest()

    merged = ProviderManifest()
    seen_payments: set[str] = set()
    merged_config: dict = {}

    # Collect all candidate values for precedence resolution.
    auth_candidates: list[str | None] = [m.auth for m in manifests]
    database_candidates: list[str | None] = [m.database for m in manifests]
    storage_candidates: list[str | None] = [m.storage for m in manifests]

    merged.auth = _priority_winner(auth_candidates, _AUTH_PRIORITY)
    merged.database = _priority_winner(database_candidates, _DATABASE_PRIORITY)
    merged.storage = _priority_winner(storage_candidates, _STORAGE_PRIORITY)

    for m in manifests:
        if m.s3_compatible:
            merged.s3_compatible = True
        for p in m.payments:
            if p not in seen_payments:
                seen_payments.add(p)
                merged.payments.append(p)
        for k, v in m.extracted_config.items():
            if k not in merged_config:
                merged_config[k] = v
            elif k == "service_role_key_found" and v:
                # True wins over False
                merged_config[k] = True

    merged.extracted_config = merged_config
    return merged


def discover_live(target_url: str) -> dict:
    """Fetch a deployed site and extract public-facing config from client JS bundles.

    Simulates what an external attacker would discover by fetching the main HTML
    page and all referenced JS bundles, then scanning them for embedded config.

    Args:
        target_url: The root URL of the deployed site (e.g. ``https://example.com``).

    Returns:
        A dict with keys:
          - ``supabase_url``          — ``https://<project>.supabase.co`` or None
          - ``supabase_anon_key``     — JWT string or None
          - ``clerk_publishable_key`` — ``pk_(test|live)_…`` string or None
          - ``clerk_fapi_host``       — decoded FAPI hostname string or None
          - ``api_prefix``            — ``/.netlify/functions/`` or ``/api/`` or None
          - ``providers``             — :class:`ProviderManifest` with detected fingerprints

    Raises:
        RuntimeError: If the target URL is unreachable (connection error / timeout).
    """
    import httpx  # deferred import — not needed for static analysis path

    _empty: dict = {
        "supabase_url": None,
        "supabase_anon_key": None,
        "clerk_publishable_key": None,
        "clerk_fapi_host": None,
        "api_prefix": None,
        "providers": ProviderManifest(),
    }

    headers = {"User-Agent": _LIVE_USER_AGENT}

    # ------------------------------------------------------------------
    # Step 1: Fetch main HTML page
    # ------------------------------------------------------------------
    try:
        resp = httpx.get(
            target_url,
            headers=headers,
            follow_redirects=True,
            timeout=20.0,
        )
    except httpx.TransportError as exc:
        raise RuntimeError(
            f"discover_live: target unreachable — {target_url}: {exc}"
        ) from exc

    # WAF detection — warn and degrade gracefully
    if _is_waf_challenge(resp.status_code, dict(resp.headers), resp.text):
        print(
            "[warn] discover_live: WAF challenge page detected — discovery not possible. "
            "Run from a whitelisted IP or disable bot protection for the pentest window.",
            file=sys.stderr,
        )
        return dict(_empty)

    html_body = resp.text

    # ------------------------------------------------------------------
    # Step 2: Parse script tags
    # ------------------------------------------------------------------
    parser = _ScriptSrcParser()
    parser.feed(html_body)

    if not parser.srcs:
        print(
            "[warn] discover_live: no <script src=...> tags found in HTML — "
            "cannot extract bundle config.",
            file=sys.stderr,
        )
        return dict(_empty)

    # Resolve relative URLs against target base.
    # urljoin handles root-relative paths (/assets/...) correctly when the
    # base includes a trailing slash — it resolves against the origin.
    base = target_url.rstrip("/") + "/"
    script_urls: list[str] = []
    for src in parser.srcs:
        if not src or src.startswith("data:"):
            continue
        if src.startswith("http://") or src.startswith("https://"):
            script_urls.append(src)
        elif src.startswith("//"):
            script_urls.append("https:" + src)
        else:
            # Do NOT strip leading slash — urljoin resolves /foo against
            # the origin (https://host/foo), not the path (https://host/app/foo).
            script_urls.append(urljoin(base, src))

    # ------------------------------------------------------------------
    # Step 3: Fetch each JS bundle and scan for patterns
    # ------------------------------------------------------------------
    all_supabase_urls: list[str] = []
    all_jwts: list[str] = []
    all_clerk_pks: list[str] = []
    all_api_prefixes: list[str] = []
    provider_manifests: list[ProviderManifest] = []

    with httpx.Client(headers=headers, timeout=15.0, follow_redirects=True) as client:
        for url in script_urls:
            try:
                js_resp = client.get(url)
            except httpx.TransportError:
                continue
            if js_resp.status_code != 200:
                continue

            js_text = js_resp.text

            for m in _RE_SUPABASE_URL.finditer(js_text):
                v = m.group(0)
                if v not in all_supabase_urls:
                    all_supabase_urls.append(v)

            for m in _RE_JWT.finditer(js_text):
                v = m.group(0)
                if v not in all_jwts:
                    all_jwts.append(v)

            for m in _RE_CLERK_PK.finditer(js_text):
                v = m.group(0)
                if v not in all_clerk_pks:
                    all_clerk_pks.append(v)

            for m in _RE_API_PREFIX.finditer(js_text):
                v = m.group(1)
                if v not in all_api_prefixes:
                    all_api_prefixes.append(v)

            # Provider fingerprinting — accumulate per-bundle manifests
            try:
                provider_manifests.append(detect_providers(js_text))
            except Exception as exc:
                print(
                    f"[warn] discover_live: detect_providers failed for {url}: {exc}",
                    file=sys.stderr,
                )

    # Merge accumulated provider manifests into a single result
    providers = _merge_manifests(provider_manifests) if provider_manifests else ProviderManifest()

    # ------------------------------------------------------------------
    # Step 4: Select best match for each field
    # ------------------------------------------------------------------
    supabase_url = all_supabase_urls[0] if all_supabase_urls else None

    # Prefer JWTs found near supabase context; fall back to any anon-role JWT.
    supabase_anon_key: str | None = None
    for jwt in all_jwts:
        try:
            # Decode payload (middle segment) without verification
            payload_b64 = jwt.split(".")[1]
            padding = 4 - (len(payload_b64) % 4)
            if padding != 4:
                payload_b64 += "=" * padding
            payload_json = base64.b64decode(payload_b64).decode("utf-8", errors="replace")
            if '"anon"' in payload_json or "'anon'" in payload_json or "anon" in payload_json:
                supabase_anon_key = jwt
                break
        except Exception:
            continue
    # Fall back: any JWT that looks like it could be an anon key
    if supabase_anon_key is None and all_jwts:
        supabase_anon_key = all_jwts[0]

    clerk_publishable_key = all_clerk_pks[0] if all_clerk_pks else None

    # Derive FAPI host from publishable key
    clerk_fapi_host: str | None = None
    if clerk_publishable_key:
        clerk_fapi_host = _decode_clerk_fapi_host(clerk_publishable_key)

    api_prefix = all_api_prefixes[0] if all_api_prefixes else None

    # ------------------------------------------------------------------
    # Step 5: Report to stderr for transparency
    # ------------------------------------------------------------------
    discovered = {
        "supabase_url": supabase_url,
        "supabase_anon_key": supabase_anon_key,
        "clerk_publishable_key": clerk_publishable_key,
        "clerk_fapi_host": clerk_fapi_host,
        "api_prefix": api_prefix,
        "providers": providers,
    }

    found = [k for k, v in discovered.items() if v is not None]
    missing = [k for k, v in discovered.items() if v is None]

    if found:
        print(f"[discover_live] found: {', '.join(found)}", file=sys.stderr)
    if missing:
        print(f"[discover_live] not found: {', '.join(missing)}", file=sys.stderr)

    return discovered
