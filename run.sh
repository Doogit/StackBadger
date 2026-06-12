#!/usr/bin/env bash
# run.sh — Pentest harness orchestrator
# Usage: ./run.sh <target_url> [--full [--yes]] [--branch] [--profile <path>] [--skip-zap]
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers (defined early so they're available in arg-parsing errors)
# ---------------------------------------------------------------------------
fail() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "INFO:  $*"; }

# Preflight/gate failures exit 10 — deliberately OUTSIDE reports/aggregate.py's
# finding-severity exit contract (0/1/2/3) so an agent or CI can never misread
# "environment not ready / run refused" as "scan ran and found things".
fail_preflight() { echo "ERROR: $*" >&2; exit 10; }

# Normalize a URL or host for gate comparison: strip scheme, fragment, query,
# path, userinfo, and port; lowercase. Returns the bare host an HTTP client
# would actually connect to.
#
# Order matters for gate integrity: the fragment and query are stripped FIRST,
# because an HTTP client drops them before host resolution. Stripping userinfo
# (@) before the fragment would let a crafted URL like
# 'https://good.com#@evil.com' normalize to 'evil.com' while the client
# connects to 'good.com' — a target-confusion that defeats the gate.
# Bracketed IPv6 literals ([::1]) are preserved whole (the :port strip only
# applies to a port that follows the closing bracket).
_normalize_host() {
  local h="$1"
  h="${h#*://}"      # strip scheme
  h="${h%%#*}"       # strip fragment (before userinfo — see above)
  h="${h%%\?*}"      # strip query
  h="${h%%/*}"       # strip path
  h="${h##*@}"       # strip userinfo
  if [[ "$h" == \[*\]* ]]; then
    # Bracketed IPv6 literal: keep "[....]", drop any trailing :port.
    h="${h%%\]*}]"
  else
    h="${h%%:*}"     # strip :port
  fi
  printf '%s' "$h" | tr '[:upper:]' '[:lower:]'
}

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
TARGET_URL=""
PROFILE=""
SKIP_ZAP=false
FULL_MODE=false
AUTO_YES=false
USE_BRANCH=false

# Parse positional + named args. First bare argument is the target URL unless
# it looks like a flag.
_positional_done=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-zap)
      SKIP_ZAP=true
      shift
      ;;
    --profile)
      [[ $# -lt 2 ]] && fail "--profile requires a path argument."
      PROFILE="$2"
      shift 2
      ;;
    --full)
      FULL_MODE=true
      shift
      ;;
    --yes)
      AUTO_YES=true
      shift
      ;;
    --read-only)
      # Explicit alias for default mode — no-op.
      shift
      ;;
    --branch)
      USE_BRANCH=true
      shift
      ;;
    --*)
      fail "Unknown flag: $1"
      ;;
    *)
      if [[ "$_positional_done" == "false" ]]; then
        TARGET_URL="$1"
        _positional_done=true
      else
        fail "Unexpected positional argument: $1"
      fi
      shift
      ;;
  esac
done

if [[ -z "$TARGET_URL" ]]; then
  echo "Usage: $0 <target_url> [--full [--yes]] [--branch] [--profile <path>] [--skip-zap]" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Backward-compat: first arg is a YAML path (old interface)
# ---------------------------------------------------------------------------
if [[ "$TARGET_URL" == *.yaml || "$TARGET_URL" == *.yml ]]; then
  warn "DEPRECATED: Pass a URL as the first argument, not a YAML path. Use --profile for the YAML."
  _OLD_YAML="$TARGET_URL"
  TARGET_URL=""
  # Attempt to extract target.base_url from the YAML file.
  if command -v python3 &>/dev/null || command -v python &>/dev/null; then
    _PY_COMPAT="${PYTHON_BIN:-python3}"
    TARGET_URL=$("$_PY_COMPAT" - "$_OLD_YAML" <<'PYEOF' 2>/dev/null || true
import sys, yaml
with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)
url = data.get("target", {}).get("base_url", "")
if url:
    print(url)
PYEOF
)
  fi
  if [[ -z "$TARGET_URL" ]]; then
    fail "Legacy YAML path provided but target.base_url could not be extracted from '$_OLD_YAML'. Pass a URL as the first argument."
  fi
  # If the caller didn't explicitly pass --profile, default it to the old YAML.
  if [[ -z "$PROFILE" ]]; then
    PROFILE="$_OLD_YAML"
  fi
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Pre-flight: locate a Python 3.11+ interpreter
# ---------------------------------------------------------------------------
# (doctor.py re-verifies the version as its first check; this loop exists to
# find the interpreter that runs doctor.py at all. A pre-set PYTHON_BIN env
# var takes precedence — used by the shell-level test harness and by callers
# pinning a specific venv interpreter.)
info "Checking Python version..."
_PY_CANDIDATES=()
if [[ -n "${PYTHON_BIN:-}" ]]; then
  _PY_CANDIDATES+=("$PYTHON_BIN")
fi
_PY_CANDIDATES+=(python3 python)
PYTHON_BIN=""
for candidate in "${_PY_CANDIDATES[@]}"; do
  if command -v "$candidate" &>/dev/null; then
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      PYTHON_BIN="$candidate"
      break
    fi
  fi
done

if [[ -z "$PYTHON_BIN" ]]; then
  fail "Python 3.11+ is required but was not found on PATH."
fi
info "Python OK: $($PYTHON_BIN --version)"

# ---------------------------------------------------------------------------
# Source .env early (before any env var checks)
# ---------------------------------------------------------------------------
if [[ -f ".env" ]]; then
  info "Loading .env..."
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# ---------------------------------------------------------------------------
# Cleanup trap (installed once)
# ---------------------------------------------------------------------------
# Removes the generated runtime profile and, if a disposable Supabase branch DB
# was created, deletes it. Installed here — before the branch block — so a
# branch-readiness timeout and an early failure are both covered by a single
# handler (the two cleanups don't clobber each other's trap).
_RUNTIME_PROFILE=""
_ZAP_RUNTIME_PLAN=""   # generated ZAP plan with profile endpoints injected (see ZAP block)
_cleanup_on_exit() {
  # Run the body at most once: the trap is registered for EXIT INT TERM, so a
  # Ctrl-C fires the handler (INT) and then again on shell exit (EXIT). Guard so
  # branch deletion isn't attempted twice.
  [[ -n "${_CLEANUP_DONE:-}" ]] && return 0
  _CLEANUP_DONE=1

  if [[ -n "${_RUNTIME_PROFILE:-}" ]]; then
    rm -f "$_RUNTIME_PROFILE"
  fi
  if [[ -n "${_ZAP_RUNTIME_PLAN:-}" ]]; then
    rm -f "$_ZAP_RUNTIME_PLAN"
  fi
  if [[ -n "${_BRANCH_ID:-}" && -n "${_PROJECT_REF:-}" ]]; then
    if [[ -z "${SUPABASE_ACCESS_TOKEN:-}" ]]; then
      # Without the token, delete_branch would KeyError on os.environ and the
      # failure would be swallowed, silently orphaning a branch DB. Surface an
      # explicit, actionable warning instead.
      warn "SUPABASE_ACCESS_TOKEN is unset at cleanup — cannot auto-delete branch database. Manually delete branch $_BRANCH_ID (project $_PROJECT_REF)."
    else
      info "Cleaning up branch database $_BRANCH_ID..."
      # Pass branch id and project ref as argv (not string-interpolated into the
      # source) so a value containing quotes/newlines can't SyntaxError-and-swallow.
      # stderr is intentionally NOT redirected: delete_branch prints its outcome
      # (success or the HTTP error body) there, and raises on a non-2xx/404
      # response so the `|| warn` fallback fires instead of orphaning the branch.
      "$PYTHON_BIN" -c "
import sys, os
sys.path.insert(0, '.')
from branch_db import delete_branch
delete_branch(sys.argv[1], sys.argv[2], os.environ['SUPABASE_ACCESS_TOKEN'])
" "$_BRANCH_ID" "$_PROJECT_REF" || warn "Branch cleanup failed — manually delete branch $_BRANCH_ID (project $_PROJECT_REF)."
    fi
  fi
}
trap _cleanup_on_exit EXIT INT TERM

# ---------------------------------------------------------------------------
# Target-confirmation + authorization gates (EVERY remote run, read-only too)
# ---------------------------------------------------------------------------
# Read-only runs still fire enumeration/injection/CORS/ZAP traffic at the
# target, so BOTH gates apply to any non-localhost host, in every mode:
#
#   CONFIRM_TARGET     — "this is the right host" (typo/wrong-env guard)
#   CONFIRM_AUTHORIZED — "a human affirmed authorization to test this host"
#
# Each must EXACT-match the host of the EFFECTIVE TARGET — the URL this run
# will actually scan (scheme/case/port-insensitive, NO subdomain cross-match:
# api.example.com != example.com). The effective target is the URL you pass to
# run.sh, OR the TARGET_BASE_URL env override when that is set (TARGET_BASE_URL
# wins over the CLI arg, same as the scan target below). Confirming and
# scanning are the SAME resolved value (EFFECTIVE_TARGET), so the gate can
# never confirm one host and scan another.
#
# It is NOT a post-redirect host: the gate runs before any network contact (so
# it cannot, and must not, resolve a redirect against an unconfirmed/
# unauthorized host), and discovery pins target.base_url to this same value
# anyway. So to test the www host of an apex that redirects, pass/override the
# www URL and confirm www.example.com. The values are meant to be set by the
# HUMAN out-of-band — an agent following LAUNCH.md must not set
# CONFIRM_AUTHORIZED for itself. --yes (AUTO_YES) does NOT bypass either gate.
# localhost / 127.0.0.1 / [::1] are exempt. Placed before the branch-DB
# lifecycle so a refused run performs zero remote side effects.
#
# SCOPE: the gate governs the application host. Discovery harvests the target's
# Supabase project URL from its JS bundle, and PostgREST/IDOR/RLS probes hit
# that <ref>.supabase.co backend — which is implicitly in scope as the target's
# own backend. Confirm you are authorized to test the whole deployment, not
# just the front-end host, before proceeding.
#
# EFFECTIVE_TARGET is resolved ONCE here and reused for reachability/discovery
# below, so the gated host and the scanned host are guaranteed identical.
EFFECTIVE_TARGET="${TARGET_BASE_URL:-$TARGET_URL}"
_TARGET_HOST="$(_normalize_host "$EFFECTIVE_TARGET")"
if [[ "$_TARGET_HOST" != "localhost" && "$_TARGET_HOST" != "127.0.0.1" && "$_TARGET_HOST" != "[::1]" ]]; then
  if [[ -z "${CONFIRM_TARGET:-}" || "$(_normalize_host "${CONFIRM_TARGET:-}")" != "$_TARGET_HOST" ]]; then
    fail_preflight "CONFIRM_TARGET gate refused: this run would scan '$_TARGET_HOST'. To confirm the target, run:  export CONFIRM_TARGET=$_TARGET_HOST  (exact host match required; --yes does not bypass this gate)"
  fi
  if [[ -z "${CONFIRM_AUTHORIZED:-}" || "$(_normalize_host "${CONFIRM_AUTHORIZED:-}")" != "$_TARGET_HOST" ]]; then
    fail_preflight "CONFIRM_AUTHORIZED gate refused: authorization to test '$_TARGET_HOST' has not been affirmed. The site OWNER (a human, not the agent) must run:  export CONFIRM_AUTHORIZED=$_TARGET_HOST  — only do this for systems you own or are explicitly authorized, in writing, to test."
  fi
  info "Target + authorization gates passed for host: $_TARGET_HOST"
fi

# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------
if [[ "$USE_BRANCH" == "true" ]]; then
  # --branch implies --full (branch exists specifically for destructive testing)
  FULL_MODE=true
fi

if [[ "$FULL_MODE" == "true" ]]; then
  export PENTEST_MODE="full"
  echo ""
  warn "========================================================="
  warn " FULL MODE — write probes enabled"
  warn "========================================================="
  warn "This mode sends INSERT, UPDATE, DELETE, and file upload"
  warn "requests to the target. If security controls are"
  warn "misconfigured, data could be created or modified."
  warn ""
  warn "Recommended: use --branch to auto-create a disposable"
  warn "Supabase branch database for Supabase-level probes."
  warn ""
  warn "NOTE: --branch redirects Supabase probes (PostgREST, RPC,"
  warn "Storage) to the branch database but Netlify function probes"
  warn "(uploads, payment, checkout) still hit the target deployment."
  warn "========================================================="
  echo ""
  if [[ "$AUTO_YES" != "true" ]]; then
    read -r -p "Continue with full mode? [y/N] " _confirm
    if [[ "$_confirm" != "y" && "$_confirm" != "Y" ]]; then
      info "Aborted. Run without --full for read-only mode."
      exit 0
    fi
  fi
else
  export PENTEST_MODE="read-only"
  info "Running in read-only mode (no write probes). Use --full for complete suite."
fi

# ---------------------------------------------------------------------------
# Branch DB lifecycle (if --branch)
# ---------------------------------------------------------------------------
if [[ "$USE_BRANCH" == "true" ]]; then
  if [[ -z "${SUPABASE_ACCESS_TOKEN:-}" ]]; then
    fail "--branch requires SUPABASE_ACCESS_TOKEN env var (Supabase Management API personal access token)."
  fi

  info "Creating disposable Supabase branch database..."

  # Determine project ref from SUPABASE_PROJECT_URL or profile.
  _PROJECT_REF="${SUPABASE_PROJECT_REF:-}"
  if [[ -z "$_PROJECT_REF" && -n "${SUPABASE_PROJECT_URL:-}" ]]; then
    # Extract ref from URL like https://<ref>.supabase.co
    _PROJECT_REF=$(echo "$SUPABASE_PROJECT_URL" | sed -E 's|https://([^.]+)\.supabase\.co.*|\1|')
  fi
  if [[ -z "$_PROJECT_REF" ]]; then
    fail "Cannot determine Supabase project ref. Set SUPABASE_PROJECT_REF or SUPABASE_PROJECT_URL."
  fi

  # Step 1: Create the branch (returns immediately with branch metadata).
  # Pass the project ref as argv (not string-interpolated into the source) so a
  # value containing quotes/newlines can't SyntaxError-and-swallow — mirroring
  # the _cleanup_on_exit trap.
  BRANCH_RESULT=$("$PYTHON_BIN" -c "
import sys, os, json
sys.path.insert(0, '.')
from branch_db import create_branch
ref = sys.argv[1]
token = os.environ['SUPABASE_ACCESS_TOKEN']
branch_id, branch_url, branch_key = create_branch(ref, token)
print(json.dumps({'id': branch_id, 'url': branch_url, 'key': branch_key}))
" "$_PROJECT_REF") || fail "Branch creation failed. Check stderr output above."

  _BRANCH_ID=$("$PYTHON_BIN" -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "$BRANCH_RESULT")
  _BRANCH_URL=$("$PYTHON_BIN" -c "import json,sys; print(json.loads(sys.argv[1])['url'])" "$BRANCH_RESULT")
  _BRANCH_KEY=$("$PYTHON_BIN" -c "import json,sys; print(json.loads(sys.argv[1])['key'])" "$BRANCH_RESULT")

  info "Branch created: $_BRANCH_ID"

  # _BRANCH_ID and _PROJECT_REF are now set, so the _cleanup_on_exit trap
  # installed earlier will delete the branch on exit — including if the
  # wait_for_ready below times out and calls fail().

  # Step 2: Wait for branch to become ready. Branch id and project ref are passed
  # as argv (not string-interpolated) so they can't SyntaxError-and-swallow —
  # mirroring the _cleanup_on_exit trap.
  "$PYTHON_BIN" -c "
import sys, os
sys.path.insert(0, '.')
from branch_db import wait_for_ready
wait_for_ready(sys.argv[1], sys.argv[2], os.environ['SUPABASE_ACCESS_TOKEN'])
" "$_BRANCH_ID" "$_PROJECT_REF" || fail "Branch readiness timed out. Cleanup trap will delete the branch."

  export SUPABASE_PROJECT_URL="$_BRANCH_URL"
  export SUPABASE_ANON_KEY="$_BRANCH_KEY"
  info "Branch URL: $_BRANCH_URL"
fi

# ---------------------------------------------------------------------------
# Resolve PROFILE to absolute path if provided
# ---------------------------------------------------------------------------
if [[ -n "$PROFILE" ]]; then
  if [[ ! -f "$PROFILE" ]]; then
    fail "Profile not found: $PROFILE"
  fi
  PROFILE="$(cd "$(dirname "$PROFILE")" && pwd)/$(basename "$PROFILE")"
  export PENTEST_PROFILE_PATH="$PROFILE"
fi

# ---------------------------------------------------------------------------
# Export the effective target URL (used by reachability + discovery)
# ---------------------------------------------------------------------------
# EFFECTIVE_TARGET was resolved ONCE at the confirmation gate above (TARGET_BASE_URL
# override, else the CLI arg) and is reused verbatim here, so the host that was
# gated is provably the host that gets scanned.
export PENTEST_TARGET_URL="$EFFECTIVE_TARGET"

# ---------------------------------------------------------------------------
# Pre-flight: delegate to doctor.py
# ---------------------------------------------------------------------------
# doctor.py owns the preflight checks (Python version, all four PENTEST_USER_*
# credentials, target reachability, User A login, User B login), printing one
# [PASS]/[FAIL] line per check and halting at the first failure. Run BEFORE
# discovery so a broken environment fails with an actionable message rather
# than a misleading "Discovery failed". Any doctor failure (it exits 10-19)
# maps to the single fixed preflight exit (10), never aggregate's 0/1/2/3.
info "Running preflight checks (doctor.py)..."
_DOCTOR_ARGS=("$EFFECTIVE_TARGET")
if [[ -n "$PROFILE" ]]; then
  _DOCTOR_ARGS+=(--profile "$PROFILE")
fi
if ! "$PYTHON_BIN" doctor.py "${_DOCTOR_ARGS[@]}"; then
  fail_preflight "Preflight failed — fix the [FAIL] check above and re-run. (Reproduce with: python doctor.py $EFFECTIVE_TARGET)"
fi
info "Preflight passed."

# ---------------------------------------------------------------------------
# Discovery + profile assembly (ONE live crawl, frozen for the whole run)
# ---------------------------------------------------------------------------
# assemble_profile() performs the single live discovery crawl for this run. We
# freeze the fully-assembled profile — discovered secrets (firebase.api_key,
# supabase.anon_key, clerk.frontend_api) merged in — to a temp YAML so sign-in,
# the ZAP credential refresh, and pytest all consume ONE artifact via
# load_profile(): no re-crawl, no mid-run stack drift.
RUNTIME_PROFILE="$(mktemp "${TMPDIR:-/tmp}/pentest-runtime-profile-XXXXXX.yaml")"
_RUNTIME_PROFILE="$RUNTIME_PROFILE"   # picked up by the _cleanup_on_exit trap
export PENTEST_RUNTIME_PROFILE_PATH="$RUNTIME_PROFILE"
info "Discovering public config from $EFFECTIVE_TARGET (single live crawl)..."
# Capture only stdout (JSON); stderr goes to the terminal for visibility.
DISCOVER_RESULT=$("$PYTHON_BIN" -c "
import sys, os, json, yaml
sys.path.insert(0, '.')
from profile_assembler import assemble_profile

target_url = os.environ['PENTEST_TARGET_URL']
profile_path = os.environ.get('PENTEST_PROFILE_PATH') or None
profile = assemble_profile(target_url, yaml_path=profile_path)

# Freeze the assembled profile so downstream steps never re-discover.
with open(os.environ['PENTEST_RUNTIME_PROFILE_PATH'], 'w') as f:
    yaml.dump(profile.raw(), f, default_flow_style=False)

result = {
    'supabase_url': (profile.supabase and profile.supabase.project_url) or '',
    'anon_key':     (profile.supabase and profile.supabase.anon_key) or '',
    'fapi_host':    (profile.clerk and profile.clerk.frontend_api) or '',
    'base_url':     (profile.target and profile.target.base_url) or '',
}
print(json.dumps(result))
") || fail "Discovery / profile assembly failed. Check stderr output above."

# Parse discovered values into shell variables.
DISCOVERED_SUPABASE_URL=$("$PYTHON_BIN" -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('supabase_url',''))" "$DISCOVER_RESULT" 2>/dev/null || true)
DISCOVERED_ANON_KEY=$("$PYTHON_BIN" -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('anon_key',''))" "$DISCOVER_RESULT" 2>/dev/null || true)
DISCOVERED_FAPI_HOST=$("$PYTHON_BIN" -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('fapi_host',''))" "$DISCOVER_RESULT" 2>/dev/null || true)
DISCOVERED_BASE_URL=$("$PYTHON_BIN" -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('base_url',''))" "$DISCOVER_RESULT" 2>/dev/null || true)

# Export discovered values — env var already set takes precedence.
export TARGET_BASE_URL="${TARGET_BASE_URL:-${DISCOVERED_BASE_URL:-$TARGET_URL}}"
export SUPABASE_PROJECT_URL="${SUPABASE_PROJECT_URL:-$DISCOVERED_SUPABASE_URL}"
export SUPABASE_ANON_KEY="${SUPABASE_ANON_KEY:-$DISCOVERED_ANON_KEY}"
export CLERK_FAPI_HOST="${CLERK_FAPI_HOST:-$DISCOVERED_FAPI_HOST}"

# Print discovered config summary (redacting JWT-shaped values).
info "Discovered config:"
info "  base_url:       $TARGET_BASE_URL"
info "  supabase_url:   ${SUPABASE_PROJECT_URL:-<not discovered>}"
info "  anon_key:       $( [[ -n "$SUPABASE_ANON_KEY" ]] && echo "<set>" || echo "<not discovered>" )"
info "  fapi_host:      ${CLERK_FAPI_HOST:-<not discovered>}"

if [[ -z "$SUPABASE_PROJECT_URL" ]]; then
  warn "supabase.project_url not discovered — Supabase-dependent tests will be skipped."
fi
if [[ -z "$SUPABASE_ANON_KEY" ]]; then
  warn "supabase.anon_key not discovered — Supabase-dependent tests will be skipped."
fi

# ---------------------------------------------------------------------------
# Activate the frozen profile for the rest of the run
# ---------------------------------------------------------------------------
# Resolve to an absolute path (Docker volume mounts and pytest need it) and make
# it the active profile. Sign-in, the ZAP refresh, and pytest all read THIS file.
PROFILE="$(cd "$(dirname "$RUNTIME_PROFILE")" && pwd)/$(basename "$RUNTIME_PROFILE")"
export PENTEST_PROFILE="$PROFILE"
# Tell conftest to load this pre-assembled profile directly instead of running
# its own discovery, so pytest stays on the exact same stack (see conftest.py).
export PENTEST_PROFILE_FROZEN=1
info "Frozen runtime profile: $PROFILE"

# ---------------------------------------------------------------------------
# Sign in test accounts via the profile-driven auth adapter
# ---------------------------------------------------------------------------
# The auth adapter is selected by stack.auth (clerk / firebase / supabase-auth /
# nextauth) via auth.create_adapter, mirroring tests/conftest.py. Bearer adapters
# yield a JWT (used by ZAP); cookie adapters (NextAuth) yield a session cookie.
# Loads the frozen profile (no re-discovery) — the discovered provider config
# (e.g. firebase.api_key) is baked in, so create_adapter works offline.
info "Signing in test accounts via the profile-driven auth adapter..."
SIGNIN_RESULT=$("$PYTHON_BIN" -c "
import sys, os
sys.path.insert(0, '.')
from profile import load_profile
from auth import create_adapter

profile = load_profile(os.environ['PENTEST_PROFILE'])
provider = (profile.stack and profile.stack.auth) or 'unknown'
print(f'[sign-in] auth provider: {provider}', file=sys.stderr)

adapter = create_adapter(profile)
if adapter.auth_type == 'cookie':
    headers = adapter.get_headers('user_a')
    cookie = headers.get('Cookie', '')
    if not cookie:
        raise SystemExit('cookie adapter returned no session cookie')
    sys.stdout.write('COOKIE\t' + cookie)
else:
    sys.stdout.write('BEARER\t' + adapter.get_token('user_a'))
") || fail "Auth sign-in failed. Check stderr output above."

# Split on the first tab: '<TYPE>\t<value>'.
SIGNIN_AUTH_TYPE="${SIGNIN_RESULT%%$'\t'*}"
SIGNIN_AUTH_VALUE="${SIGNIN_RESULT#*$'\t'}"
case "$SIGNIN_AUTH_TYPE" in
  BEARER)
    export PENTEST_USER_A_JWT="$SIGNIN_AUTH_VALUE"
    info "Sign-in OK — Bearer JWT acquired for user_a."
    ;;
  COOKIE)
    # Fail-fast credential check for cookie auth: a failed sign-in aborts the
    # run here instead of letting every authenticated test skip/fail. The cookie
    # is exported as the fallback seed for the cookie-based ZAP scan (the ZAP
    # refresh block re-fetches a fresh cookie and falls back to this one);
    # pytest re-authenticates independently via conftest's adapter.
    export PENTEST_USER_A_COOKIE="$SIGNIN_AUTH_VALUE"
    info "Sign-in OK — session cookie acquired for user_a (cookie-based auth)."
    ;;
  *)
    fail "Sign-in returned unrecognized auth type: '$SIGNIN_AUTH_TYPE'."
    ;;
esac

# user_b sign-in check: cross-user (IDOR) probes silently skip without a
# working user_b, which reads as "passed". Verify it can authenticate NOW,
# against the same frozen profile, so a dead User B aborts the run instead.
# (No token is exported — ZAP scans as user_a; pytest re-authenticates user_b
# via conftest's adapter.)
info "Verifying user_b sign-in..."
"$PYTHON_BIN" -c "
import sys, os
sys.path.insert(0, '.')
from profile import load_profile
from auth import create_adapter
profile = load_profile(os.environ['PENTEST_PROFILE'])
adapter = create_adapter(profile)
headers = adapter.get_headers('user_b')
if not headers:
    raise SystemExit('adapter returned no auth headers for user_b')
" || fail "user_b sign-in failed — cross-user (IDOR) probes need a working User B. Check PENTEST_USER_B_EMAIL / PENTEST_USER_B_PASSWORD."
info "Sign-in OK — user_b authenticated."

# ---------------------------------------------------------------------------
# Auth verify_path fast-fail (optional, profile-driven)
# ---------------------------------------------------------------------------
# When the profile declares auth.verify_path — an API-LAYER route that returns
# 401/403 to unauthenticated callers (PostgREST endpoint / auth-checked
# function), NOT a CDN-cached page that 200s anonymously — request it with
# EACH account's credential now. A 401/403 here means the provider issued a
# token the target API rejects: a broken account or, more often, the WRONG
# stack.auth adapter. Failing now beats discovering it as 50 skipped tests
# later. Unset -> warn + skip (black-box safe). Exits 10 (preflight), never
# aggregate's 0/1/2/3.
info "Checking auth.verify_path (if set)..."
# The status-interpretation logic (2xx / 401-403 / 3xx-no-follow /
# inconclusive) lives in doctor._check_verify_path — ONE source of truth for
# both the doctor preflight and this pre-scan check; only the per-account
# loop and adapter plumbing live here.
"$PYTHON_BIN" -c "
import sys, os
sys.path.insert(0, '.')
from profile import load_profile
from auth import create_adapter
from doctor import _check_verify_path

profile = load_profile(os.environ['PENTEST_PROFILE'])
verify_path = (profile.auth and profile.auth.verify_path) or ''
if not verify_path:
    print('[verify-path] auth.verify_path not set — skipping the pre-scan auth verification (black-box mode).', file=sys.stderr)
    raise SystemExit(0)
base_url = os.environ.get('TARGET_BASE_URL') or (profile.target and profile.target.base_url) or ''
adapter = create_adapter(profile)
failures = []
try:
    for account, who in (('user_a', 'User A'), ('user_b', 'User B')):
        try:
            headers = adapter.get_headers(account)
        except Exception as exc:
            failures.append(f'{account}: sign-in failed while fetching headers for the verify_path check: {exc}')
            continue
        ok, detail, fix = _check_verify_path(base_url, verify_path, headers, who)
        if ok:
            print(f'[verify-path] {account}: {detail}', file=sys.stderr)
        else:
            failures.append(f'{account}: {detail}. Fix: {fix}')
finally:
    if hasattr(adapter, 'close'):
        adapter.close()
for f in failures:
    print('[verify-path] FAIL ' + f, file=sys.stderr)
raise SystemExit(1 if failures else 0)
" || fail_preflight "auth.verify_path check failed — see the [verify-path] FAIL lines above."

# ---------------------------------------------------------------------------
# Pre-flight: Key endpoint spot-check
# ---------------------------------------------------------------------------
info "Spot-checking key endpoints..."
_SPOT_CHECK_INPUT="${PROFILE:-}"

if [[ -n "$_SPOT_CHECK_INPUT" ]]; then
  API_PREFIX=$("$PYTHON_BIN" - "$_SPOT_CHECK_INPUT" <<'PYEOF' 2>/dev/null || true
import sys, yaml
with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)
prefix = data.get("target", {}).get("api_prefix", "")
print(prefix)
PYEOF
)

  SPOT_CHECK_PATHS=$("$PYTHON_BIN" - "$_SPOT_CHECK_INPUT" <<'PYEOF' 2>/dev/null || true
import sys, yaml
with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)
eps = data.get("endpoints", {})
paths = []
for cat in ("authenticated", "anonymous"):
    items = eps.get(cat, [])
    if items:
        paths.append(items[0].get("path", ""))
for p in paths[:2]:
    if p:
        print(p)
PYEOF
)

  if [[ -z "$SPOT_CHECK_PATHS" ]]; then
    warn "No endpoints found in profile for spot-check — skipping."
  else
    while IFS= read -r path; do
      [[ -z "$path" ]] && continue
      url="${TARGET_BASE_URL}${API_PREFIX}${path}"
      status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X OPTIONS "$url" 2>/dev/null || echo "000")
      if [[ "$status" == "404" ]]; then
        warn "Endpoint returned 404: $url"
      else
        info "Endpoint check: $url -> HTTP $status"
      fi
    done <<< "$SPOT_CHECK_PATHS"
  fi
else
  info "No profile provided — skipping endpoint spot-check."
fi

# ---------------------------------------------------------------------------
# Docker / ZAP availability
# ---------------------------------------------------------------------------
ZAP_AVAILABLE=false
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"

if [[ "$SKIP_ZAP" == "true" ]]; then
  info "ZAP skipped via --skip-zap flag."
elif command -v docker &>/dev/null; then
  if docker image inspect "$ZAP_IMAGE" &>/dev/null 2>&1; then
    ZAP_AVAILABLE=true
    info "Docker and ZAP image found — ZAP scan will run."
  else
    warn "Docker is available but ZAP image '$ZAP_IMAGE' is not present locally."
    warn "Run: docker pull $ZAP_IMAGE"
    warn "Continuing without ZAP scan."
  fi
else
  warn "Docker not found on PATH — ZAP scan will be skipped."
  warn "Install Docker to enable ZAP DAST scanning."
fi

# ---------------------------------------------------------------------------
# Ensure output directory exists
# ---------------------------------------------------------------------------
mkdir -p reports/output

# ---------------------------------------------------------------------------
# Timestamp for report filenames (avoids overwriting previous runs)
# ---------------------------------------------------------------------------
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
export PENTEST_RUN_TS="$RUN_TS"
info "Run timestamp: $RUN_TS"

# ---------------------------------------------------------------------------
# Run pytest
# ---------------------------------------------------------------------------
info "Running pytest..."
set +e
"$PYTHON_BIN" -m pytest tests/ \
  --profile "$PROFILE" \
  --json-report \
  --json-report-file="reports/pytest-report-${RUN_TS}.json" \
  -v
PYTEST_EXIT=$?
set -e

if [[ $PYTEST_EXIT -ne 0 && $PYTEST_EXIT -ne 1 ]]; then
  warn "pytest exited with code $PYTEST_EXIT (may indicate collection or infrastructure error)."
fi
info "pytest finished with exit code $PYTEST_EXIT."

# ---------------------------------------------------------------------------
# Refresh the auth credential for ZAP via the auth adapter
# ---------------------------------------------------------------------------
# The ZAP automation plan seeds auth through the replacer + requestor headers:
# a Bearer JWT (${JWT_TOKEN}) for bearer stacks, or a session Cookie
# (${SESSION_COOKIE}) for cookie stacks (NextAuth / Auth.js). Exactly one is
# populated; the other is passed empty so its replacer rule is a no-op.
#
# Refresh immediately before the scan: bearer JWTs can expire in ~60s (Clerk).
# NextAuth session cookies are far longer-lived, so a single pre-scan fetch is
# sufficient — we re-fetch on the same code path for consistency.
#
# NOTE: loads the frozen runtime profile (PENTEST_PROFILE) — no re-discovery —
# so the auth_type gating ZAP here is the same stack pytest ran against. The
# discovered provider config (e.g. firebase.api_key) is baked into the frozen
# profile, so create_adapter resolves the credential offline.
# Do NOT suppress stderr — a traceback must be visible if the refresh fails.
if [[ "$ZAP_AVAILABLE" == "true" ]]; then
  if [[ "$SIGNIN_AUTH_TYPE" == "COOKIE" ]]; then
    info "Refreshing session cookie for ZAP scan..."
    FRESH_COOKIE=$("$PYTHON_BIN" -c "
import sys, os
sys.path.insert(0, '.')
from profile import load_profile
from auth import create_adapter
profile = load_profile(os.environ['PENTEST_PROFILE'])
adapter = create_adapter(profile)
cookie = adapter.get_headers('user_a').get('Cookie', '')
if not cookie:
    raise SystemExit('cookie adapter returned no session cookie')
sys.stdout.write(cookie)
") || FRESH_COOKIE=""
    if [[ -z "$FRESH_COOKIE" ]]; then
      FRESH_COOKIE="${PENTEST_USER_A_COOKIE:-}"
      warn "ZAP cookie refresh failed — falling back to the sign-in cookie."
    fi
    if [[ -z "$FRESH_COOKIE" ]]; then
      # No usable cookie: running ZAP now would silently produce an
      # UNAUTHENTICATED scan reported as "ran". Skip ZAP instead.
      warn "No session cookie available for ZAP — skipping ZAP to avoid an unauthenticated scan."
      ZAP_AVAILABLE=false
    else
      export SESSION_COOKIE="$FRESH_COOKIE"
      export JWT_TOKEN=""
    fi
  else
    info "Refreshing Bearer JWT for ZAP scan..."
    FRESH_JWT=$("$PYTHON_BIN" -c "
import sys, os
sys.path.insert(0, '.')
from profile import load_profile
from auth import create_adapter
profile = load_profile(os.environ['PENTEST_PROFILE'])
adapter = create_adapter(profile)
print(adapter.get_token('user_a'))
") || FRESH_JWT=""
    if [[ -z "$FRESH_JWT" ]]; then
      FRESH_JWT="${PENTEST_USER_A_JWT:-}"
      warn "ZAP JWT refresh failed — falling back to the sign-in token (may be expired)."
    fi
    if [[ -z "$FRESH_JWT" ]]; then
      # No usable token: running ZAP now would silently produce an
      # UNAUTHENTICATED scan reported as "ran". Skip ZAP instead.
      warn "No Bearer JWT available for ZAP — skipping ZAP to avoid an unauthenticated scan."
      ZAP_AVAILABLE=false
    else
      export JWT_TOKEN="$FRESH_JWT"
      export SESSION_COOKIE=""
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Run ZAP (if available)
# ---------------------------------------------------------------------------
ZAP_REPORT_ARG=""
if [[ "$ZAP_AVAILABLE" == "true" ]]; then
  # ── Generate the runtime ZAP plan from the active profile ──────────────────
  # The committed zap/automation-plan.yaml ships an empty requestor list. Inject
  # one request per endpoint the frozen profile declares (authenticated /
  # payment / internal use the Bearer header set; anonymous and the upload
  # endpoint use the anon-key set; webhooks get signature-shaped probe headers)
  # so ZAP seeds — and then actively scans — exactly the active stack's surface.
  # ${TARGET_BASE_URL} / ${JWT_TOKEN} / ${SESSION_COOKIE} / ${SUPABASE_ANON_KEY}
  # are kept LITERAL so ZAP performs the env substitution at scan time. On
  # failure we fall back to the static skeleton plan (no seeded endpoints).
  ZAP_PLAN_FILE="automation-plan.yaml"
  # Requestor-injection logic lives in zap/build_runtime_plan.py (source of
  # truth). Its __main__ owns all IO and exits non-zero on a missing requestor
  # job so the static-skeleton fallback below still fires.
  if "$PYTHON_BIN" -m zap.build_runtime_plan; then
    ZAP_PLAN_FILE="automation-plan.runtime.yaml"
    _ZAP_RUNTIME_PLAN="$(pwd)/zap/automation-plan.runtime.yaml"
    info "Generated runtime ZAP plan from profile endpoints: zap/$ZAP_PLAN_FILE"
  else
    warn "ZAP runtime plan generation failed — running the static skeleton plan (no seeded endpoints)."
  fi

  # In read-only mode, restrict ZAP to passive scanning only.
  ZAP_MODE_ARGS=""
  if [[ "$PENTEST_MODE" == "read-only" ]]; then
    info "ZAP running in passive-only mode (read-only pentest mode)."
    ZAP_MODE_ARGS="-config scanner.attackStrength=OFF"
  fi

  info "Running ZAP automation scan (this may take up to 30 minutes)..."
  # Exactly one of JWT_TOKEN / SESSION_COOKIE is non-empty here (set by the
  # refresh block above, which skips ZAP entirely when neither credential is
  # available). The empty one drives an inert empty-header replacer rule. Both
  # are passed so the plan's ${JWT_TOKEN} / ${SESSION_COOKIE} tokens always
  # resolve (an undefined ZAP var would be left as a literal "${...}").
  set +e
  docker run --rm \
    -v "$(pwd)/zap:/zap/wrk:rw" \
    -v "$(pwd)/reports:/zap/reports:rw" \
    -e TARGET_BASE_URL="$TARGET_BASE_URL" \
    -e JWT_TOKEN="${JWT_TOKEN:-}" \
    -e SESSION_COOKIE="${SESSION_COOKIE:-}" \
    -e SUPABASE_ANON_KEY="${SUPABASE_ANON_KEY:-}" \
    -e SUPABASE_PROJECT_URL="${SUPABASE_PROJECT_URL:-}" \
    -e REPORT_DIR="/zap/reports" \
    "$ZAP_IMAGE" \
    zap.sh -cmd -autorun "/zap/wrk/$ZAP_PLAN_FILE" $ZAP_MODE_ARGS
  ZAP_EXIT=$?
  set -e

  if [[ $ZAP_EXIT -ne 0 ]]; then
    warn "ZAP exited with code $ZAP_EXIT — report may be partial."
  else
    info "ZAP scan complete."
  fi

  # ZAP writes zap-report.json (from automation-plan.yaml reportFile setting).
  if [[ -f "reports/zap-report.json" ]]; then
    # Scrub Bearer tokens, JWTs, and NextAuth/Auth.js cookies from the ZAP
    # report before aggregation. See reports/scrub.py (tested in
    # tests/test_scrub.py) — opaque session/OAuth cookies are not eyJ-shaped, so
    # cookie redaction plus the exact seeded credential (ZAP_SCRUB_SECRETS) is
    # required to keep them out of the persisted report.
    # Fail CLOSED ([SEC-DATA]): if scrubbing errors, discard the unscrubbed
    # report rather than persist/aggregate a file that still carries the live
    # credential. stderr is intentionally NOT suppressed so a traceback shows.
    info "Scrubbing secrets from ZAP report..."
    # Seeded credential(s) for literal redaction — exactly one is non-empty.
    export ZAP_SCRUB_SECRETS="${SESSION_COOKIE:-}
${JWT_TOKEN:-}"
    if "$PYTHON_BIN" -m reports.scrub "reports/zap-report.json"; then
      mv "reports/zap-report.json" "reports/zap-report-${RUN_TS}.json"
      ZAP_REPORT_ARG="--zap-report reports/zap-report-${RUN_TS}.json"
    else
      warn "ZAP report scrubbing failed — discarding the unscrubbed report to avoid persisting secrets ([SEC-DATA])."
      rm -f "reports/zap-report.json"
    fi
  else
    warn "ZAP report not found at reports/zap-report.json — skipping ZAP input to aggregate."
  fi
fi

# ---------------------------------------------------------------------------
# Aggregate reports
# ---------------------------------------------------------------------------
PYTEST_REPORT_FILE="reports/pytest-report-${RUN_TS}.json"
AGGREGATE_EXIT=0

if [[ ! -f "$PYTEST_REPORT_FILE" ]]; then
  warn "pytest JSON report not found at $PYTEST_REPORT_FILE — skipping aggregation."
else
  if "$PYTHON_BIN" -c "import reports.aggregate" &>/dev/null 2>&1; then
    info "Aggregating reports..."
    set +e
    # shellcheck disable=SC2086
    if [[ -n "$PROFILE" ]]; then
      "$PYTHON_BIN" -m reports.aggregate \
        --pytest-report "$PYTEST_REPORT_FILE" \
        $ZAP_REPORT_ARG \
        --profile "$PROFILE" \
        --run-ts "$RUN_TS" \
        --output-dir reports/output/
    else
      "$PYTHON_BIN" -m reports.aggregate \
        --pytest-report "$PYTEST_REPORT_FILE" \
        $ZAP_REPORT_ARG \
        --run-ts "$RUN_TS" \
        --output-dir reports/output/
    fi
    AGGREGATE_EXIT=$?
    set -e
  else
    warn "reports.aggregate module not found — skipping report aggregation."
    warn "Install the module or implement reports/aggregate.py to enable merged reports."
    AGGREGATE_EXIT=0
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================================"
echo " Pentest Harness Run Complete"
echo "========================================================"
echo " Target:         $TARGET_BASE_URL"
echo " Mode:           $PENTEST_MODE"
echo " Profile:        ${PROFILE:-<none>}"
echo " ZAP scan:       $( [[ "$ZAP_AVAILABLE" == "true" ]] && echo "ran" || echo "skipped" )"
echo " pytest report:  reports/pytest-report-${RUN_TS}.json"
if [[ "$ZAP_AVAILABLE" == "true" && -f "reports/zap-report-${RUN_TS}.json" ]]; then
  echo " ZAP report:     reports/zap-report-${RUN_TS}.json"
fi
if [[ -d "reports/output" ]]; then
  echo " Merged output:  reports/output/"
fi
echo "========================================================"
echo ""

# Exit code contract (from aggregate.py):
#   0 — no findings
#   1 — HIGH or CRITICAL findings
#   2 — only MEDIUM/LOW/INFO findings (no HIGH/CRITICAL)
#   3 — infrastructure error (parse failure, missing inputs)
# When aggregation ran, propagate its exit code.
# When aggregation was skipped, propagate pytest exit code.
if [[ $AGGREGATE_EXIT -ne 0 ]]; then
  exit $AGGREGATE_EXIT
fi
exit $PYTEST_EXIT
