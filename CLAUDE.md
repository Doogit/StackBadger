# StackBadger — Agent Guide

StackBadger is an **active black-box API security harness** (offensive scanner). It signs in to a
live target, sends real attack traffic, and writes HTML/JSON reports. Full user docs live in
README.md (provider matrix, profile schema, env vars) and LAUNCH.md (the human runbook) — consult
those rather than re-deriving them. Read SECURITY.md before running anything against a real host.

## CRITICAL safety rules
- **Never** run `run.sh <url>` or pytest against a real target on your own initiative. That sends
  live attack traffic and requires **written authorization** (SECURITY.md, AUTHORIZATION.md). Only
  do so when the user explicitly names a target and confirms authorization.
- **Read-only is the default** and the only mode safe against production. Mutation probes carry
  `@pytest.mark.write_probe` and run only under `--full`/`--branch`. Any new INSERT/UPDATE/DELETE/
  upload probe MUST be marked `@pytest.mark.write_probe`. Never remove that gate.
- `--full`/`--branch` require `--yes` to skip the confirm prompt; never auto-pass `--yes`.
- Keep probes **stack-agnostic**: derive every endpoint/table/RPC/bucket from the active profile.
  Never hardcode a name from one specific application. New example profiles use placeholder hosts
  only (`example.com`, `your-*`).

## Environment / venv (Windows host)
- Activate: `.venv\Scripts\Activate.ps1` (PowerShell) or `.venv\Scripts\activate` (cmd). The README's
  `source .venv/bin/activate` is the POSIX form; on this checkout the path is `.venv\Scripts\`.
- When in doubt, call the interpreter directly: `.venv\Scripts\python.exe -m pytest ...`.
- Install: `pip install -e .` (editable). Python 3.11+ required.

## run.sh is bash — it does NOT run natively in PowerShell
`run.sh` uses `set -euo pipefail`, traps, `mktemp`, `curl`, and Docker; `.gitattributes` pins it to
LF. Run it via Git Bash / WSL: `bash run.sh <url> ...`. For local dev and single-module debugging,
prefer invoking pytest directly (below) — that skips run.sh's discovery/sign-in/ZAP and is
cross-platform.

## Canonical commands
- Offline self-tests (safe default for dev — example profiles use reserved placeholder hosts, so
  live probes skip and only the harness machinery runs):
  `.venv\Scripts\python.exe -m pytest tests/ --profile profiles/clerk-supabase-example.yaml`
- Single module (debugging / rate-limit avoidance):
  `.venv\Scripts\python.exe -m pytest tests/test_idor.py --profile profiles/<name>.yaml -v`
- A `--profile` is **required** for pytest (no no-profile pytest path; the black-box no-profile flow
  exists only through run.sh). Read-only marker filter for raw pytest: `-m "not write_probe"`.
- Generate a profile from a target's source tree (offline, safe):
  `.venv\Scripts\python.exe discover.py /path/to/project --output profiles/<name>.yaml`
- Full orchestrated run (LIVE — only with authorization, bash only):
  `bash run.sh https://target --profile profiles/x.yaml --skip-zap`

## Exit codes (run.sh)
`0` clean / no findings · `1` HIGH/CRITICAL findings **OR** pre-test harness failure (sign-in error,
unreachable target) · `2` MEDIUM/LOW only · `3` infra error (collection failure, missing deps). To
disambiguate exit 1: check whether `reports/output/` was produced — present → findings; absent →
harness failed before tests ran (LAUNCH.md Step 6). Raw pytest exit codes are pytest's own, distinct.

## Architecture (data flow)
`profiles/*.yaml` (structural metadata) → `discover.py` (live bundle crawl or static source scan +
provider fingerprinting) → `profile_assembler.py` (merges discovered config + YAML overrides into one
frozen profile) → `auth/` adapters (selected by `stack.auth`: clerk · firebase · supabase_auth ·
nextauth; sign-in + refresh, no server secrets) → `tests/` (one module per attack category;
`conftest.py` provides profile/auth_adapter/anon|user_a|user_b clients/api_client/evidence fixtures
and marker-based skip gating) → `reports/` (pytest JSON + optional ZAP JSON → scrub → aggregate →
`reports/output/` HTML+JSON; per-test request/response evidence in `reports/evidence/`). run.sh
freezes ONE discovery crawl to a temp YAML so sign-in, ZAP, and pytest consume the same artifact.

## Gotchas
- `--profile` path is resolved relative to the invocation cwd. Run from the repo root or pass an
  absolute path, or you'll get "Profile not found".
- Provider-override env vars (`SUPABASE_ANON_KEY`, `FIREBASE_API_KEY`, `CLERK_FAPI_HOST`,
  `SUPABASE_PROJECT_URL`) are the highest-precedence config layer and are baked into EVERY run from
  that shell. Use a **separate shell per target** when running concurrently.
- Tests **skip** (not fail) when their required provider/config is missing — partial profiles are
  valid and still useful.
- A green run on an example profile means "skipped cleanly," not "tested a real site."

## Generated / gitignored (never commit)
`.env`, `*.env` (except `zap/zap-api.env.example`), `reports/output/`, `reports/evidence/`,
`report.json`, `zap/automation-plan.runtime.yaml`, `fixtures/records_oversized.csv`, `.venv/`, real
per-target profiles `profiles/*.yaml` (only `*-example.yaml` are tracked), `AUTHORIZATION.md`,
`roe/`, `.claude/settings.local.json`, `docs/plans/`.
