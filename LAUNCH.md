# StackBadger — Interactive Launch

This file is the **agent runbook**: numbered, gated steps for an AI agent driving a run. Tell
Claude Code: **"Follow LAUNCH.md to run a security test against https://your-site.com"**

Humans: start with [README.md](README.md) instead — quickstart, config reference, profile schema,
and the [Troubleshooting table](README.md#troubleshooting) this runbook leans on.

---

## Instructions for Claude

Follow these steps in order. Ask the user for input where indicated.
Do NOT proceed past a step until it succeeds.

The gated sequence:

```
0  source detect (optional)   1  gather inputs        1a authorization (HUMAN-set)
1b mode                       2  environment setup    3 / 3a credentials or provision
4  profile                    4a doctor gate          5  run
6  interpret exit code        7  recap                8  teardown (if provisioned)
```

When any step fails with an error you don't recognize, map it via the README
[Troubleshooting table](README.md#troubleshooting) before asking the user.

### Step 0 (optional accelerator): Source stack-detection

**Only if the user has the target's source code.** Black-box bundle discovery
is the zero-config default and needs nothing — skip to Step 1 when there is no
source. Source detection exists because a deployed bundle cannot distinguish
Supabase Auth from Clerk-auth-on-a-Supabase-database (`supabase-js` statically
bundles the GoTrue client either way), while source can.

```bash
python discover.py /path/to/target-project --output profiles/<name>.yaml
```

The verdict goes to **stderr** (stdout is the profile YAML when not using
`--output`), mixed with human-readable evidence lines. Capture and extract it
like this:

```bash
python discover.py /path/to/target-project --output profiles/<name>.yaml 2>detect-auth.log
grep -F '[detect-auth-json]' detect-auth.log   # one JSON line: {provider, confidence, evidence}
```

Then act on the verdict:

- **`confidence=high`** — the generated profile's `stack.auth` is set.
  Present the evidence to the user and confirm it matches their understanding
  before using the profile.
- **`confidence=ambiguous`** — multiple active auth libraries were found.
  `stack.auth` was deliberately left as a `CONFIRM` placeholder. You MUST
  present the evidence lines to the user, ask which provider actively signs
  users in, and set `stack.auth` in the profile to their answer. Never pick
  one yourself.
- **`confidence=none`** — no auth library detected; fall back to bundle
  discovery and ask the user what the auth provider is.

The detector layers dependency presence, then active usage (e.g.
`supabase.auth.*` calls and `@supabase/ssr` middleware vs `@clerk/*` imports),
then the target's own `CLAUDE.md`/`AGENTS.md` prose — prose is corroboration
only, and code evidence wins on conflict.

Also review the generated profile for `# TODO` placeholders before using it.

### Step 1: Gather inputs from the user

If the target URL was not already given in the prompt, ask for it. Then ask for two test accounts:

> I need a few things to run StackBadger:
> 1. **Target site URL** (production or staging) — unless you already gave it to me
> 2. **Test Account A** — email and password
> 3. **Test Account B** — email and password (a different account, for cross-user IDOR probes)
>
> Both accounts must exist in the target's auth provider (Clerk, Firebase, Supabase Auth, or a
> NextAuth credentials provider), with email+password sign-in enabled and **MFA disabled**.

If the accounts do **not** exist yet and the target uses **Supabase Auth**, offer to create them
in Step 3a instead of asking for credentials. For Clerk / Firebase / NextAuth, the user must
create them in the provider dashboard first — `python provision_accounts.py --provider clerk`
(or `firebase` / `nextauth`) prints the steps.

### Step 1a: Authorization gate (human-set, machine-enforced)

Authorization must be affirmed by the **human**, out-of-band — do NOT set these
variables yourself, and do not proceed until the user confirms they have set them:

- [ ] I confirm I'm authorized to test {TARGET}

> Before I can run anything, you (not I) must affirm authorization in your shell.
> Run these two exports — `run.sh` refuses any remote scan without them:
>
> ```bash
> export CONFIRM_TARGET=<target host>       # e.g. staging.example.com — exact host, no scheme/port
> export CONFIRM_AUTHORIZED=<target host>   # affirms you own / are authorized in writing to test it
> ```
>
> No subdomain cross-match (`api.example.com` != `example.com`). Use the host of
> the effective target — the URL you pass to `run.sh` (or `TARGET_BASE_URL` if
> that override is set) — not a post-redirect host. If the site redirects
> apex -> www and you want to test www, pass the www URL and confirm
> `www.example.com`. Only do this for systems you own or are explicitly
> authorized, in writing, to test.

If `run.sh` later refuses with a `CONFIRM_TARGET` / `CONFIRM_AUTHORIZED` gate
error, relay the message to the user and wait — never set the variables yourself.

### Step 1b: Select test mode

> **Test mode:**
> - **Read-only** (default) — Verifies security via response codes only. No writes to the target. Safe for production.
> - **Full** — Includes write probes (INSERT/UPDATE/DELETE/upload with sentinel data). Recommended only against a staging or branch environment.
>
> Which mode? (default: read-only)

If the user selects **full mode** and the target uses **Supabase**, recommend `--branch`:
> Full mode selected. Since this target uses Supabase, I recommend `--branch` to auto-create a
> disposable branch database. This requires `SUPABASE_ACCESS_TOKEN` in `.env`.
> - `--branch` (recommended) — creates a throwaway database, runs full suite, deletes it after
> - `--full --yes` — runs full suite against the target URL directly (use with caution)

For non-Supabase targets in full mode, use `--full --yes` against a non-production deployment.
If the user doesn't specify, use read-only mode with no extra flags.

### Step 2: Pre-flight checks

```bash
# Python version
python3 --version  # must be 3.11+

# Virtual environment
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -e . --quiet

# Docker (optional — not blocking)
if command -v docker >/dev/null 2>&1; then
  echo "Docker: available"
else
  echo "Docker: not found (ZAP scan will be skipped)"
fi
```

If Python < 3.11 or `pip install` fails, stop and tell the user.

### Step 3: Write credentials

Write the credentials to `.env`. This file is gitignored. If a stale `.env` exists, overwrite it —
`run.sh` sources `.env` on startup and stale values would shadow the user's input.

```bash
cat > .env <<EOF
PENTEST_USER_A_EMAIL=<from user>
PENTEST_USER_A_PASSWORD=<from user>
PENTEST_USER_B_EMAIL=<from user>
PENTEST_USER_B_PASSWORD=<from user>
EOF
```

### Step 3a (alternative): Provision the accounts — Supabase Auth only

If the user opted into account creation in Step 1, skip the manual `.env` write above and run:

```bash
python provision_accounts.py --provider supabase-auth
```

Requirements (ask the user to put them in `.env` — do NOT ask them to paste the key into the
chat):

- `SUPABASE_SERVICE_ROLE_KEY` — the project service-role key (Dashboard → Project Settings →
  API keys). The Admin API accepts nothing else; `SUPABASE_ACCESS_TOKEN` only lets the script
  *fetch* this key.
- `SUPABASE_PROJECT_URL` — or pass `--project-url https://<ref>.supabase.co`.

The script creates both accounts confirmed (`email_confirm: true` — never raw SQL, which breaks
GoTrue logins), generates strong passwords, and writes all four `PENTEST_USER_*` values plus the
created user IDs into `.env` with mode `0600`.

> **Re-source `.env` before running anything else.** The credentials were written AFTER your
> shell (and any earlier `source .env`) loaded the file. `run.sh` sources `.env` itself on
> startup, but a `python doctor.py` or direct-pytest call from this same shell will not see the
> new values until you re-source:
>
> ```bash
> set -a; source .env; set +a
> ```

Gate: do not proceed until the script exits **0**. Exit codes: `0` = both
accounts provisioned and written to `.env`; `1` = failure — relay the error
(it is already secret-redacted) and wait for the user; `2` = you ran it with a
non-Supabase `--provider` and it only PRINTED manual dashboard steps — nothing
was provisioned, so wait for the user to confirm the accounts exist and then
write `.env` via Step 3.

### Step 4: Choose a profile (optional but recommended)

StackBadger runs **with or without** a profile:

- **No profile (black-box):** live discovery fingerprints the stack and extracts public config
  automatically. Auth, access-control, storage, CORS, and info-disclosure probes run; endpoint- and
  table-specific probes skip because there is no declared surface. This is the default — nothing to do.
- **With a profile:** unlocks endpoint-specific probes (IDOR on named resources, payment-gate
  bypass, webhook spoofing, RPC abuse).

Decide which applies:

1. **A profile already exists** for this target in `profiles/` → use it with `--profile`.
2. **The user has the target's source code** → use the profile generated in Step 0 (or run it
   now — see Step 0 for how to read the `[detect-auth]` verdict and when a confirm is required).
3. **URL only, no profile** → run black-box (no `--profile` flag). Live discovery fingerprints the
   stack (Firebase and NextAuth are auto-detected; otherwise it defaults to Clerk + Supabase +
   Stripe). Supabase Auth shares Supabase's fingerprint and is not auto-detected as the auth
   provider — supply a profile naming `stack.auth: supabase-auth` for those targets.

Profile field meanings (including `exclude_paths` / `exclude_tables` / `auth.verify_path`) are in
the README [Profile schema](README.md#profile-schema) — don't re-derive them here. Every supported
stack runs end-to-end, NextAuth (cookie auth) included: ZAP is seeded with whatever credential the
adapter yields (Bearer header or session cookie).

### Step 4a: Preflight gate (doctor.py)

Run the machine-readable self-check before the harness:

```bash
# PROFILE_FLAG: --profile profiles/<name>.yaml if Step 4 chose one; omit for black-box
python doctor.py <TARGET_URL> <PROFILE_FLAG> --json
```

stdout is one JSON object: `{"passed": bool, "exit_code": int, "checks": [...]}`. Each check
carries a `fix` string when it fails; on an internal doctor error (exit `19`) the JSON also
carries a top-level `error` string — relay it.

Gate: proceed only when `passed` is `true` (exit `0`). On failure, relay the failing check's
`fix` to the user and wait — exit codes `10`–`19` identify which check failed (Python version,
missing credentials, unreachable target, User A/B sign-in). `run.sh` re-runs doctor internally
and collapses any failure to exit `10`; running it explicitly here catches environment problems
early and gives you structured output instead of a mid-run abort.

Note: a clean doctor pass does not guarantee `run.sh` exits 0 — the `CONFIRM_TARGET` /
`CONFIRM_AUTHORIZED` gates (Step 1a) and the `auth.verify_path` fast-fail also exit `10` on
their own; doctor does not check those.

### Step 5: Run the harness

Use the `./run.sh` orchestrator for any stack — it signs in via the profile's `stack.auth` adapter
(or the discovered/default Clerk stack with no profile).

```bash
# Clear stale reports from any prior run (prevents misinterpreting old results)
rm -rf reports/output reports/evidence

# MODE_FLAGS:
#   Read-only (default): (empty)
#   Full + branch:       --branch --yes
#   Full (no branch):    --full --yes
# PROFILE_FLAG (optional): --profile profiles/<name>.yaml   (omit for black-box)

if command -v docker >/dev/null 2>&1; then
  ./run.sh <TARGET_URL> <PROFILE_FLAG> <MODE_FLAGS>
else
  ./run.sh <TARGET_URL> <PROFILE_FLAG> --skip-zap <MODE_FLAGS>
fi
```

**Alternative — direct pytest** (skips `run.sh`'s pre-flight and ZAP seeding; handy for debugging a
single module):

```bash
rm -rf reports/output reports/evidence

# Read-only is the default (write probes carry @pytest.mark.write_probe).
# For the full suite, drop the marker filter: -m "" (and run against a non-prod target).
TARGET_BASE_URL=<TARGET_URL> \
  python -m pytest tests/ --profile profiles/<name>.yaml -m "not write_probe" -v

# Optional: build the merged HTML/JSON report from the pytest run.
python -m reports.aggregate || true
```

### Step 6: Interpret the exit code

**Direct pytest:** the exit code is pytest's own — `0` = all passed, `1` = one or more
failures/errors (a failed security probe). Read the per-test results from `report.json` at the
harness root (or `reports/output/` if you ran `reports.aggregate`).

**`run.sh`:** check exit `10` first — it is categorically different from the others:

- Exit `10`: a preflight check or safety gate **refused the run before any probe fired** —
  doctor failure, `CONFIRM_TARGET` / `CONFIRM_AUTHORIZED` mismatch, or the `auth.verify_path`
  fast-fail. Nothing was scanned and this is never a finding. Relay the `[FAIL]` / gate message
  (it names the fix); for gate messages, the HUMAN must act (Step 1a) — never set the variables
  yourself.
- Exit `0`: "Clean run — no findings." (But check the skipped count — see Step 7.4.)
- Exit `1`: HIGH/CRITICAL findings present. Summarize from `reports/output/`.
- Exit `2`: MEDIUM/LOW findings only. Summarize as warnings.
- Exit `3`: Infrastructure error from report aggregation (collection failure, parse error).

Edge case — **any exit code other than `10` with no `reports/output/`**: pytest died before its
report was written and aggregation was skipped, so `run.sh` propagated pytest's raw exit code
(which can be 1–5). The findings-severity interpretation above only applies when
`reports/output/` is populated; with no reports, treat the exit as an infrastructure failure and
report the stdout/stderr error, not as findings:

```bash
if [ -d reports/output ] && ls reports/output/*.json >/dev/null 2>&1; then
  echo "Reports generated — interpret the exit code as findings severity."
else
  echo "No reports — infrastructure failure before aggregation. Report the stdout/stderr error."
fi
```

Read and summarize `reports/output/` for the user. Highlight actionable findings and distinguish
them from the known platform-dependent findings listed in the README. Map unrecognized errors via
the README [Troubleshooting table](README.md#troubleshooting).

### Step 7: Post-run recap

1. **Files created** — list the report artifacts:
   ```bash
   find reports/ -type f \( -name '*.json' -o -name '*.html' \) | sort
   ```

2. **Test counts** — summarize from the timestamped pytest report:
   ```bash
   python3 -c "
   import json, glob, os
   files = sorted(glob.glob('reports/pytest-report-*.json'), key=os.path.getmtime)
   if not files:
       print('No pytest report found.'); raise SystemExit
   with open(files[-1]) as f:
       data = json.load(f)
   s = data.get('summary', {})
   print(f'Collected: {s.get(\"collected\", \"?\")}')
   print(f'Passed:    {s.get(\"passed\", 0)}')
   print(f'Failed:    {s.get(\"failed\", 0)}')
   print(f'Skipped:   {s.get(\"skipped\", 0)}')
   "
   ```

3. **Mode confirmation:**
   - Read-only: "No data was written to or deleted from the target site."
   - Full without `--branch`: "Write probes were executed against the target. Verify target state if this was production."
   - Full with `--branch`: "Write probes ran against a disposable Supabase branch database (now deleted). No production data was affected."

4. **Stack tested** — state the stack from the profile's `stack` block (or the Clerk + Supabase +
   Stripe default for a no-profile run), and note any test modules that skipped because their
   provider was absent or config was missing. A skip for missing profile fields means that
   surface was **never tested**, not that it passed — say so explicitly.

### Step 8: Teardown (required if Step 3a provisioned accounts)

```bash
python teardown.py
```

Requires `SUPABASE_SERVICE_ROLE_KEY` and `SUPABASE_PROJECT_URL` in `.env` (or pass
`--project-url`) — the same values Step 3a used. Deletes the two seeded accounts by the user IDs
stored in `.env` (falling back to a lookup of the script's own `stackbadger-pentest-*` emails if a
failed run never stored the IDs) and clears the stored values. Idempotent — safe to re-run. Gate: if it exits non-zero, relay which account is still standing and wait; the
seeded accounts are real, confirmed users in the target's auth system and must not outlive the
test. (Branch databases were already deleted by `run.sh`'s exit trap. If the accounts were
created manually in a dashboard, delete them there instead.)
