# StackBadger — Interactive Launch

This file is the agent runbook for StackBadger. Tell Claude Code:
**"Follow LAUNCH.md to run a security test against https://your-site.com"**

---

## Instructions for Claude

Follow these steps in order. Ask the user for input where indicated.
Do NOT proceed past a step until it succeeds.

### Step 1: Gather inputs from the user

If the target URL was not already given in the prompt, ask for it. Then ask for two test accounts:

> I need a few things to run StackBadger:
> 1. **Target site URL** (production or staging) — unless you already gave it to me
> 2. **Test Account A** — email and password
> 3. **Test Account B** — email and password (a different account, for cross-user IDOR probes)
>
> Both accounts must exist in the target's auth provider (Clerk, Firebase, Supabase Auth, or a
> NextAuth credentials provider), with email+password sign-in enabled and **MFA disabled**.

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
> the URL you pass to `run.sh` — not a post-redirect host. If the site redirects
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

### Step 4: Choose a profile (optional but recommended)

StackBadger runs **with or without** a profile:

- **No profile (black-box):** live discovery fingerprints the stack and extracts public config
  automatically. Auth, access-control, storage, CORS, and info-disclosure probes run; endpoint- and
  table-specific probes skip because there is no declared surface. This is the default — nothing to do.
- **With a profile:** unlocks endpoint-specific probes (IDOR on named resources, payment-gate
  bypass, webhook spoofing, RPC abuse).

Decide which applies:

1. **A profile already exists** for this target in `profiles/` → use it with `--profile`.
2. **The user has the target's source code** → offer to auto-generate one:
   ```bash
   python discover.py /path/to/target-project --output profiles/<name>.yaml
   ```
   Then review the generated profile for `# TODO` placeholders before using it.
3. **URL only, no profile** → run black-box (no `--profile` flag). Live discovery fingerprints the
   stack (Firebase and NextAuth are auto-detected; otherwise it defaults to Clerk + Supabase +
   Stripe). Supabase Auth shares Supabase's fingerprint and is not auto-detected as the auth
   provider — supply a profile naming `stack.auth: supabase-auth` for those targets.

> **Note — NextAuth (cookie auth).** `run.sh` signs in via the adapter named in `stack.auth` for
> every supported stack. The optional ZAP scan is seeded with whatever the adapter yields: a Bearer
> header for bearer stacks (Clerk / Firebase / Supabase Auth), or the session **cookie** for NextAuth
> (cookie auth). Sign-in, pytest, and ZAP all run end-to-end for every stack.

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

NextAuth (cookie auth) targets run end-to-end too — ZAP is seeded with the session cookie.

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

**`run.sh`:** `run.sh` exits `1` for BOTH harness failures (missing deps, sign-in error,
unreachable target) AND HIGH/CRITICAL findings. Distinguish by checking for report output:

```bash
if [ -d reports/output ] && ls reports/output/*.json >/dev/null 2>&1; then
  echo "Reports generated — interpret the exit code as test results."
else
  echo "No reports — the harness failed before tests ran. Report the stdout/stderr error."
fi
```

Interpretation:
- Exit 0: "Clean run — no findings."
- Exit 1 WITH reports: HIGH/CRITICAL findings present. Summarize from `reports/output/`.
- Exit 1 WITHOUT reports: Harness infrastructure failure. Report the error from stdout/stderr.
- Exit 2: MEDIUM/LOW findings only. Summarize as warnings.
- Exit 3: Infrastructure error (pytest collection failure, missing deps).

Read and summarize `reports/output/` for the user. Highlight actionable findings and distinguish
them from the known platform-dependent findings listed in the README.

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
   provider was absent or config was missing.
