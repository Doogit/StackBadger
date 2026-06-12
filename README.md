# StackBadger

> _Badger your stack before someone else does._

StackBadger is a portable, profile-driven **black-box offensive security harness**. It attacks a live web
application the way an external attacker would — discovering all the configuration it needs from
the deployed client bundle, signing in as a real user, and running a pytest suite of auth-bypass,
IDOR, access-control, injection, and misconfiguration probes — then merges the results (plus an
optional ZAP DAST scan) into HTML and JSON reports.

**No server-side secrets required.** Point it at a URL, give it two test accounts, and run. The
one-command `./run.sh` flow works for any supported stack — auto-discovering a Clerk + Supabase +
Stripe target, or signing in via the adapter named in a profile — see
[What makes it portable](#what-makes-it-portable).

## Responsible use / authorization required

StackBadger is an **active offensive scanner** — it signs in, enumerates
endpoints, and sends real attack traffic, and in `--full` mode it attempts
state-changing writes. **Only run it against systems you own or are explicitly
authorized, in writing, to test.** Unauthorized scanning is illegal in many
jurisdictions and may breach your providers' terms of service. Use disposable
test accounts and a non-production environment whenever possible. See
[SECURITY.md](SECURITY.md) for the full authorization expectation, what `--full`
write probes do, and how to report a vulnerability in StackBadger itself.

Authorization is **machine-enforced**, not just a checkbox: `run.sh` refuses to
scan any non-localhost host (read-only mode included) unless both
`CONFIRM_TARGET=<host>` ("this is the right host") and
`CONFIRM_AUTHORIZED=<host>` ("a human affirmed authorization") exact-match the
host of the **effective target** — the URL you pass to `run.sh`, or
`TARGET_BASE_URL` if you set that override (it wins over the CLI arg, and the
gate confirms exactly what gets scanned). It is the CLI/override host, never a
post-redirect host. `CONFIRM_AUTHORIZED` must be set by the site owner out-of-band —
an AI agent running the harness must never set it for itself — and `--yes` does
not bypass either gate. See `.env.example` for the exact format.

## What makes it portable

StackBadger's pytest suite is **stack-agnostic**: it ships auth adapters and attack modules for a range
of providers, and you select the target's stack with a profile (or, for the default
Clerk + Supabase + Stripe stack, let live discovery fill it in). Supported:

| Layer | Supported providers |
|-------|---------------------|
| **Auth** | Clerk · Firebase Auth · Supabase Auth (GoTrue) · NextAuth / Auth.js |
| **Database** | Supabase (PostgREST + RLS) · Firestore |
| **Storage** | Supabase Storage · Firebase Storage · AWS S3 · Cloudflare R2 |
| **Payments** | Stripe · Paddle · LemonSqueezy (webhook signature probes) |
| **Hosting** | Netlify · Vercel · Cloudflare (informational) |

**One command, any stack:** `./run.sh <url>` automates the whole flow end-to-end (live discovery →
sign-in → optional ZAP → report). With no profile it auto-discovers a Clerk + Supabase + Stripe
target; add `--profile <file>.yaml` to target any other stack — the orchestrator signs in via the
adapter named in `stack.auth` (Clerk / Firebase / Supabase Auth / NextAuth). NextAuth uses cookie
auth, so the optional ZAP scan (which seeds a Bearer header) is skipped on that path; every
supported stack otherwise runs end-to-end.

Adding a new target is a YAML profile. See [Adding a new target](#adding-a-new-target).

---

## Fastest path: one prompt in Claude Code

StackBadger is designed to be driven by an AI coding agent. **Clone it, do the one-time setup below,
then open Claude Code in this directory and paste a single prompt.**

```
Follow LAUNCH.md to run a security test against https://your-site.com
```

Claude will: gather your test-account credentials, run pre-flight checks, discover the target's
public config, execute the suite via `./run.sh` (adding `--profile` for non-default stacks), and
summarize the report — no file editing required.
`LAUNCH.md` contains the full agent runbook.

### One-time setup (required before the prompt)

```bash
# 1. Clone and enter the directory
git clone https://github.com/Doogit/StackBadger.git
cd StackBadger

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install
pip install -e .

# 4. Add two test-account credentials
cp .env.example .env
# Edit .env — email + password for two test accounts (see "Test accounts" below)
```

That's it. Now run the Claude Code prompt above, or use the manual CLI below.

> All commands below assume you are inside the StackBadger directory (the repository root).

---

## Manual quick start

`./run.sh` automates the full flow. With no profile it auto-discovers a Clerk + Supabase + Stripe
target and signs in via Clerk; add `--profile` to target any supported stack (the adapter named in
`stack.auth` handles sign-in) and to unlock the endpoint-specific probes.

```bash
# Black-box run — assumes Clerk + Supabase + Stripe; config auto-discovered from the live bundle
./run.sh https://your-site.com --skip-zap
```

```bash
# Full suite including a ZAP DAST scan (requires Docker)
./run.sh https://your-site.com
```

```bash
# With a profile — any supported stack; signs in via the profile's stack.auth adapter
./run.sh https://your-site.com --profile profiles/your-site.yaml
```

## Running on other stacks

`./run.sh <url> --profile profiles/your-site.yaml` drives **any** supported stack — the orchestrator
signs in via the adapter named in the profile's `stack.auth` (Clerk / Firebase / Supabase Auth /
NextAuth), using the same `.env` credentials. Two things to know:

- **NextAuth (cookie auth):** sign-in, pytest, and the optional ZAP scan all run end-to-end. ZAP is
  seeded with the session **cookie** (Bearer stacks — Clerk / Firebase / Supabase Auth — are seeded
  with a Bearer header instead); the report scrubber redacts the session cookie before persisting.
- **Live discovery fingerprints Firebase and NextAuth** from the client bundle, so for those targets
  even a no-profile run usually selects the right `stack.auth`. Supabase Auth shares Supabase's
  fingerprint and is not auto-detected as the auth provider, so name `stack.auth: supabase-auth`
  explicitly in a profile. This is a fundamental limit, not a missing feature: `supabase-js`
  statically bundles the GoTrue auth client even for database-only use, so a static bundle scan
  cannot tell a Supabase-Auth target from a Clerk-auth + Supabase-database target (an inherent limit of static bundle analysis).
  A profile is also what unlocks the endpoint-specific probes.

```bash
# 1. Write a profile naming the stack (copy a template):
cp profiles/firebase-example.yaml profiles/your-site.yaml   # then edit stack + provider block

# 2. Run end-to-end via the orchestrator:
./run.sh https://your-site.com --profile profiles/your-site.yaml --skip-zap
```

You can also invoke pytest directly (skips `run.sh`'s pre-flight and ZAP seeding) — handy for
debugging a single module. The same `--full`/write-probe gating applies via markers (use
`-m "not write_probe"` for read-only, the default):

```bash
TARGET_BASE_URL=https://your-site.com \
  python -m pytest tests/ --profile profiles/your-site.yaml -m "not write_probe" -v
```

## Prerequisites

- Python 3.11 or later, and pip
- Two test accounts in the target's auth system (see [Test accounts](#test-accounts))
- A live or staging deployment of the target
- Docker (optional — only for the ZAP DAST scan)

## How it works

This is the `./run.sh` flow. With no profile it assumes Clerk + Supabase + Stripe; with `--profile`
it uses the providers named in the profile, and step 2 signs in via that stack's auth adapter.

1. **Discover** — `discover.py` fetches the target's HTML and JS bundles and extracts public config
   (Supabase project URL + anon key, Clerk publishable key / FAPI host, and provider fingerprints)
   the way an external attacker would. No secrets needed — these values are already public.
   (`discover.py` can also fingerprint providers when pointed at a project's source tree, to help
   author a profile.)
2. **Sign in** — `run.sh` authenticates the two test accounts via the adapter named in `stack.auth`
   (Clerk FAPI, Firebase, Supabase Auth, or NextAuth), using email + password exactly as a browser
   does, and refreshes the credential throughout the run.
3. **Test** — Runs pytest modules against the discovered config. Tests whose required config is
   missing **skip** (they do not fail), so partial profiles still produce useful results.
4. **Scan** (optional) — Runs a ZAP DAST scan seeded with the acquired credential: a Bearer header
   for bearer stacks, or the session cookie for NextAuth cookie auth.
5. **Report** — Aggregates pytest + ZAP results into HTML and JSON.

When no `--profile` is given, `run.sh` builds a runtime profile from live discovery — using the
fingerprinted stack when one is detected, and defaulting to Clerk + Supabase + Stripe otherwise. A
profile lets you name the stack explicitly and adds structural metadata (endpoint list, table names,
RPCs) that unlocks the endpoint-specific probes.

## Modes

| Flag | Mode | Writes to target? | ZAP mode |
|------|------|--------------------|----------|
| _(none)_ | Read-only (default) | No | Passive only |
| `--read-only` | Read-only (explicit) | No | Passive only |
| `--full --yes` | Full | Yes (sentinel UUIDs) | Active |
| `--branch --yes` | Full against disposable branch DB | Branch only | Active |

### Read-only (default)

```bash
./run.sh https://your-site.com
```

All probes verify security controls via HTTP response codes only — no INSERT/UPDATE/DELETE or file
upload requests reach the target. **Safe to run against production.** Write probes (marked
`@pytest.mark.write_probe`) are skipped and counted as skipped.

### Full (`--full`)

```bash
./run.sh https://your-site.com --full --yes
```

Adds write probes that attempt mutations using sentinel UUIDs. If controls are misconfigured, data
could be created or modified. **Recommended only against a non-production environment.**

### Branch (`--branch`) — Supabase targets

```bash
./run.sh https://your-site.com --branch --yes
```

Auto-creates a disposable Supabase branch database, runs the full suite against it, and deletes the
branch afterward — even on failure or Ctrl-C. Requires `SUPABASE_ACCESS_TOKEN`. The safest way to
run write probes. (Supabase-only; other databases use `--full` against a staging target.)

## Test accounts

StackBadger needs **two separate user accounts** in the target's auth system, used for cross-user
(IDOR) probes:

1. In your target's auth provider — **Clerk**, **Firebase Auth**, **Supabase Auth**, or a
   **NextAuth credentials** provider — create two users with **email + password** sign-in enabled.
2. Disable **MFA** on both accounts (headless sign-in cannot complete a TOTP/SMS challenge; StackBadger
   detects MFA and skips with a clear error).
3. For the strongest coverage, ensure each account owns at least one real resource (an uploaded
   file, a document, a row) so positive-control checks can confirm a probe's baseline.
4. Set the credentials in `.env`:
   ```bash
   PENTEST_USER_A_EMAIL=pentest-a@example.com
   PENTEST_USER_A_PASSWORD=...
   PENTEST_USER_B_EMAIL=pentest-b@example.com
   PENTEST_USER_B_PASSWORD=...
   ```

StackBadger signs in via the provider's public sign-in API, acquires tokens, and refreshes them for the
duration of the run. No manual token rotation.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PENTEST_USER_A_EMAIL` / `_PASSWORD` | Yes | Test account A. |
| `PENTEST_USER_B_EMAIL` / `_PASSWORD` | Yes (IDOR tests) | Test account B (cross-user probes). |
| `TARGET_BASE_URL` | No | Overrides the target URL CLI argument. |
| `SUPABASE_ACCESS_TOKEN` | No | Supabase Management API token — required only for `--branch`. |
| `PENTEST_INTERNAL_SECRET` | No | Internal-endpoint authorization secret, for internal-endpoint tests. |
| `PENTEST_USER_A_JWT` / `_B_JWT` | No | Pre-obtained token used as a fallback when live sign-in is unreachable or fails (at startup or mid-run). Live sign-in is attempted first. |

**Provider config overrides** (all auto-discovered by default; set only to override):

| Variable | Provider |
|---|---|
| `SUPABASE_PROJECT_URL` / `SUPABASE_ANON_KEY` | Supabase |
| `CLERK_FAPI_HOST` | Clerk |
| `FIREBASE_API_KEY` | Firebase |

Missing config causes the dependent tests to **skip**, not fail.

> **Concurrent runs against different targets:** these overrides are the highest-precedence
> config layer, so an exported `SUPABASE_ANON_KEY` / `FIREBASE_API_KEY` (etc.) is baked into
> **every** run launched from that shell — including the frozen profile of a no-profile run.
> Two `./run.sh` invocations against different targets from one shell with such a value
> exported will share the inherited credential. Use a **separate shell per target** (or unset
> the override) when running concurrently against different deployments.

## Adding a new target

You have three options, fastest first:

**1. Zero config.** Just run it — live discovery fills in the config and fingerprints the stack
(defaulting to Clerk + Supabase + Stripe when nothing is detected):
```bash
./run.sh https://new-site.com --skip-zap
```
Endpoint-specific probes skip (no endpoint list), but auth, access-control, storage, CORS, and
info-disclosure probes run. Supabase Auth isn't auto-detected as the auth provider — name it in a
profile (option 2 or 3).

**2. Auto-generate a profile from source** (if you have the target's repo). This is also how StackBadger
fingerprints non-default providers — `discover.py`'s source scan detects the stack and writes it
into the profile:
```bash
python discover.py /path/to/target-project --output profiles/new-site.yaml
# Any stack: ./run.sh https://new-site.com --profile profiles/new-site.yaml
```

**3. Hand-write a profile.** Copy a template and fill it in:
```bash
cp profiles/firebase-example.yaml profiles/new-site.yaml   # or clerk-supabase-example.yaml for Clerk+Supabase
```
Then update `stack`, the provider config block, and `endpoints`. See the schema below and the
step-by-step `discover-prompt.md`.

## Profile schema

Profiles live in `profiles/`. Every field is optional except `target.base_url`; the relevant
provider block is required when you name that provider in `stack`.

```yaml
target:
  base_url: "https://example.com"      # Required. CLI target URL overrides this.
  api_prefix: "/.netlify/functions"    # Optional. Prepended to all API paths. (/api for Vercel, etc.)

stack:
  auth: clerk            # clerk | firebase | supabase-auth | nextauth
  database: supabase     # supabase | firestore
  storage: supabase      # supabase | firebase | s3 | r2
  payments: stripe       # stripe | paddle | lemonsqueezy  (string or list)
  hosting: netlify       # netlify | vercel | cloudflare (informational)

# --- Provider config blocks (include the one(s) matching stack) ---

supabase:                              # auth: supabase-auth and/or database/storage: supabase
  project_url: "https://xxx.supabase.co"   # Auto-discovered; set to override.
  anon_key: "eyJ..."                        # Auto-discovered; set to override.
  storage_buckets: [user-files]
  tables:
    user_facing: [documents, projects, comments]   # Expected per-user RLS.
    public_read_only: [public_posts]                # Readable without auth.
    service_role_only: [audit_log, billing_events]  # Must be inaccessible via anon key.
  table_pks: {documents: document_id}

clerk:                                 # auth: clerk
  frontend_api: "https://xxx.clerk.accounts.dev"   # Auto-discovered; set to override.

firebase:                              # auth: firebase and/or storage/database: firebase/firestore
  api_key: "AIza..."                   # Auto-discovered; set to override.
  project_id: "your-project-id"
  storage_bucket: "your-project-id.appspot.com"
  firestore_collections: [users, orders]
  test_document_ids: {user_a: "doc-a", user_b: "doc-b"}   # Positive controls for rules tests.
  test_storage_paths: {user_a: "users/uid-a/f.pdf", user_b: "users/uid-b/f.pdf"}

nextauth:                              # auth: nextauth
  signin_path: "/api/auth/callback/credentials"   # Optional; sensible defaults.
  session_path: "/api/auth/session"

aws:                                   # storage: s3
  s3_bucket: "my-bucket"
  s3_region: "us-east-1"
  presigned_url_endpoint: "/api/files/presign"

cloudflare:                            # storage: r2
  r2_account_id: "your-account-id"
  r2_bucket: "my-bucket"

payments:                              # Paddle / LemonSqueezy webhook paths only.
  paddle_webhook_path: "/api/webhooks/paddle"        # Stripe is declared under endpoints.webhook
  lemonsqueezy_webhook_path: "/api/webhooks/lemonsqueezy"   # with signature: stripe (see below).

# --- Structural metadata (drives endpoint-specific probes) ---

endpoints:
  authenticated:
    - {path: /list-documents, method: POST, probe_body: {project_id: "{{uuid}}"}}
    - {path: /export-document, method: POST, payment_gated: true}
  anonymous:
    - {path: /public-feed, method: POST, fully_anonymous: true}
  webhook:
    - {path: /clerk-webhook, method: POST, signature: svix}     # svix | stripe (Paddle/LemonSqueezy use the payments block)
    - {path: /stripe-webhook, method: POST, signature: stripe}
  internal:
    - {path: /notify-user, method: POST}
  payment:
    - {path: /create-checkout-session, method: POST}

supabase_rpcs:
  client_callable:
    - {name: merge_anon_session, params: [anon_id], risk: high}   # high | medium | low
  server_only: [replace_document_body]

payment_gate:                          # Payment-gate bypass probe targets.
  table: users
  column: paid_at
  checkout_fields: [document_id, success_url, cancel_url]

uploads:                               # File-upload abuse probe config.
  endpoint: /import-csv
  format: csv
  valid_fixture: fixtures/records.csv

sensitive_patterns: ["at Object.", "/var/task/", "SyntaxError"]   # Info-disclosure leak markers.
custom_headers: {anon_session: "x-anon-session"}
features: {anon_sessions: true}
source_file_map: {/list-documents: "netlify/functions/list-documents.js"}

test_accounts:
  user_a: {email: "pentest-a@example.com"}
  user_b: {email: "pentest-b@example.com"}
```

Two ready-made profiles ship as references: `profiles/clerk-supabase-example.yaml` (Clerk + Supabase +
Stripe + Netlify) and `profiles/firebase-example.yaml` (Firebase + Firestore).

## Architecture

```
profiles/            Site profile YAML (structural metadata: endpoints, tables, RPCs)
    |
    v
discover.py          Provider fingerprinting + live bundle discovery (or static source analysis)
    |
    v
profile_assembler.py Merges discovered config + optional YAML overrides
    |
    v
auth/                Auth adapters (per provider; sign-in + auto-refresh, no secrets)
    |                base · clerk · firebase · supabase_auth · nextauth
    v
tests/               pytest modules (one per attack category)
    |                conftest.py provides: profile, auth_adapter, anon/user_a/user_b clients,
    |                api_client, evidence fixtures
    v
reports/evidence/    Per-test HTTP request/response pairs (JSON, saved on failure)
    |
    v
reports/             Aggregated output: pytest JSON + ZAP JSON -> HTML + JSON summary
zap/                 ZAP Automation Framework plan (requestor-seeded active scan)
fixtures/            Adversarial input files for upload and injection tests
```

### Test categories

| Module | Attack category |
|---|---|
| `test_auth_bypass` | Unauthenticated access to protected endpoints |
| `test_idor` | Insecure direct object reference (cross-user resource access) |
| `test_rls_bypass` | Supabase RLS bypass via anon key, role spoofing |
| `test_firestore_rules` | Firestore Security Rules misconfiguration (cross-user read/write) |
| `test_storage_bypass` | Supabase Storage access without ownership |
| `test_firebase_storage` | Firebase Storage rules + signed-URL abuse |
| `test_s3_storage` | S3 / R2 bucket access, presigned-URL reuse, path traversal |
| `test_anon_session` | Anon session merge abuse, session fixation |
| `test_webhook_spoofing` | Svix / Stripe signature bypass, internal-endpoint secret probing |
| `test_webhook_paddle` | Paddle webhook signature bypass (gated on `paddle` in `stack.payments`) |
| `test_webhook_lemonsqueezy` | LemonSqueezy webhook signature bypass (gated on `lemonsqueezy`) |
| `test_injection` | SQL injection, prompt injection via uploaded files |
| `test_file_upload` | Oversized uploads, malformed CSV, polyglot files |
| `test_auth_flows` | Token reuse, privilege escalation, re-auth gaps |
| `test_payment_gate` | Payment-gated endpoint bypass without checkout |
| `test_api_surface` | Unexpected endpoints, HTTP method enumeration |
| `test_cors_headers` | CORS misconfiguration, cross-origin credential leakage |
| `test_info_disclosure` | Stack traces, internal endpoint exposure, version leakage |

Adapter unit tests (`test_clerk_fapi`, `test_firebase_auth_adapter`, `test_nextauth_adapter`,
`test_supabase_auth_adapter`, `test_discover`, `test_profile_assembler`) validate the harness
machinery itself and run without a live target.

## Reports

| File | Format | Description |
|---|---|---|
| `reports/pytest-report-<ts>.json` | JSON | Raw pytest results (per-test pass/fail/skip). |
| `reports/zap-report-<ts>.json` | JSON | ZAP `traditional-json-plus` findings by severity. |
| `reports/output/` | HTML + JSON | Merged human-readable + agent-readable report. |
| `reports/evidence/` | JSON | Per-test HTTP request/response pairs. |

> In read-only mode, write-probe tests appear in the **skipped** count with reason
> "Skipped in read-only mode (use --full to enable write probes)." This is expected.

### Exit codes

`run.sh` uses these exit codes for CI gating:

| Code | Meaning | Recommended CI action |
|------|---------|----------------------|
| `0` | Clean run — no findings | Pass |
| `1` | HIGH or CRITICAL findings present | Fail build |
| `2` | MEDIUM or LOW findings only | Warn, do not block |
| `3` | Infrastructure error (collection failure, missing deps, parse error) | Fail build (harness is broken, not the app) |
| `10` | Preflight or safety gate failed — the scan never ran | Fail build; fix the reported gate/check and re-run |

> The finding-severity codes (`0`–`3`) come from `reports/aggregate.py`. Code `10` is distinct: it
> means a pre-scan check refused the run — `doctor.py` preflight (Python version, missing credentials,
> unreachable target, a User A/B sign-in failure) or a `CONFIRM_TARGET` / `CONFIRM_AUTHORIZED` gate
> mismatch. No probes fired, so a `10` is never a finding. Run `python doctor.py <url> --json` to see
> the per-check verdict (it uses granular codes `10`–`19`; `run.sh` collapses any of them to `10`).

## Known platform-dependent findings

Some findings reflect platform constraints or intentional design, not bugs. Whether they apply
depends on your target's hosting and stack:

- **Anon/publishable key visible in client bundle** — Supabase anon keys and Firebase API keys are
  intentionally public. RLS / Security Rules are the authorization mechanism, not key secrecy.
- **CSP / X-Frame-Options / HSTS headers absent** — Many CDNs (e.g. Netlify) do not inject these by
  default, and preview URLs lack HSTS preloading. Flag as informational unless your threat model
  requires them.
- **Server version header** — Often emitted by the CDN and not configurable.

Confirm these against your own product decisions before treating them as defects.

## Troubleshooting

**Sign-in failed** — Check the `.env` credentials, confirm MFA is disabled on both accounts, and
that the target is reachable. Live sign-in is attempted first; `PENTEST_USER_*_JWT` is used only as
a fallback when sign-in is unreachable or fails. If the provider's bot protection blocks headless
sign-in, resolve that (e.g. allowlist the IP) before running.

**Docker not found** — ZAP is optional. Pass `--skip-zap`, or install Docker and
`docker pull ghcr.io/zaproxy/zaproxy:stable`.

**Rate limiting (429s)** — Run modules individually to reduce concurrency:
`python -m pytest tests/test_injection.py --profile profiles/your-site.yaml -v`.

**Profile not found** — The `--profile` path is relative to where you invoke `run.sh`. Run from the
StackBadger directory or pass an absolute path.

**Unsupported auth adapter** — `stack.auth` must be one of `clerk`, `firebase`, `supabase-auth`,
`nextauth`. For other providers, supply `PENTEST_USER_*_JWT` tokens and the suite will run with the
generic bearer flow where possible.
