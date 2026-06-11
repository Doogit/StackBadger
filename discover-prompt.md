# StackBadger — Profile Discovery Guide

A step-by-step guide for an AI coding agent (Claude Code) to discover endpoints
and build a StackBadger profile for any codebase. (For a black-box, URL-only run you
do not need a profile at all — StackBadger's live discovery handles it. Use this guide
when you have the target's source code and want full endpoint coverage.)

## Prerequisites

- Access to the target project's source code (local path or worktree).
- The StackBadger profile schema — see `profiles/clerk-supabase-example.yaml` (Clerk + Supabase)
  or `profiles/firebase-example.yaml` (Firebase) as references.
- Python 3.11+ with `pyyaml` available (provided by `pyproject.toml`).

---

## Step 1: Stack Detection

Search for these indicators in the project root and all subdirectories.

### Hosting platform

| File | Platform |
|------|----------|
| `netlify.toml` | `stack.hosting: netlify` |
| `vercel.json` | `stack.hosting: vercel` |
| `wrangler.toml` | `stack.hosting: cloudflare` |

### SDK dependencies

Scan every `package.json` (skip `node_modules`) and `requirements.txt`:

| Pattern | Field |
|---------|-------|
| `"@clerk/` | `stack.auth: clerk` |
| `"firebase"` / `"@firebase/auth"` | `stack.auth: firebase` |
| `"next-auth"` / `"@auth/core"` | `stack.auth: nextauth` |
| `"@supabase/supabase-js"` (auth usage) | `stack.auth: supabase-auth` |
| `"@supabase/supabase-js"` | `stack.database: supabase` and `stack.storage: supabase` |
| `"firebase"` / `"firebase-admin"` (Firestore usage) | `stack.database: firestore`, `stack.storage: firebase` |
| `"@aws-sdk/client-s3"` | `stack.storage: s3` |
| `"@aws-sdk/client-s3"` + R2 endpoint | `stack.storage: r2` |
| `"stripe"` | `stack.payments: stripe` |
| `"@paddle/paddle-node-sdk"` / `paddle` | `stack.payments: paddle` |
| `"@lemonsqueezy/lemonsqueezy.js"` | `stack.payments: lemonsqueezy` |

Record the detected values. If a field is absent, omit it from the profile —
never guess. When you detect a non-Supabase provider, add its config block
(`firebase`, `nextauth`, `aws`, `cloudflare`, `payments`) per the schema in
`README.md` instead of the Supabase-specific Steps 4–5 below.

---

## Step 2: Endpoint Discovery

Use the detected hosting platform to locate handler files.

### Netlify

Glob: `**/netlify/functions/*.{js,ts,mjs}`

Each matched file is one endpoint. The path is `/{filename_without_extension}`.

### Vercel

Glob: `api/**/*.{js,ts}`

The path is `/{relative_path_without_extension}` (e.g., `api/foo/bar.ts` →
`/foo/bar`).

### Other / unknown hosting

Fall back to: `**/functions/*.{js,ts}` and `**/api/*.{js,ts}`. Note in a
comment that the hosting platform could not be determined.

### HTTP method

Read each handler file and look for an explicit `method: "GET"` or similar
declaration. Default to `POST` if none is found.

---

## Step 3: Auth Classification

For each discovered endpoint, read the handler source and classify using the
first matching rule below (checked in order):

| Pattern in source | Classification |
|-------------------|----------------|
| `webhook` / `svix.verify` / `stripe.webhooks.constructEvent` | `webhook` |
| `checkout` / `createCheckoutSession` | `payment` |
| `verifyInternalCall` / `x-internal-secret` | `internal` |
| `verifyAuthOrAnon` / `verifyOptionalAuth` | `anonymous` |
| `verifyAuth` / `requireAuth` / `verifyToken` | `authenticated` |
| (none of the above) | `unknown` — add a comment with the file path |

Place each endpoint under the matching key in the `endpoints:` block:

```yaml
endpoints:
  authenticated:
    - path: /my-endpoint
      method: POST
  webhook:
    - path: /clerk-webhook
      method: POST
      signature: svix   # svix | stripe
  payment:
    - path: /create-checkout-session
      method: POST
  internal:
    - path: /notify-user
      method: POST
  anonymous:
    - path: /public-feed
      method: POST
  # unknown endpoints (if any):
  unknown:
    - path: /mystery-endpoint
      method: POST
      auth: "unknown  # path/to/mystery-endpoint.js"
```

---

## Step 4: Supabase / Database Discovery

Perform this step only if `stack.database == supabase`.

### Tables

Grep all `.js`, `.ts`, `.mjs`, and `.py` files for:

```
\.from\("([^"]+)"\)
```

Collect all unique capture groups as table names.

### Storage buckets

Grep the same files for:

```
\.storage\.from\("([^"]+)"\)
```

Collect bucket names and remove them from the table list.

### RPCs

Grep for:

```
\.rpc\("([^"]+)"
```

List each unique name under `supabase_rpcs.client_callable`. Assign
`risk: unknown` initially; escalate to `risk: high` for mutations that bypass
user-scoping (e.g., `merge_anon_session`, `replace_document_body`).

### Table primary keys

Grep `**/migrations/*.sql` for inline `PRIMARY KEY` declarations:

```sql
CREATE TABLE uploads (
  upload_id uuid PRIMARY KEY ...
```

Populate `supabase.table_pks` with `table_name: pk_column`.

### Supabase block template

```yaml
supabase:
  project_url: "https://YOUR_PROJECT.supabase.co"
  anon_key: "eyJ..."
  storage_buckets:
    - user-files
  tables:
    user_facing:
      - uploads
      - entry_lines
    public_read_only: []
    service_role_only: []
  table_pks:
    uploads: upload_id
```

---

## Step 5: Feature Detection

Search all source files for these patterns and set the corresponding flag:

| Pattern | Flag |
|---------|------|
| `anon_session` or `x-anon-session` | `features.anon_sessions: true` |

If a pattern is absent, omit the flag (do not set it to `false`).

---

## Step 6: Assemble Profile

Combine all discovered data into a YAML profile following this template. Fill in
every `# TODO` placeholder before saving.

```yaml
target:
  base_url: "https://YOUR_DOMAIN.com"   # TODO: fill in
  api_prefix: "/.netlify/functions"     # adjust per hosting

stack:
  auth: clerk
  database: supabase
  payments: stripe
  hosting: netlify
  storage: supabase

supabase:
  project_url: "https://YOUR_PROJECT.supabase.co"  # TODO
  anon_key: "eyJ..."                               # TODO
  storage_buckets:
    - user-files
  tables:
    user_facing:
      - uploads
    public_read_only: []
    service_role_only: []
  table_pks:
    uploads: upload_id

clerk:
  frontend_api: "https://YOUR_INSTANCE.clerk.accounts.dev"  # TODO

endpoints:
  authenticated: []
  anonymous: []
  webhook: []
  internal: []
  payment: []

supabase_rpcs:
  client_callable:
    - name: merge_anon_session
      params: [anon_id]
      risk: high
  server_only: []

source_file_map:
  /my-endpoint: "react-app/netlify/functions/my-endpoint.js"

features:
  anon_sessions: true

test_accounts:
  user_a:
    email: "pentest-a@example.com"
  user_b:
    email: "pentest-b@example.com"
```

Save the file as `profiles/<project-name>.yaml` inside the StackBadger
directory.

---

## Step 7: Validate

### Automated check

```bash
python -c "
import sys; sys.path.insert(0, '.')
from profile import load_profile
p = load_profile('profiles/<your-profile>.yaml')
print('OK — base_url:', p.target.base_url)
"
```

A clean run prints `OK — base_url: ...` with no tracebacks or warnings.

### Cross-check with discover.py

Run the automated discovery script and diff against your hand-built profile:

```bash
python discover.py /path/to/project --output /tmp/discovered.yaml
diff profiles/<your-profile>.yaml /tmp/discovered.yaml
```

Items present in `discover.py` output but missing from your profile are
candidates you may have overlooked. Items present only in your profile (e.g.,
`supabase.tables.service_role_only`, `risk` overrides, `probe_body` entries)
are expected — they require human judgment and should stay.

### Checklist

- [ ] `target.base_url` is a real URL, not the placeholder.
- [ ] Every endpoint in `source_file_map` maps to an existing file path relative
      to the project root.
- [ ] All `# TODO` placeholders are resolved or deliberately left for later.
- [ ] `supabase.project_url` and `anon_key` are filled (or explicitly marked
      `# TODO` if running in offline mode).
- [ ] No `auth: unknown` entries remain (investigate each one).
- [ ] `load_profile` runs without warnings.
