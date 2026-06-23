# Engagement Authorization (TEMPLATE)

> Copy this file to `AUTHORIZATION.md` and fill it in before running StackBadger
> against any target. `AUTHORIZATION.md` is gitignored so a real, client-identifying
> scope never gets committed. **No filled-in authorization = do not run.**

## Authorizing party
- Name / title:
- Organization (owner of the target):
- Email / phone:
- Signature + date:

## In-scope targets
List exact base URLs, domains, subdomains, IP ranges, and APIs that are authorized.
These are what you put in `target.base_url` / the CLI `<url>` argument.
-

## Explicit exclusions
Hosts, paths, and especially production data stores that must NOT be touched.
Exclusions carry equal weight to inclusions.
-

## Testing window
- Permitted dates/times (with time zone):

## Permitted mode (maps to StackBadger flags)
- [ ] Read-only (default) — safe against production
- [ ] Full write probes (`--full`) — authorized only against: <environment>
- [ ] Branch DB (`--branch`) — Supabase disposable branch, requires `SUPABASE_ACCESS_TOKEN`
- [ ] ZAP active scan permitted (omit `--skip-zap`)

## Cloud / third-party authorization
If the target runs on AWS/Azure/GCP or other managed platforms, confirm compliance
with that provider's penetration-testing policy.
-

## Communication plan
- Primary contact during testing:
- Emergency contact (outage or critical finding mid-run):
- Escalation procedure:
