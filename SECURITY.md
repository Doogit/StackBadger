# Security Policy

## Responsible use — authorization required

StackBadger is an **active offensive security scanner**. It signs in as a real
user, enumerates endpoints, and sends auth-bypass, IDOR, access-control,
injection, and misconfiguration probes at a live target — and in `--full` mode it
attempts state-changing writes. Running it against a system is a security test,
not a passive observation.

**Only run StackBadger against systems you own or are explicitly authorized, in
writing, to test.** Unauthorized scanning of computer systems is illegal in many
jurisdictions (for example, the U.S. Computer Fraud and Abuse Act and equivalent
laws elsewhere) and may also breach the terms of service of the target's hosting,
auth, database, and payment providers. You are solely responsible for ensuring
you have permission before pointing this tool at any host.

Before you run a scan:

- Confirm you have explicit, documented authorization covering the exact target,
  the test window, and the techniques involved (including write probes if you
  use `--full`).
- Use a staging or non-production environment whenever possible.
- Provision dedicated, disposable test accounts rather than real user accounts.
- Coordinate with the system owner so your traffic is not mistaken for a real
  attack.

## What `--full` (write probes) actually does

The default mode is **read-only**: probes assert security controls from HTTP
response codes only — no INSERT/UPDATE/DELETE and no file uploads reach the
target. It is the safe default.

`--full --yes` enables write probes (marked `@pytest.mark.write_probe`). These
attempt real mutations — inserts, updates, deletes, and file uploads — using
sentinel UUIDs. If the target's access controls are misconfigured, **data can be
created, modified, or deleted**, and uploaded objects may persist. Treat `--full`
as a destructive operation: run it only against a non-production environment, or
a disposable Supabase branch via `--branch`, and only with authorization that
explicitly covers write testing.

## Reporting a vulnerability in StackBadger itself

This policy is about vulnerabilities in **StackBadger**, not in the systems you
scan with it.

If you discover a security issue in StackBadger (for example, a flaw that could
leak captured credentials or scan target data, or cause the harness to behave
unsafely), please report it privately rather than opening a public issue:

- Use GitHub's **"Report a vulnerability"** flow (Security → Advisories) on this
  repository to open a private security advisory.

Please include a description, reproduction steps, and the impact you observed.
We will acknowledge the report and work with you on a fix and coordinated
disclosure.
