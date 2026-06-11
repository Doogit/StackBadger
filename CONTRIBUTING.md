# Contributing to StackBadger

Thanks for your interest in improving StackBadger. This is a portable,
profile-driven API-security harness, and contributions that keep it
stack-agnostic and safe-by-default are especially welcome.

## Before you start

- Read [SECURITY.md](SECURITY.md). StackBadger is an active offensive scanner —
  only ever point it at systems you own or are authorized to test, including
  while developing the tool itself.
- Keep the harness **portable**. Probes and tests must derive every target
  detail (endpoints, tables, RPCs, buckets) from the active profile. Never
  hardcode a name from one specific application.
- Keep the default **read-only**. New write/mutation probes must be marked
  `@pytest.mark.write_probe` so they only run under `--full`.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .
```

## Running the tests

The suite is profile-driven. Run it against each shipped example profile and
confirm live probes skip cleanly (the example profiles use reserved placeholder
hosts, so no real target is contacted):

```bash
python -m pytest tests/ --profile profiles/clerk-supabase-example.yaml
python -m pytest tests/ --profile profiles/firebase-example.yaml
```

## Adding support for a new stack

1. Add an auth adapter under `auth/` (subclass the abstract adapter) if the
   stack introduces a new auth provider.
2. Wire any new provider fingerprints into `discover.py`.
3. Add a small example profile under `profiles/` using only placeholder hosts
   (`example.com`, `your-*.<managed-platform>`), following the structure and
   comment style of the existing examples.
4. Confirm the new profile loads and skips live tests:
   `python -m pytest tests/ --profile profiles/<new>.yaml`.

## Pull requests

- Keep changes focused and include tests for new behavior.
- Run the full suite against the example profiles before opening a PR.
- Describe what you changed and why, and note any change to default safety
  behavior (read-only vs. write probes).
