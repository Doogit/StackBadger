---
description: Run StackBadger's offline self-tests against the shipped example profiles (no live target).
---
Run the harness self-tests. These contact no real site — example profiles use reserved placeholder
hosts, so live probes skip and only the offline machinery (adapters, discovery, scrubbing,
aggregation, profile assembly) executes.

Use the venv interpreter:
1. `.venv\Scripts\python.exe -m pytest tests/ --profile profiles/clerk-supabase-example.yaml -q`
2. `.venv\Scripts\python.exe -m pytest tests/ --profile profiles/firebase-example.yaml -q`

If $ARGUMENTS names a single module (e.g. `test_idor`), run only that module against the first
profile with `-v` instead. Report pass/fail/skip counts and surface any non-skip failure.
