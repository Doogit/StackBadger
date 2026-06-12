#!/usr/bin/env python3
"""teardown.py — remove the seeded StackBadger test accounts.

Usage:
    python teardown.py [--project-url URL]

Thin wrapper over ``provision_accounts.py --cleanup``: deletes the two test
accounts by the user IDs ``provision_accounts.py`` stored in ``.env``
(``PENTEST_USER_A_ID`` / ``PENTEST_USER_B_ID``) via the GoTrue Admin API —
falling back to a lookup by the script's own deterministic
``stackbadger-pentest-*`` emails when a failed run never stored the IDs —
then clears the stored values. Idempotent — running it again (or with nothing
provisioned) is a no-op that exits 0. A failed deletion exits 1 and names
what is still standing; ``--provider clerk|firebase|nextauth`` exits 2 after
printing where to delete manually (this script only automates Supabase).

What teardown does NOT cover (by design):

- **Branch databases** are deleted by ``run.sh``'s exit trap (``--branch``
  mode), not here.
- **Full-mode sentinel writes against a non-branch target**: write probes only
  mutate state when a security control failed — each successful write is
  itself a reported finding with evidence in ``reports/``. There is no
  generic, safe way to delete app-level rows from the outside; clean those up
  in the target app guided by the findings report.

Run this after every provisioned run — the seeded accounts are real,
confirmed users in the target's auth system and must not outlive the test.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if "--cleanup" not in argv:
        argv = ["--cleanup", *argv]
    from provision_accounts import main as provision_main

    return provision_main(argv)


if __name__ == "__main__":
    sys.path.insert(0, str(_SCRIPT_DIR))
    sys.exit(main())
