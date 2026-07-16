#!/usr/bin/env python3
"""Expiry-enforcing wrapper around ``pip-audit`` for the SCA CI gate.

``pip-audit`` has no native allowlist-file, expiry, or severity semantics
(``--ignore-vuln`` is a per-id CLI flag only). This wrapper makes the
time-boxed allowlist real:

  1. Read ``.github/pip-audit-allowlist.txt``.
  2. Drop any entry whose ``expires:`` date is today or in the past, so
     ``pip-audit`` re-flags that advisory and the job fails. This is what makes
     expiry enforced rather than decorative.
  3. Expand the surviving ids to repeated ``--ignore-vuln <ID>`` args.
  4. Invoke ``pip-audit`` against the installed environment and propagate its
     exit code.

A malformed allowlist line fails loudly (non-zero) rather than being silently
skipped: a typo must never silently widen suppression.

Allowlist line format (one entry per line):

    <VULN-ID>  # expires:YYYY-MM-DD — <justification>

Blank lines and full-line ``#`` comments are ignored.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

# <VULN-ID>  # expires:YYYY-MM-DD <justification>
# The id is any non-whitespace run (GHSA-…, PYSEC-…, CVE-…). The comment must
# begin with an ``expires:`` date; the justification tail is free text.
_ENTRY_RE = re.compile(
    r"^(?P<id>\S+)\s+#\s*expires:(?P<date>\d{4}-\d{2}-\d{2})\b.*$"
)


class AllowlistError(Exception):
    """A malformed allowlist line — fail loudly, never suppress silently."""


def parse_allowlist(text: str, today: datetime.date) -> list[str]:
    """Return the vuln ids to ``--ignore-vuln``, dropping expired entries.

    Raises ``AllowlistError`` on any malformed non-comment line.
    """
    ids: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        m = _ENTRY_RE.match(line)
        if m is None:
            raise AllowlistError(
                f"malformed allowlist line {lineno}: {raw!r}\n"
                "expected: <VULN-ID>  # expires:YYYY-MM-DD — <justification>"
            )

        try:
            expires = datetime.date.fromisoformat(m.group("date"))
        except ValueError as exc:
            raise AllowlistError(
                f"invalid expires date on line {lineno}: {raw!r} ({exc})"
            ) from exc

        vuln_id = m.group("id")
        if expires <= today:
            # Expired: do NOT suppress. pip-audit re-flags it and the job fails.
            print(
                f"pip-audit-allowlist: entry {vuln_id} expired on {expires} "
                f"(today {today}); no longer suppressed.",
                file=sys.stderr,
            )
            continue

        ids.append(vuln_id)
    return ids


def build_args(ids: list[str]) -> list[str]:
    """Base ``pip-audit`` invocation plus one ``--ignore-vuln`` per surviving id."""
    args = ["pip-audit", "--strict"]
    for vuln_id in ids:
        args += ["--ignore-vuln", vuln_id]
    return args


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=Path(".github/pip-audit-allowlist.txt"),
        help="path to the allowlist file",
    )
    args = parser.parse_args(argv)

    try:
        text = args.allowlist.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(
            f"pip-audit-allowlist: allowlist file not found: {args.allowlist}",
            file=sys.stderr,
        )
        return 2

    try:
        ids = parse_allowlist(text, datetime.date.today())
    except AllowlistError as exc:
        print(f"pip-audit-allowlist: {exc}", file=sys.stderr)
        return 2

    cmd = build_args(ids)
    if ids:
        print(
            "pip-audit-allowlist: suppressing "
            + ", ".join(ids)
            + " (unexpired allowlist entries).",
            file=sys.stderr,
        )
    print("pip-audit-allowlist: running: " + " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
