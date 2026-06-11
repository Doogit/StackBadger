"""Unit tests for the live-suite placeholder-target gate.

``_is_placeholder_target`` (in ``tests/conftest.py``) decides whether the entire
live probe suite is skipped for a given ``target.base_url``. Because a wrong
answer either skips a real target's security probes (false negative) or fires
live HTTP at a reserved placeholder (the 64-failure noise this gate exists to
prevent), the matcher ships with explicit match / no-match vectors per the
project's [RX-TEST] rule.

These are pure-function tests: they import the helper directly and do not touch
the network or the ``profile`` fixture.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# conftest.py lives in this directory; ensure it is importable by name.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from conftest import _is_placeholder_target  # noqa: E402


# Hosts that ARE reserved placeholders -> live suite must skip.
PLACEHOLDER_URLS = [
    "https://example.com",
    "http://example.com",
    "https://www.example.com",          # subdomain (IANA-owned, cannot be a real target)
    "https://sub.deep.example.com",     # deeper subdomain
    "https://example.org",
    "https://example.net",
    "https://example.edu",
    "https://foo.example",              # RFC 6761 reserved .example TLD
    "https://example",                  # bare reserved label
    "https://EXAMPLE.COM",              # case-insensitive
    "https://example.com.",             # trailing-dot FQDN form
    "https://user@example.com",         # userinfo is stripped by urlparse
    "https://example.com:8443",         # explicit port
    "https://example.com/import-csv",   # path does not affect host
    # ``your-*`` shipped-example convention, scoped to managed-platform suffixes.
    "https://your-firebase-app.web.app",
    "https://your-project.supabase.co",
    "https://your-app.vercel.app",
    "https://YOUR-FIREBASE-APP.WEB.APP",  # case-insensitive
]


# Hosts that are NOT placeholders -> live suite must run.
REAL_URLS = [
    "https://notexample.com",           # similar prefix, different host
    "https://myexample.com",
    "https://example.com.evil.com",     # attacker-shaped: real host is *.evil.com
    "https://example.com@evil.com",     # userinfo trick: real host is evil.com
    "https://api.acme.com",
    "https://staging.acme.io",
    "https://localhost:8888",
    "https://your-company.com",          # real target that merely starts with "your-"
    "https://your-app.io",               # "your-" prefix off a managed-platform suffix
    "",                                  # empty
]


@pytest.mark.parametrize("url", PLACEHOLDER_URLS)
def test_placeholder_hosts_match(url):
    assert _is_placeholder_target(url) is True, f"{url!r} should be treated as a placeholder"


@pytest.mark.parametrize("url", REAL_URLS)
def test_real_hosts_do_not_match(url):
    assert _is_placeholder_target(url) is False, f"{url!r} should be treated as a real target"


def test_scheme_less_input_is_not_detected():
    """Documents a known limitation: a scheme-less host parses with no netloc.

    ``urlparse("example.com").hostname`` is ``None`` (the value is read as a
    path), so the gate returns False and the live suite would run. Profiles are
    expected to carry a fully-qualified URL with a scheme, so this is acceptable;
    the test pins the behavior so any future change to it is deliberate.
    """
    assert _is_placeholder_target("example.com") is False
