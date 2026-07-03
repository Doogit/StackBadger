"""Pytest configuration and fixtures for the pentest harness.

Fixtures
--------
Session-scoped (created once per pytest run):
    profile         — parsed YAML profile (_AttrDict with attribute access)
    auth_adapter    — AbstractAuthAdapter (profile-driven); skips if auth env vars are absent
    evidence_dir    — pathlib.Path to reports/evidence/ (created if needed)

Function-scoped (fresh per test):
    anon_client     — httpx.Client with Supabase anon headers only
    user_a_client   — httpx.Client with user_a Bearer token
    user_b_client   — httpx.Client with user_b Bearer token
    api_client      — httpx.Client targeting Netlify Functions base URL
    evidence        — EvidenceCapture bound to the current test node

Conditional skip hooks
-----------------------
Tests decorated with @pytest.mark.clerk / .supabase / .stripe are skipped
automatically when the active profile's stack does not include that component.

The session-scoped ``profile`` fixture additionally skips every live test when
target.base_url resolves to a reserved example/placeholder host (see
``_is_placeholder_target``), so running the shipped example profile produces
skips rather than live-probe failures. Offline unit tests do not consume the
``profile`` fixture and still run.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
import re as _re
from typing import Iterable, Optional
from urllib.parse import urlparse

import httpx
import pytest

# ---------------------------------------------------------------------------
# Resolve the StackBadger package root so imports work regardless of the
# current working directory when pytest is invoked.
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent          # tests/
_PKG_ROOT = _HERE.parent                         # StackBadger/
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from auth import create_adapter  # noqa: E402
from auth.base import AuthConfigError  # noqa: E402
from exclusions import (  # noqa: E402
    effective_exclude_paths,
    effective_exclude_tables,
    is_excluded_path,
    is_excluded_table,
)
from profile import load_profile  # noqa: E402
from profile_assembler import assemble_profile  # noqa: E402
from reports.ledger import (  # noqa: E402
    extract_marker_sidecar,
    sidecar_path_for,
    write_sidecar,
)
from reports.scrub import scrub_evidence_body, scrub_locator  # noqa: E402


# ---------------------------------------------------------------------------
# pytest CLI option
# ---------------------------------------------------------------------------

def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--profile",
        action="store",
        default=None,
        help="Path to the YAML site profile (required)",
    )


# ---------------------------------------------------------------------------
# Custom marker registration
# ---------------------------------------------------------------------------

def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "clerk: test requires Clerk auth stack")
    config.addinivalue_line("markers", "supabase: test requires Supabase database stack")
    config.addinivalue_line("markers", "stripe: test requires Stripe payments stack")
    config.addinivalue_line("markers", "storage: test requires Supabase storage")
    config.addinivalue_line(
        "markers",
        "write_probe: test sends INSERT/UPDATE/DELETE/upload requests "
        "(skipped in read-only mode; use --full to enable)",
    )
    # Provider-specific markers (multi-stack support)
    config.addinivalue_line("markers", "firebase_auth: test requires Firebase Auth stack")
    config.addinivalue_line("markers", "firestore: test requires Firestore database")
    config.addinivalue_line("markers", "firebase_storage: test requires Firebase Storage")
    config.addinivalue_line("markers", "supabase_auth: test requires Supabase Auth (GoTrue)")
    config.addinivalue_line("markers", "nextauth: test requires NextAuth / Auth.js")
    config.addinivalue_line("markers", "s3: test requires S3-compatible storage (S3 or R2)")
    config.addinivalue_line("markers", "paddle: test requires Paddle payments")
    config.addinivalue_line("markers", "lemonsqueezy: test requires LemonSqueezy payments")
    # ASVS 5.0 scope axis (orthogonal to the read-only/write safety axis).
    # asvs_extended gates heavy probes behind SCAN_SCOPE=asvs; asvs()/cwe()
    # carry the requirement/CWE ids the coverage ledger joins on (Tier-2).
    config.addinivalue_line(
        "markers",
        "asvs_extended: heavy ASVS-scope probe; deselected unless SCAN_SCOPE=asvs",
    )
    config.addinivalue_line(
        "markers",
        "asvs(id): ASVS 5.0 requirement id(s) this probe exercises (coverage ledger)",
    )
    config.addinivalue_line(
        "markers",
        "cwe(id): CWE id(s) this probe exercises (CASA grading unit, coverage ledger)",
    )


# ---------------------------------------------------------------------------
# Conditional skip hook — runs after collection
# ---------------------------------------------------------------------------

def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip tests whose stack marker does not match the active profile,
    and skip write_probe tests when PENTEST_MODE is not 'full'."""

    # --- write_probe gating ---
    pentest_mode = os.environ.get("PENTEST_MODE", "read-only")
    if pentest_mode != "full":
        skip_write = pytest.mark.skip(
            reason="Skipped in read-only mode (use --full to enable write probes)"
        )
        for item in items:
            if item.get_closest_marker("write_probe"):
                item.add_marker(skip_write)

    # --- scope-axis gating (orthogonal to the write_probe safety axis) ---
    # SCAN_SCOPE=core (default) deselects asvs_extended probes; SCAN_SCOPE=asvs
    # runs the full set. Skip-with-reason (not deselect) keeps the skip auditable
    # in the report, mirroring the write_probe block above.
    scan_scope = os.environ.get("SCAN_SCOPE", "core")
    if scan_scope != "asvs":
        skip_extended = pytest.mark.skip(
            reason="Skipped in core scope (set SCAN_SCOPE=asvs to enable extended ASVS probes)"
        )
        for item in items:
            if item.get_closest_marker("asvs_extended"):
                item.add_marker(skip_extended)

    # --- stack-marker gating ---
    profile_path = config.getoption("--profile")
    try:
        profile = load_profile(profile_path)
    except Exception:
        # If the profile cannot be loaded, let fixtures handle the error.
        return

    stack_map = {
        "clerk": (profile.stack and profile.stack.auth) or "",
        "supabase": (profile.stack and profile.stack.database) or "",
        "stripe": (profile.stack and profile.stack.payments) or "",
        "storage": (profile.stack and profile.stack.storage) or "",
    }

    # All stack markers require an exact provider match.  The storage marker
    # requires "supabase" specifically because the storage tests call
    # profile.supabase.* and Supabase Storage endpoints directly.  On profiles
    # with a non-Supabase storage backend (e.g. S3), these tests must skip.
    exact_match_markers = {"clerk", "supabase", "stripe", "storage"}
    # storage tests require supabase as the storage provider.
    storage_required_value = "supabase"

    # --- Provider-specific markers (multi-stack) ---
    # Each entry maps marker name -> (stack field, expected value or callable).
    # Callable receives the active value and returns True if the marker matches.
    _PROVIDER_MARKERS: dict[str, tuple] = {
        "firebase_auth":    ("auth", "firebase"),
        "firestore":        ("database", "firestore"),
        "firebase_storage": ("storage", "firebase"),
        "supabase_auth":    ("auth", "supabase-auth"),
        "nextauth":         ("auth", "nextauth"),
        "s3":               ("storage", lambda v: v in ("s3", "r2"), "s3 or r2"),
        "paddle":           ("payments", lambda v: "paddle" in (v if isinstance(v, list) else [v]), "paddle"),
        "lemonsqueezy":     ("payments", lambda v: "lemonsqueezy" in (v if isinstance(v, list) else [v]), "lemonsqueezy"),
    }

    for item in items:
        skipped = False

        # Legacy stack_map markers (clerk, supabase, stripe, storage)
        for marker_name, active_value in stack_map.items():
            if item.get_closest_marker(marker_name):
                required = storage_required_value if marker_name == "storage" else marker_name
                if isinstance(active_value, list):
                    should_skip = required.lower() not in [v.lower() for v in active_value]
                else:
                    should_skip = active_value.lower() != required.lower() if active_value else True

                if should_skip:
                    item.add_marker(
                        pytest.mark.skip(
                            reason=(
                                f"Skipped: profile stack.{_marker_field(marker_name)} "
                                f"is '{active_value or '(empty)'}', "
                                f"requires '{marker_name}'"
                            )
                        )
                    )
                    skipped = True
                    break

        if skipped:
            continue

        # Provider markers — check against profile.stack fields
        for marker_name, marker_spec in _PROVIDER_MARKERS.items():
            field, expected = marker_spec[0], marker_spec[1]
            expected_desc = marker_spec[2] if len(marker_spec) > 2 else (
                expected if isinstance(expected, str) else getattr(expected, '__doc__', None) or 'matching provider'
            )
            if not item.get_closest_marker(marker_name):
                continue
            active_value = stack_map.get(field, "") or (
                getattr(profile.stack, field, "") if hasattr(profile, "stack") and profile.stack else ""
            )
            if callable(expected):
                matches = expected(active_value) if active_value else False
            else:
                matches = active_value.lower() == expected.lower() if active_value else False

            if not matches:
                item.add_marker(
                    pytest.mark.skip(
                        reason=(
                            f"Skipped: profile stack.{field} "
                            f"is '{active_value or '(empty)'}', "
                            f"marker '{marker_name}' requires '{expected_desc}'"
                        )
                    )
                )
                break


def _marker_field(marker_name: str) -> str:
    """Map marker name to its profile.stack field name."""
    return {
        "clerk": "auth",
        "supabase": "database",
        "stripe": "payments",
        "storage": "storage",
    }.get(marker_name, marker_name)


def pytest_collection_finish(session: pytest.Session) -> None:
    """Emit the ASVS/CWE marker sidecar — the coverage-ledger input (Tier-2).

    ``pytest-json-report`` records marker *names* but not their *arguments*, so
    the ``asvs(id)`` / ``cwe(id)`` ids are captured here at collection time (when
    every collected node — including ones about to skip — is visible with its
    markers) and joined against pass/skip/fail outcomes by ``reports.ledger``.

    Gated on ``SCAN_SCOPE=asvs`` so core/CI runs stay byte-identical: the ledger
    only runs under asvs scope. The sidecar path mirrors ``--json-report-file``
    (suffix-swapped) so run.sh's timestamped report and its sidecar co-locate.
    A write failure is warned, never fatal — the sidecar is auxiliary to the scan.
    """
    if os.environ.get("SCAN_SCOPE", "core") != "asvs":
        return
    json_report_file = session.config.getoption("json_report_file", default=None)
    dest = sidecar_path_for(json_report_file or "report.json")
    try:
        write_sidecar(extract_marker_sidecar(session.items), dest)
    except OSError as exc:
        print(f"[warn] Could not write ASVS marker sidecar to {dest}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

# RFC 2606 / 6761 reserved example domains. The shipped example profile points
# target.base_url at https://example.com as a *structural* placeholder (copy it,
# then repoint base_url at your own site). Live probes against a reserved example
# host produce noise rather than findings -- example.com serves no security
# headers and returns 405 to every POST -- so when the target resolves to one of
# these hosts we skip the live suite instead of emitting spurious failures. The
# offline unit tests (adapters, scrubbing, discovery) do not consume this fixture
# and still run. Point base_url at a real deployment to enable the live tests.
_PLACEHOLDER_HOSTS = ("example.com", "example.org", "example.net", "example.edu")

# Managed-platform suffixes where a ``your-*`` host is unambiguously a shipped
# example placeholder (e.g. ``your-firebase-app.web.app``). Used to scope the
# ``your-*`` placeholder heuristic so a real target like ``your-company.com``
# is still scanned.
_EXAMPLE_PLATFORM_SUFFIXES = (
    "web.app",
    "firebaseapp.com",
    "supabase.co",
    "vercel.app",
    "netlify.app",
    "appspot.com",
    "pages.dev",
)


def _is_placeholder_target(base_url: str) -> bool:
    """Return True when base_url's host is a reserved example/placeholder domain.

    Two placeholder conventions are recognised so every shipped example profile
    produces skips rather than live-probe noise:
      1. RFC 2606/6761 reserved example domains (example.com, .example, ...).
      2. The ``your-*`` first-label convention used by the example profiles
         (e.g. ``your-firebase-app.web.app``, ``your-project.supabase.co``),
         but ONLY when the host also sits on a known managed-platform suffix.
         These resolve to real hosts that 404 every probe, so treat them as
         placeholders. The suffix guard keeps a genuine target that merely
         starts with ``your-`` (e.g. ``your-company.com``) from being silently
         skipped — a no-op pentest is worse than a noisy one. Point
         target.base_url at a real deployment to enable the live tests.
    """
    # rstrip(".") canonicalizes the fully-qualified form (e.g. "example.com.").
    host = (urlparse(base_url).hostname or "").lower().rstrip(".")
    if not host:
        return False
    if host == "example" or host.endswith(".example"):
        return True
    first_label = host.split(".", 1)[0]
    if (first_label == "your" or first_label.startswith("your-")) and any(
        host.endswith(suffix) for suffix in _EXAMPLE_PLATFORM_SUFFIXES
    ):
        return True
    return any(host == h or host.endswith("." + h) for h in _PLACEHOLDER_HOSTS)


def _skip_if_placeholder_target(base_url: str) -> None:
    """Skip the requesting (live) test when the target is a placeholder host."""
    if _is_placeholder_target(base_url):
        pytest.skip(
            f"Target base_url '{base_url}' is a reserved example/placeholder host; "
            "live probes skipped. Point target.base_url at a real deployment "
            "(or run a URL-only black-box scan via run.sh) to enable them."
        )


@pytest.fixture(scope="session")
def profile(request: pytest.FixtureRequest):
    """Return the session site profile (structural YAML + live-discovered config).

    Normal pentest runs go through run.sh, which performs the single live
    discovery crawl, freezes the fully-assembled profile to a temp YAML, and
    points --profile at it with PENTEST_PROFILE_FROZEN set. In that case the
    fixture loads that artifact directly (no second crawl) so pytest stays on
    the exact stack the rest of the run used.

    A direct ``pytest --profile foo.yaml`` invocation (no run.sh, flag unset)
    instead calls assemble_profile to auto-discover the Supabase URL / anon key
    from the target's JS bundle and merges them with the YAML structural data.
    """
    profile_path = request.config.getoption("--profile")
    if profile_path is None:
        raise ValueError(
            "A profile is required. Pass --profile=<path/to/profile.yaml> when invoking pytest."
        )
    # Honor the freeze signal only for the exact artifact run.sh assembled and
    # exported as PENTEST_PROFILE. Gating on the path (not just the boolean)
    # stops a stale PENTEST_PROFILE_FROZEN left in the shell from a prior run.sh
    # from silently skipping discovery when a developer later runs
    # `pytest --profile some-raw.yaml` directly against a raw YAML.
    if os.environ.get("PENTEST_PROFILE_FROZEN") and profile_path == os.environ.get(
        "PENTEST_PROFILE"
    ):
        frozen = load_profile(profile_path)
        if not (frozen.target and frozen.target.base_url):
            raise ValueError(
                f"Frozen profile {profile_path} is missing target.base_url — "
                "run.sh's discovery/freeze step produced an incomplete artifact."
            )
        _skip_if_placeholder_target(frozen.target.base_url)
        return frozen
    yaml_prof = load_profile(profile_path)
    target_url = (yaml_prof.target and yaml_prof.target.base_url) or ""
    if not target_url:
        raise ValueError(
            "Profile must have target.base_url set. "
            "Add target.base_url to the YAML profile."
        )
    _skip_if_placeholder_target(target_url)
    return assemble_profile(target_url, yaml_path=profile_path)


@pytest.fixture(scope="session")
def auth_adapter(profile):
    """Return an auth adapter via create_adapter(profile), or skip on config error.

    Only ``AuthConfigError`` (missing env vars, unsupported provider, etc.)
    triggers a skip.  All other exceptions propagate as test failures so that
    real adapter regressions are not silently swallowed.

    Individual user fixtures (user_a_client, user_b_client) check their own
    JWT env var so partial runs (e.g. only User A) remain possible.
    """
    try:
        adapter = create_adapter(profile)
    except AuthConfigError as exc:
        pytest.skip(f"Auth adapter unavailable: {exc}")
    yield adapter
    if hasattr(adapter, "close"):
        adapter.close()


@pytest.fixture(scope="session")
def evidence_dir() -> Path:
    """Create and return the reports/evidence/ directory path."""
    # Place evidence relative to the package root so it is predictable.
    reports_path = _PKG_ROOT / "reports" / "evidence"
    reports_path.mkdir(parents=True, exist_ok=True)
    return reports_path


# ---------------------------------------------------------------------------
# Function-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def anon_client(profile) -> httpx.Client:
    """httpx.Client with Supabase anon headers only (no user auth)."""
    headers: dict[str, str] = {}
    if profile.supabase and profile.supabase.anon_key:
        headers["apikey"] = profile.supabase.anon_key
        headers["Authorization"] = f"Bearer {profile.supabase.anon_key}"
    base_url = (profile.target and profile.target.base_url) or ""
    with httpx.Client(base_url=base_url, headers=headers, timeout=30.0) as client:
        yield client


@pytest.fixture()
def user_a_client(profile, auth_adapter) -> httpx.Client:
    """httpx.Client that injects fresh user_a Bearer token before each request.

    Authentication is acquired via FAPI sign-in (from PENTEST_USER_A_EMAIL +
    PENTEST_USER_A_PASSWORD env vars). No pre-exported JWT is required.
    """
    # Verify the adapter can serve user_a (has credentials for it).
    if not _adapter_has_account(auth_adapter, "user_a"):
        pytest.skip("user_a_client unavailable — no credentials for user_a")
    base_url = (profile.target and profile.target.base_url) or ""
    with _AuthedClient(base_url=base_url, adapter=auth_adapter, account="user_a", timeout=30.0) as client:
        yield client


@pytest.fixture()
def user_b_client(profile, auth_adapter) -> httpx.Client:
    """httpx.Client that injects fresh user_b Bearer token before each request.

    Authentication is acquired via FAPI sign-in (from PENTEST_USER_B_EMAIL +
    PENTEST_USER_B_PASSWORD env vars). No pre-exported JWT is required.
    """
    if not _adapter_has_account(auth_adapter, "user_b"):
        pytest.skip("user_b_client unavailable — no credentials for user_b")
    base_url = (profile.target and profile.target.base_url) or ""
    with _AuthedClient(base_url=base_url, adapter=auth_adapter, account="user_b", timeout=30.0) as client:
        yield client


def _adapter_has_account(adapter, account_name: str) -> bool:
    """Check if the auth adapter has credentials for the given account."""
    # ClerkAuthAdapter stores sessions keyed by account name.
    sessions = getattr(adapter, "_sessions", None)
    if sessions is not None:
        return account_name in sessions
    # Fallback: try to detect via env var presence (backward compat).
    prefix = {"user_a": "PENTEST_USER_A", "user_b": "PENTEST_USER_B"}.get(account_name, "")
    return bool(os.environ.get(f"{prefix}_EMAIL") or os.environ.get(f"{prefix}_JWT"))


@pytest.fixture()
def api_client(profile) -> httpx.Client:
    """httpx.Client targeting the Netlify Functions base URL."""
    base_url = (profile.target and profile.target.base_url) or ""
    api_prefix = (profile.target and profile.target.api_prefix) or "/.netlify/functions"
    full_base = base_url.rstrip("/") + api_prefix
    with httpx.Client(base_url=full_base, timeout=30.0) as client:
        yield client


@pytest.fixture()
def evidence(request: pytest.FixtureRequest, evidence_dir: Path) -> "EvidenceCapture":
    """EvidenceCapture bound to the current test; auto-saves on failure."""
    cap = EvidenceCapture(node_id=request.node.nodeid, evidence_dir=evidence_dir)
    yield cap
    # Auto-save all captured evidence if the test failed.
    rep_call = getattr(request.node, "rep_call", None)
    if rep_call is not None and rep_call.failed:
        cap.flush()


# Make rep_call available on the node object via a hook.
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)


# ---------------------------------------------------------------------------
# Profile-driven helper functions (importable by test modules)
# ---------------------------------------------------------------------------

def endpoints_for_category(profile, category: str) -> list[dict]:
    """Return endpoint list for the given category name, or empty list.

    Categories: authenticated, anonymous, webhook, internal, payment.
    Converts _AttrDict endpoints to plain dicts for easier consumption.
    Endpoints matching the profile's effective ``exclude_paths`` (user list
    union the default-on list — session/state-destroying paths like /logout)
    are filtered out here, the single enumeration seam every probe module
    reads endpoints through. See exclusions.py.
    """
    eps = getattr(profile.endpoints, category, None)
    if not eps:
        return []
    exclude_paths = effective_exclude_paths(profile.exclude_paths)
    result = []
    for ep in eps:
        if hasattr(ep, 'items'):
            ep_dict = dict(ep.items())
        elif hasattr(ep, '__dict__'):
            ep_dict = {k: v for k, v in vars(ep).items() if not k.startswith('_')}
        else:
            ep_dict = ep
        path = ep_dict.get("path") if isinstance(ep_dict, dict) else None
        if path and is_excluded_path(path, exclude_paths):
            continue
        result.append(ep_dict)
    return result


def require_endpoints(profile, category: str) -> list[dict]:
    """Same as endpoints_for_category but calls pytest.skip() if empty."""
    eps = endpoints_for_category(profile, category)
    if not eps:
        pytest.skip(f"No endpoints defined for category '{category}' in profile")
    return eps


def probe_body_for(endpoint: dict) -> dict:
    """Return the probe_body for an endpoint dict, or empty dict."""
    body = endpoint.get("probe_body", {})
    if body is None:
        return {}
    if hasattr(body, 'items'):
        return dict(body.items())
    return body if isinstance(body, dict) else {}


def all_tables(profile, tier: str) -> list[str]:
    """Return table list from profile.supabase.tables[tier].

    Tables matching the profile's effective ``exclude_tables`` (user list
    union the default-on list) are filtered out here — ``exclude_paths`` is
    path-only and does NOT cover PostgREST table probes
    (``/rest/v1/<table>?id=eq.<uuid>``); this is the seam that does.
    """
    tables = profile.supabase and profile.supabase.tables
    if not tables:
        return []
    tier_list = getattr(tables, tier, None)
    if not tier_list:
        return []
    exclude_tables = effective_exclude_tables(profile.exclude_tables)
    return [t for t in tier_list if not is_excluded_table(t, exclude_tables)]


def all_rpcs(profile, tier: str) -> list[dict]:
    """Return RPC list from profile.supabase_rpcs[tier]."""
    rpcs = profile.supabase_rpcs
    if not rpcs:
        return []
    tier_list = getattr(rpcs, tier, None)
    if not tier_list:
        return []
    result = []
    for rpc in tier_list:
        if hasattr(rpc, 'items'):
            result.append(dict(rpc.items()))
        elif hasattr(rpc, '__dict__'):
            result.append({k: v for k, v in vars(rpc).items() if not k.startswith('_')})
        else:
            result.append(rpc)
    return result


def first_endpoint(profile, category: str) -> dict:
    """First endpoint of a category, or pytest.skip. Adopts require_endpoints (D5)."""
    eps = require_endpoints(profile, category)   # skips if category empty
    ep = eps[0]
    if not ep.get("path"):
        pytest.skip(f"First endpoint in category '{category}' has no 'path'")
    return ep


def upload_path(profile) -> str:
    """Return the profile's upload endpoint path, or skip if none is declared.

    Upload-domain-specific (reads ``profile.uploads.endpoint``), not a
    category-endpoint helper. Lives here so it is importable across modules.
    """
    path = profile.uploads and profile.uploads.endpoint
    if not path:
        pytest.skip("No upload endpoint defined in profile (profile.uploads.endpoint)")
    return path


def require_rpcs(profile, tier: str) -> list[dict]:
    """all_rpcs + pytest.skip when empty (RPC analogue of require_endpoints)."""
    rpcs = all_rpcs(profile, tier)
    if not rpcs:
        pytest.skip(f"No RPCs defined for tier '{tier}' in profile")
    return rpcs


def find_rpc(profile, tier: str, *, name_contains: Iterable[str]) -> dict:
    """First RPC in `tier` whose name contains ALL substrings in name_contains, else pytest.skip.

    Generalizes test_anon_session._find_merge_rpc_name. ``name_contains`` is a
    sequence of substrings AND-matched case-insensitively against each RPC name,
    e.g. ``("merge", "anon")``. A bare ``str`` is rejected — it would otherwise
    be iterated character-by-character and silently never match.
    """
    if isinstance(name_contains, str):
        raise TypeError(
            "find_rpc(name_contains=...) expects a sequence of substrings "
            f"(e.g. ('merge', 'anon')), not a bare str {name_contains!r}"
        )
    subs = tuple(name_contains)
    for rpc in all_rpcs(profile, tier):
        name = (rpc.get("name") or "").lower()
        if all(s.lower() in name for s in subs):
            return rpc
    pytest.skip(f"No RPC in tier '{tier}' matching {subs}")


# ---------------------------------------------------------------------------
# _AuthedClient — httpx.Client subclass that refreshes auth headers per request
# ---------------------------------------------------------------------------

class _AuthedClient(httpx.Client):
    """httpx.Client that calls auth_adapter.get_headers() before each request.

    This ensures the token is always fresh even for long-running test sessions.
    """

    def __init__(self, adapter, account: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._adapter = adapter
        self._account = account

    def send(self, request: httpx.Request, **kwargs):
        # Merge fresh auth headers before sending.
        # AuthConfigError is re-raised directly (config issue, not a bug).
        # Other exceptions are wrapped as RuntimeError to surface adapter bugs.
        try:
            auth_headers = self._adapter.get_headers(self._account)
        except AuthConfigError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"Cannot obtain auth headers for '{self._account}': {exc}"
            ) from exc

        for key, value in auth_headers.items():
            request.headers[key] = value
        return super().send(request, **kwargs)


# ---------------------------------------------------------------------------
# EvidenceCapture
# ---------------------------------------------------------------------------

class EvidenceCapture:
    """Capture HTTP request/response pairs and persist them as JSON artefacts.

    Usage inside a test::

        def test_something(evidence, user_a_client):
            resp = user_a_client.get("/some-path")
            evidence.capture(resp, label="initial_get")

    Files are written to ``reports/evidence/<sanitised_node_id>_<label>.json``.
    The file format is::

        {
            "timestamp": "2026-05-03T12:00:00Z",
            "request": {
                "method": "GET",
                "url": "https://...",
                "headers": {...},
                "body": "..."
            },
            "response": {
                "status_code": 200,
                "headers": {...},
                "body": "..."
            }
        }
    """

    def __init__(self, node_id: str, evidence_dir: Path) -> None:
        self._node_id = node_id
        self._evidence_dir = evidence_dir
        self._pending: list[dict] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture(self, response: httpx.Response, label: str = "") -> None:
        """Record a request/response pair and write it to disk immediately.

        Args:
            response: The :class:`httpx.Response` to capture.
            label: Short identifier appended to the filename (optional).
        """
        record = self._build_record(response, label)
        self._pending.append(record)
        self._write(record, label)

    def flush(self) -> None:
        """Re-write all pending records (called automatically on test failure)."""
        for record in self._pending:
            label = record.get("_label", "")
            self._write(record, label)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    _REDACTED_HEADERS = {
        "authorization", "apikey", "x-internal-secret", "set-cookie", "cookie",
    }

    def _build_record(self, response: httpx.Response, label: str) -> dict:
        req = response.request
        url = str(req.url)
        # Every field that can carry a credential is scrubbed before it touches
        # disk (plan §6 evidence-redaction gate): bodies via scrub_evidence_body
        # (tokens + wholesale Gmail/Drive/M365 content), the request URL and
        # header values via scrub_locator (a token can ride in a ?code= /
        # #access_token= query/fragment or a Location/Cookie header), and
        # credential-named headers via the _scrub_headers denylist.
        record: dict = {
            "_label": label,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "request": {
                "method": req.method,
                "url": scrub_locator(url),
                "headers": self._scrub_headers(dict(req.headers)),
                "body": scrub_evidence_body(self._safe_request_body(req), url=url),
            },
            "response": {
                "status_code": response.status_code,
                "headers": self._scrub_headers(dict(response.headers)),
                "body": scrub_evidence_body(self._decode_content(response.content), url=url),
            },
        }
        return record

    @classmethod
    def _scrub_headers(cls, headers: dict) -> dict:
        """Redact credential-bearing headers to avoid persisting tokens to disk.

        Credential-named headers (Authorization, Cookie, ...) are redacted to a
        short prefix. Every OTHER header value still runs through scrub_locator so
        a token riding in a non-denylisted header — a ``Location`` redirect with
        ``?code=`` / ``#access_token=``, or a Bearer/JWT reflected in a custom
        header — is also caught while non-secret header text is preserved.
        """
        scrubbed = {}
        for key, value in headers.items():
            if key.lower() in cls._REDACTED_HEADERS:
                # Keep the prefix for debugging but redact the secret portion.
                scrubbed[key] = value[:15] + "[REDACTED]" if len(value) > 15 else "[REDACTED]"
            else:
                scrubbed[key] = scrub_locator(value)
        return scrubbed

    def _write(self, record: dict, label: str) -> None:
        sanitised = _re.sub(r'[^\w.\-]', '_', self._node_id, flags=_re.ASCII)
        suffix = f"_{label}" if label else ""
        filename = f"{sanitised}{suffix}.json"
        dest = self._evidence_dir / filename
        # Strip the internal _label key before writing.
        output = {k: v for k, v in record.items() if k != "_label"}
        dest.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def _decode_content(content: bytes) -> str:
        """Attempt UTF-8 decode; fall back to hex representation for binary."""
        if not content:
            return ""
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            return content.hex()

    @staticmethod
    def _safe_request_body(req) -> str:
        """Read request body, handling streaming multipart requests gracefully."""
        try:
            content = req.content
        except httpx.RequestNotRead:
            return "<streaming multipart -- not captured>"
        return EvidenceCapture._decode_content(content)
