#!/usr/bin/env python3
"""doctor.py — non-destructive preflight self-check for StackBadger.

Usage:
    python doctor.py <target_url> [--profile profiles/site.yaml] [--json]

Runs the environment checks a real scan depends on, in order, printing one
``[PASS]`` / ``[FAIL] <check> — <fix>`` line per check and HALTING at the
first failure:

    1. python-version    Python >= 3.11
    2. env-complete      every required PENTEST_USER_* credential is set
    3. target-reachable  the target URL answers HTTP at all
    4. user-a-login      User A authenticates via the profile's auth adapter
    5. user-b-login      User B authenticates via the same adapter

When the profile declares ``auth.verify_path`` (an API-layer route that 401s
unauthenticated callers), checks 4 and 5 additionally request it with the
acquired credential and fail on 401/403 — catching a wrong ``stack.auth``
adapter that a bare provider sign-in cannot. Unset -> the login checks run
without it (black-box safe).

doctor is read-only: it signs in the two test accounts and fetches the
target's public pages/bundles (profile assembly), nothing else. It does NOT
probe IDOR or send any attack traffic.

Exit codes are in the 10-19 range so they can never be confused with
``reports/aggregate.py``'s finding-severity contract (0/1/2/3):

    0   every check passed
    10  python-version failed
    11  env-complete failed
    12  target-reachable failed
    13  user-a-login failed
    14  user-b-login failed
    19  internal doctor error

``--json`` writes a machine-readable summary to stdout (human lines move to
stderr): ``{"passed": bool, "exit_code": int, "checks": [...]}``.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

# doctor.py is a standalone tool runnable from any cwd (e.g.
# `python path/to/doctor.py ...`). Default the .env / .env.example lookups to
# the repo the script lives in, NOT the caller's cwd, so a standalone run finds
# the repo's credentials instead of failing env-complete spuriously. Explicit
# --env-file / --env-example still override.
_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_ENV_FILE = _SCRIPT_DIR / ".env"
_DEFAULT_ENV_EXAMPLE = _SCRIPT_DIR / ".env.example"

EXIT_OK = 0
EXIT_PYTHON_VERSION = 10
EXIT_ENV_INCOMPLETE = 11
EXIT_TARGET_UNREACHABLE = 12
EXIT_USER_A_LOGIN = 13
EXIT_USER_B_LOGIN = 14
EXIT_INTERNAL_ERROR = 19

# Fallback required-credential set, used when .env.example is missing.
_FALLBACK_REQUIRED_KEYS = (
    "PENTEST_USER_A_EMAIL",
    "PENTEST_USER_A_PASSWORD",
    "PENTEST_USER_B_EMAIL",
    "PENTEST_USER_B_PASSWORD",
)


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str
    fix: str = ""
    exit_code: int = EXIT_OK


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse simple KEY=VALUE lines; ignores comments and blank lines.

    Shared with provision_accounts.py (imported there) so .env parsing
    semantics cannot drift between the preflight and provisioning scripts.
    """
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def load_dotenv(env_file: Path, environ: dict[str, str]) -> None:
    """Load *env_file* into *environ* without overriding already-set vars.

    run.sh sources .env itself before delegating here; standalone invocations
    (``python doctor.py ...``) need the same values, so doctor loads them too.
    Existing environment values win — mirroring shell ``source`` order, where
    the caller's explicit exports were applied last.
    """
    for key, value in parse_env_file(env_file).items():
        if key not in environ or not environ[key]:
            environ[key] = value


def required_env_keys(env_example: Path) -> tuple[str, ...]:
    """Derive the required credential set from .env.example.

    The contract of .env.example is that its UNCOMMENTED keys are the required
    ones (optional vars are shipped commented out). Falls back to the four
    PENTEST_USER_* keys when the file is absent.
    """
    keys = tuple(parse_env_file(env_example).keys())
    return keys or _FALLBACK_REQUIRED_KEYS


# ---------------------------------------------------------------------------
# Checks — each returns a CheckResult; the runner halts at the first failure.
# ---------------------------------------------------------------------------

def check_python_version() -> CheckResult:
    version = ".".join(str(v) for v in sys.version_info[:3])
    if sys.version_info >= (3, 11):
        return CheckResult("python-version", True, f"Python {version}")
    return CheckResult(
        "python-version",
        False,
        f"Python {version} is too old",
        fix="install Python 3.11+ and re-run with it",
        exit_code=EXIT_PYTHON_VERSION,
    )


def check_env_complete(environ: dict[str, str], env_example: Path) -> CheckResult:
    required = required_env_keys(env_example)
    missing = [k for k in required if not environ.get(k)]
    if not missing:
        return CheckResult("env-complete", True, f"all {len(required)} required credentials set")
    return CheckResult(
        "env-complete",
        False,
        f"missing {', '.join(missing)}",
        fix="set the missing key(s) in .env (copy .env.example and fill in all "
            "four PENTEST_USER_* values — User B is required for cross-user IDOR probes)",
        exit_code=EXIT_ENV_INCOMPLETE,
    )


def check_target_reachable(target_url: str) -> CheckResult:
    import httpx

    try:
        resp = httpx.get(target_url, timeout=10.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        return CheckResult(
            "target-reachable",
            False,
            f"{target_url}: {exc.__class__.__name__}: {exc}",
            fix="check the URL, DNS, and that the deployment is up",
            exit_code=EXIT_TARGET_UNREACHABLE,
        )
    return CheckResult("target-reachable", True, f"{target_url} -> HTTP {resp.status_code}")


def _build_adapter(target_url: str, profile_path: str | None):
    """Assemble the runtime profile (one live crawl) and build its auth adapter.

    Returns ``(adapter, provider, verify_path)`` — *verify_path* is the
    profile's optional ``auth.verify_path`` (None when unset).
    """
    from auth import create_adapter
    from profile_assembler import assemble_profile

    profile = assemble_profile(target_url, yaml_path=profile_path)
    provider = (profile.stack and profile.stack.auth) or "unknown"
    verify_path = (profile.auth and profile.auth.verify_path) or None
    return create_adapter(profile), provider, verify_path


def _check_verify_path(target_url: str, verify_path: str, headers: dict, who: str):
    """Request the profile's auth.verify_path with one account's headers.

    ``verify_path`` is ROOT-relative: it resolves against the ORIGIN of
    *target_url*, not against any path prefix the target URL carries. For
    ``https://example.com/app`` + ``/api/me`` the probe goes to
    ``https://example.com/api/me`` (urljoin semantics for a leading-slash
    path), never ``.../app/api/me``.

    Returns ``(ok, detail, fix)``: 2xx passes; 401/403 fails (the provider
    issued a credential the API rejects — broken account or wrong adapter);
    any other status is inconclusive and passes with a warning detail, since
    verify_path is an optional accelerator, not a gate on the route existing.
    """
    import httpx
    from urllib.parse import urljoin

    url = urljoin(target_url.rstrip("/") + "/", verify_path)
    try:
        # Redirects are deliberately NOT followed: middleware that rejects a
        # bad credential with 302 -> /login -> 200 would otherwise read as a
        # 2xx "pass" for exactly the wrong-adapter condition this check
        # exists to catch.
        resp = httpx.get(url, headers=headers, timeout=15.0, follow_redirects=False)
    except httpx.HTTPError as exc:
        return (
            False,
            f"{who}: verify_path {verify_path} request failed: "
            f"{exc.__class__.__name__}: {exc}",
            "check the URL/network; if verify_path is wrong, fix auth.verify_path in the profile",
        )
    if 200 <= resp.status_code < 300:
        return True, f"verify_path {verify_path} -> HTTP {resp.status_code}", ""
    if resp.status_code in (401, 403):
        return (
            False,
            f"{who} signed in, but {verify_path} returned HTTP {resp.status_code}",
            f"the provider issued a credential the API rejects — either the "
            f"{who} account is broken in the target app, or stack.auth selects "
            "the wrong adapter (token from the wrong issuer; see LAUNCH.md Step 0)",
        )
    if 300 <= resp.status_code < 400:
        return (
            True,
            f"verify_path {verify_path} -> HTTP {resp.status_code} redirect "
            "(inconclusive — redirects are not followed; a redirect-to-login is "
            "indistinguishable from rejection. Point auth.verify_path at a "
            "direct API route that answers 2xx/401 itself)",
            "",
        )
    return (
        True,
        f"verify_path {verify_path} -> HTTP {resp.status_code} (inconclusive — "
        "expected 2xx; is it an API-layer route?)",
        "",
    )


def check_logins(target_url: str, profile_path: str | None) -> list[CheckResult]:
    """Sign in user_a then user_b via the profile-driven adapter.

    When the profile declares ``auth.verify_path``, each account's login check
    additionally requests that route with the acquired credential — catching a
    wrong adapter (sign-in succeeds against the provider, but the target API
    rejects the token) that a bare sign-in cannot.
    """
    results: list[CheckResult] = []
    try:
        adapter, provider, verify_path = _build_adapter(target_url, profile_path)
    except Exception as exc:
        results.append(CheckResult(
            "user-a-login",
            False,
            f"could not build the auth adapter: {exc}",
            fix="the profile's stack.auth may not match the target's real auth "
                "provider — set stack.auth in a --profile YAML (e.g. "
                "supabase-auth) or run the LAUNCH.md Step 0 source detection",
            exit_code=EXIT_USER_A_LOGIN,
        ))
        return results

    try:
        for account, check_name, exit_code in (
            ("user_a", "user-a-login", EXIT_USER_A_LOGIN),
            ("user_b", "user-b-login", EXIT_USER_B_LOGIN),
        ):
            who = "User A" if account == "user_a" else "User B"
            try:
                headers = adapter.get_headers(account)
                if not headers:
                    raise RuntimeError("adapter returned no auth headers")
            except Exception as exc:
                results.append(CheckResult(
                    check_name,
                    False,
                    f"{who} failed to authenticate via the '{provider}' adapter: {exc}",
                    fix=f"verify PENTEST_{account.upper()}_EMAIL/_PASSWORD are a real, "
                        f"confirmed account in the target's auth provider; if the "
                        f"provider itself is wrong, fix stack.auth (LAUNCH.md Step 0)",
                    exit_code=exit_code,
                ))
                return results
            detail = f"{account} authenticated via '{provider}' adapter"
            if verify_path:
                ok, vp_detail, vp_fix = _check_verify_path(
                    target_url, verify_path, headers, who
                )
                if not ok:
                    results.append(CheckResult(
                        check_name, False, vp_detail, fix=vp_fix, exit_code=exit_code,
                    ))
                    return results
                detail += f"; {vp_detail}"
            results.append(CheckResult(check_name, True, detail))
    finally:
        if hasattr(adapter, "close"):
            try:
                adapter.close()
            except Exception:
                pass
    return results


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_doctor(
    target_url: str,
    profile_path: str | None = None,
    *,
    env_file: Path = _DEFAULT_ENV_FILE,
    env_example: Path = _DEFAULT_ENV_EXAMPLE,
    environ: dict[str, str] | None = None,
) -> tuple[int, list[CheckResult]]:
    """Run all checks in order, halting at the first failure."""
    import os

    env = environ if environ is not None else os.environ  # type: ignore[assignment]
    load_dotenv(env_file, env)

    results: list[CheckResult] = []
    # Thunks, not results: a later check must not even RUN (e.g. no network
    # traffic) once an earlier one has failed.
    for check in (
        lambda: check_python_version(),
        lambda: check_env_complete(env, env_example),
        lambda: check_target_reachable(target_url),
    ):
        result = check()
        results.append(result)
        if not result.passed:
            return result.exit_code, results

    login_results = check_logins(target_url, profile_path)
    results.extend(login_results)
    for result in login_results:
        if not result.passed:
            return result.exit_code, results

    return EXIT_OK, results


def _emit(results: list[CheckResult], exit_code: int, json_mode: bool) -> None:
    human_out = sys.stderr if json_mode else sys.stdout
    for r in results:
        if r.passed:
            print(f"[PASS] {r.name} — {r.detail}", file=human_out)
        else:
            print(f"[FAIL] {r.name} — {r.detail}. Fix: {r.fix}", file=human_out)
    if json_mode:
        print(json.dumps({
            "passed": exit_code == EXIT_OK,
            "exit_code": exit_code,
            "checks": [asdict(r) for r in results],
        }, indent=2))


def force_utf8_streams() -> None:
    """Emit UTF-8 regardless of the platform's default code page.

    On Windows, stdout/stderr default to the legacy ANSI code page (e.g.
    cp1252), so non-ASCII characters in human-readable output render as mojibake
    even in a UTF-8-capable console. Best-effort and purely cosmetic:
    reconfiguring is a no-op where the stream is already UTF-8, is skipped when
    the stream lacks reconfigure() (e.g. a test capture), and any failure is
    swallowed rather than aborting startup.

    Shared helper — also imported by provision_accounts.py (and thus teardown.py).
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001 — best-effort cosmetic; never block startup
            pass


def main(argv: list[str] | None = None) -> int:
    force_utf8_streams()
    parser = argparse.ArgumentParser(
        description="Non-destructive preflight self-check (no attack traffic).",
    )
    parser.add_argument("target_url", help="Target site URL, e.g. https://staging.example.com")
    parser.add_argument("--profile", default=None, help="Optional YAML profile (names stack.auth etc.)")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON summary to stdout")
    parser.add_argument("--env-file", default=str(_DEFAULT_ENV_FILE), help=argparse.SUPPRESS)
    parser.add_argument("--env-example", default=str(_DEFAULT_ENV_EXAMPLE), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    try:
        exit_code, results = run_doctor(
            args.target_url,
            args.profile,
            env_file=Path(args.env_file),
            env_example=Path(args.env_example),
        )
    except Exception as exc:  # never let an internal bug masquerade as a finding
        print(f"[FAIL] doctor-internal — unexpected error: {exc}", file=sys.stderr)
        if args.json:
            # Keep the stdout=JSON contract even on internal failure so an agent
            # parsing stdout gets a verdict instead of empty output.
            print(json.dumps({
                "passed": False,
                "exit_code": EXIT_INTERNAL_ERROR,
                "checks": [],
                "error": str(exc),
            }, indent=2))
        return EXIT_INTERNAL_ERROR

    _emit(results, exit_code, args.json)
    return exit_code


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
