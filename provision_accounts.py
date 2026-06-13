#!/usr/bin/env python3
"""provision_accounts.py — create the two StackBadger test accounts.

Usage:
    python provision_accounts.py [--provider supabase-auth] [--project-url URL]
    python provision_accounts.py --cleanup

Supabase Auth (GoTrue) is the only automated provider: the naive path (raw SQL
``INSERT`` into ``auth.users``) produces a login ``500 "Database error querying
schema"`` because GoTrue scans NULL token columns into non-nullable Go strings
(supabase/auth#1940). The canonical fix — used here — is the GoTrue Admin API:

    POST {project_url}/auth/v1/admin/users   with  email_confirm: true

which populates every token column correctly. The Admin API requires the
project **service-role key** (``SUPABASE_SERVICE_ROLE_KEY``). The Supabase
Management API personal access token (``SUPABASE_ACCESS_TOKEN``) can NOT call
the Admin API — it is accepted here only as an optional path to *fetch* the
service-role key (``GET https://api.supabase.com/v1/projects/{ref}/api-keys``).

Other providers (Clerk / Firebase / NextAuth) are manual: ``--provider clerk``
(etc.) prints the dashboard steps documented in README.md instead of running.

Secret handling
---------------
- The service-role key is read from the environment / ``.env`` and is NEVER
  echoed; error messages and tracebacks are scrubbed before printing
  (mirroring ``reports/scrub.py``).
- Credentials and the created user IDs are written to ``.env`` atomically
  (full rewrite via a temp file — never a partial write) and the file mode is
  set to ``0o600``.
- Re-running is idempotent: existing ``.env`` credentials are reused, an
  "already registered" response recovers the existing user's ID by listing.

``--cleanup`` deletes the two accounts by the user IDs stored in ``.env``
(``PENTEST_USER_A_ID`` / ``PENTEST_USER_B_ID``) — falling back to a lookup by
the deterministic ``stackbadger-pentest-*`` email for a run that failed before
the IDs were written — and clears the stored values. ``teardown.py`` is a thin
wrapper over this flag.

Exit codes: 0 success (including a no-op cleanup), 1 failure, 2 manual steps
printed (non-Supabase provider — nothing was provisioned or deleted).
Failures never leave a partially-written ``.env``.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
import tempfile
import traceback
from pathlib import Path

# Standalone-script convention (mirrors doctor.py): resolve .env relative to
# the repo the script lives in, not the caller's cwd.
_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_ENV_FILE = _SCRIPT_DIR / ".env"

# .env keys this script owns. Everything else in .env is preserved verbatim.
_KEY_EMAIL_A = "PENTEST_USER_A_EMAIL"
_KEY_PASS_A = "PENTEST_USER_A_PASSWORD"
_KEY_EMAIL_B = "PENTEST_USER_B_EMAIL"
_KEY_PASS_B = "PENTEST_USER_B_PASSWORD"
_KEY_ID_A = "PENTEST_USER_A_ID"
_KEY_ID_B = "PENTEST_USER_B_ID"

_SERVICE_ROLE_ENV = "SUPABASE_SERVICE_ROLE_KEY"
_ACCESS_TOKEN_ENV = "SUPABASE_ACCESS_TOKEN"

# Exit codes: 0 = provisioned/torn down, 1 = failure, 2 = manual steps were
# printed (Clerk/Firebase/NextAuth) — nothing was provisioned or deleted.
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_MANUAL_STEPS = 2

# Secrets shorter than this are not redacted (same guard as reports/scrub.py —
# too likely to collide with non-secret substrings).
_MIN_SECRET_LEN = 8

_MANUAL_PROVIDERS = {
    "clerk": (
        "Clerk has no scripted provisioning here — create the accounts in the dashboard:\n"
        "  1. Clerk Dashboard -> Users -> Create user (twice: account A and account B).\n"
        "  2. Enable email + password sign-in; mark the email address verified.\n"
        "  3. Ensure MFA is OFF for both accounts (headless sign-in cannot answer a challenge).\n"
        "  4. Put the four PENTEST_USER_* values in .env."
    ),
    "firebase": (
        "Firebase has no scripted provisioning here — create the accounts in the console:\n"
        "  1. Firebase Console -> Authentication -> Users -> Add user (twice).\n"
        "  2. Email/Password provider must be enabled; no MFA enrollment.\n"
        "  3. Put the four PENTEST_USER_* values in .env."
    ),
    "nextauth": (
        "NextAuth/Auth.js credentials providers are app-defined — there is no generic API:\n"
        "  1. Create two users through the target app's own sign-up flow (or its admin tooling).\n"
        "  2. Both must work with the credentials (email + password) provider; MFA off.\n"
        "  3. Put the four PENTEST_USER_* values in .env."
    ),
}


# ---------------------------------------------------------------------------
# Secret redaction (mirror of the reports/scrub.py literal-secret layer)
# ---------------------------------------------------------------------------

# Registry of (secret value, redaction label) pairs known at runtime. Every
# secret this script handles is registered the moment it exists — env-sourced
# keys, Management-API-fetched keys, generated passwords — so EVERY error
# print routes through one scrubber, not just the top-level exception handler.
_RUNTIME_SECRETS: list[tuple[str, str]] = []


def _register_secret(value: str | None, label: str) -> None:
    if value and len(value) >= _MIN_SECRET_LEN:
        _RUNTIME_SECRETS.append((value, label))


def _scrub(text: str) -> str:
    """Redact every registered secret plus key-shaped patterns from *text*.

    The pattern layer (``sb_secret_*`` / ``eyJ*``) is a belt-and-braces catch
    for any service-role-key shape that was never registered (e.g. one echoed
    back by a proxy error page).
    """
    for secret, label in _RUNTIME_SECRETS:
        text = text.replace(secret, f"[REDACTED_{label}]")
    text = re.sub(r"sb_secret_[A-Za-z0-9_-]+", "[REDACTED_SERVICE_ROLE_KEY]", text)
    text = re.sub(r"eyJ[A-Za-z0-9._/+=-]{20,}", "[REDACTED_JWT]", text)
    return text


# ---------------------------------------------------------------------------
# .env read / atomic write
# ---------------------------------------------------------------------------
# Read-side helpers come from doctor.py — same parsing semantics everywhere
# (run.sh `source`, doctor preflight, provisioning) so the three consumers
# can never drift. The write side (update_env_file) is unique to this script.
from doctor import _force_utf8_streams, load_dotenv, parse_env_file  # noqa: E402


def update_env_file(path: Path, updates: dict[str, str | None]) -> None:
    """Rewrite *path* with *updates* applied — atomic, never partial.

    Keys mapping to a string are set (replacing an existing line or appended);
    keys mapping to ``None`` are removed. All other lines are preserved
    verbatim. The replacement file is written next to the target and swapped in
    with ``os.replace``, then chmod'd to ``0o600`` so the credentials are not
    world-readable.
    """
    lines: list[str] = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    handled: set[str] = set()
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        key = stripped.partition("=")[0].strip() if "=" in stripped else None
        if key and not stripped.startswith("#") and key in updates:
            if key in handled:
                # Drop duplicate lines of a managed key: both bash `source`
                # and parse_env_file are last-wins, so a surviving later
                # duplicate would silently shadow the value just written.
                continue
            handled.add(key)
            value = updates[key]
            if value is not None:
                out.append(f"{key}={value}")
            # None -> drop the line entirely.
        else:
            out.append(line)
    for key, value in updates.items():
        if key not in handled and value is not None:
            out.append(f"{key}={value}")

    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(out) + "\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    # os.replace preserves the temp file's mode, but set it again explicitly in
    # case the platform's rename semantics differ.
    os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# GoTrue Admin API
# ---------------------------------------------------------------------------

def _admin_headers(service_role_key: str) -> dict[str, str]:
    return {
        "apikey": service_role_key,
        "Authorization": f"Bearer {service_role_key}",
        "Content-Type": "application/json",
    }


def _find_user_id_by_email(http, project_url: str, service_role_key: str, email: str) -> str | None:
    """Recover an existing user's ID via the Admin list endpoint (paginated)."""
    wanted = email.strip().lower()
    for page in range(1, 21):  # up to 1000 users — far beyond two test accounts
        resp = http.get(
            f"{project_url}/auth/v1/admin/users",
            params={"page": page, "per_page": 50},
            headers=_admin_headers(service_role_key),
            timeout=20.0,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Admin API list users failed: HTTP {resp.status_code} — {resp.text[:300]}"
            )
        users = resp.json().get("users") or []
        if not users:
            return None
        for user in users:
            if str(user.get("email", "")).strip().lower() == wanted:
                return str(user.get("id"))
    return None


def _admin_create_user(
    http, project_url: str, service_role_key: str, email: str, password: str
) -> str:
    """Create one confirmed user via the Admin API; return the user ID.

    ``email_confirm: true`` makes GoTrue populate the confirmation-token
    columns correctly — the whole point of using the Admin API instead of raw
    SQL (supabase/auth#1940). If the email is already registered, the existing
    user's ID is recovered (idempotent re-run).
    """
    resp = http.post(
        f"{project_url}/auth/v1/admin/users",
        json={"email": email, "password": password, "email_confirm": True},
        headers=_admin_headers(service_role_key),
        timeout=20.0,
    )
    if resp.status_code in (200, 201):
        user_id = str(resp.json().get("id") or "")
        if not user_id:
            raise RuntimeError(
                "Admin API created the user but returned no 'id' field "
                f"(keys: {list(resp.json().keys())})"
            )
        return user_id

    body = resp.text[:300]
    if resp.status_code in (400, 422) and re.search(
        r"already (been )?registered|already exists", body, re.IGNORECASE
    ):
        existing = _find_user_id_by_email(http, project_url, service_role_key, email)
        if existing:
            # The account predates this run, so the password we are about to
            # write to .env may not be the one GoTrue has (stale .env, prior
            # partial run). For accounts THIS SCRIPT named (deterministic
            # pattern) set it explicitly — otherwise provisioning reports
            # [ok] with credentials that cannot sign in. For an operator-
            # supplied custom email, never silently reset: a typo'd real
            # user's email here would lock that user out. Same ownership
            # gate cleanup uses for delete-by-email.
            if _is_provisioned_email(email):
                _admin_set_password(http, project_url, service_role_key, existing, password)
            else:
                print(
                    f"[warn] {email} already exists — password NOT changed "
                    "(not a script-managed account). doctor.py will verify "
                    "sign-in; if it fails, fix the password in .env or delete "
                    "the account and re-provision.",
                    file=sys.stderr,
                )
            return existing
        raise RuntimeError(
            f"User {email} is already registered but could not be found via the "
            "Admin list endpoint — delete it in the dashboard or use different "
            "PENTEST_USER_* emails."
        )

    raise RuntimeError(
        f"Admin API create user failed for {email}: HTTP {resp.status_code} — {body}"
    )


def _admin_set_password(
    http, project_url: str, service_role_key: str, user_id: str, password: str
) -> None:
    """Set a recovered user's password so .env credentials are live."""
    resp = http.put(
        f"{project_url}/auth/v1/admin/users/{user_id}",
        json={"password": password, "email_confirm": True},
        headers=_admin_headers(service_role_key),
        timeout=20.0,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(
            f"Admin API password update failed for user {user_id}: "
            f"HTTP {resp.status_code} — {resp.text[:300]}"
        )


def _admin_delete_user(http, project_url: str, service_role_key: str, user_id: str) -> bool:
    """Delete one user by ID. Returns True if deleted or already gone."""
    resp = http.delete(
        f"{project_url}/auth/v1/admin/users/{user_id}",
        headers=_admin_headers(service_role_key),
        timeout=20.0,
    )
    if resp.status_code in (200, 204, 404):
        return True
    raise RuntimeError(
        f"Admin API delete user {user_id} failed: HTTP {resp.status_code} — {resp.text[:300]}"
    )


def _fetch_service_role_key(http, access_token: str, project_ref: str) -> str | None:
    """Optionally fetch the service-role key via the Management API.

    This is the ONLY thing ``SUPABASE_ACCESS_TOKEN`` is good for here — the
    PAT cannot call the GoTrue Admin API itself.
    """
    resp = http.get(
        f"https://api.supabase.com/v1/projects/{project_ref}/api-keys",
        params={"reveal": "true"},
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20.0,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Management API api-keys lookup failed: HTTP {resp.status_code} — "
            f"{resp.text[:300]}"
        )
    for entry in resp.json():
        if entry.get("name") == "service_role" or entry.get("type") == "secret":
            key = entry.get("api_key")
            if key:
                return str(key)
    return None


def _project_ref_from_url(project_url: str) -> str | None:
    m = re.match(r"https://([^.]+)\.supabase\.co", project_url)
    return m.group(1) if m else None


# Every Admin API call sends the service-role key (Authorization + apikey
# headers) to whatever host this URL names — a typoed or attacker-supplied
# host would receive the project's root credential. Fail closed unless the
# URL is exactly an https://<ref>.supabase.co origin (single host label, no
# port, no path); custom domains / self-hosted Supabase require the explicit
# --allow-custom-domain opt-in.
_SUPABASE_HOST_RE = re.compile(r"^https://[a-z0-9-]+\.supabase\.co$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Provision / cleanup flows
# ---------------------------------------------------------------------------

def _resolve_project_url(args, env: dict[str, str]) -> str:
    project_url = (args.project_url or env.get("SUPABASE_PROJECT_URL") or "").rstrip("/")
    if not project_url:
        raise RuntimeError(
            "Supabase project URL not available. Pass --project-url or set "
            "SUPABASE_PROJECT_URL in .env."
        )
    if not project_url.startswith("https://"):
        raise RuntimeError(
            f"Supabase project URL must use https://, got: {project_url[:40]}"
        )
    if not _SUPABASE_HOST_RE.match(project_url) and not getattr(
        args, "allow_custom_domain", False
    ):
        raise RuntimeError(
            f"Refusing to send the service-role key to '{project_url[:80]}': it "
            "is not an https://<ref>.supabase.co origin. A typoed or malicious "
            "host here would receive your project's root credential. If this "
            "really is your project on a custom domain or self-hosted Supabase, "
            "re-run with --allow-custom-domain."
        )
    return project_url


def _resolve_service_role_key(http, env: dict[str, str], project_url: str) -> str:
    key = env.get(_SERVICE_ROLE_ENV, "")
    if key:
        return key
    access_token = env.get(_ACCESS_TOKEN_ENV, "")
    project_ref = _project_ref_from_url(project_url)
    if access_token and project_ref:
        print(
            f"[info] {_SERVICE_ROLE_ENV} not set — fetching it via the Management "
            f"API ({_ACCESS_TOKEN_ENV} is only used for this lookup; the key "
            "itself will not be printed).",
            file=sys.stderr,
        )
        fetched = _fetch_service_role_key(http, access_token, project_ref)
        if fetched:
            _register_secret(fetched, "SERVICE_ROLE_KEY")
            return fetched
    raise RuntimeError(
        f"{_SERVICE_ROLE_ENV} is required (the GoTrue Admin API only accepts the "
        f"project service-role key; {_ACCESS_TOKEN_ENV} cannot call it). Get it "
        "from Supabase Dashboard -> Project Settings -> API keys and set it in "
        ".env, or set SUPABASE_ACCESS_TOKEN to let this script fetch it."
    )


# Deterministic default emails (no random suffix) so a re-run after ANY state
# loss — stale .env, first-run failure between accounts, deleted .env —
# collides with the existing account, recovers its ID, and resets its password
# (see _admin_create_user) instead of orphaning it and minting a new one.
_DETERMINISTIC_EMAIL_PREFIX = "stackbadger-pentest-"


def _default_email(slot: str) -> str:
    return f"{_DETERMINISTIC_EMAIL_PREFIX}{slot}@example.com"


def _is_provisioned_email(email: str) -> bool:
    """True when *email* matches the deterministic pattern this script mints.

    Used by cleanup as the safety gate for delete-by-email fallback: an
    operator's manually-created account (custom email) must never be deleted
    by lookup — only accounts this script itself named.
    """
    return email.strip().lower().startswith(_DETERMINISTIC_EMAIL_PREFIX)


def provision(args, env: dict[str, str], env_file: Path, http) -> int:
    """Create accounts A and B, then write creds + IDs to .env (atomic)."""
    project_url = _resolve_project_url(args, env)
    service_role_key = _resolve_service_role_key(http, env, project_url)

    # Reuse .env credentials when present so operator-chosen accounts are
    # honored; otherwise use deterministic emails + strong random passwords.
    # Both accounts are resolved BEFORE any write, so .env is only ever
    # rewritten once, with complete data.
    email_a = env.get(_KEY_EMAIL_A) or _default_email("a")
    pass_a = env.get(_KEY_PASS_A) or secrets.token_urlsafe(18)
    email_b = env.get(_KEY_EMAIL_B) or _default_email("b")
    pass_b = env.get(_KEY_PASS_B) or secrets.token_urlsafe(18)
    _register_secret(pass_a, "PASSWORD")
    _register_secret(pass_b, "PASSWORD")

    id_a = _admin_create_user(http, project_url, service_role_key, email_a, pass_a)
    print(f"[ok] account A provisioned: {email_a} (id: {id_a})")
    id_b = _admin_create_user(http, project_url, service_role_key, email_b, pass_b)
    print(f"[ok] account B provisioned: {email_b} (id: {id_b})")

    update_env_file(env_file, {
        _KEY_EMAIL_A: email_a,
        _KEY_PASS_A: pass_a,
        _KEY_EMAIL_B: email_b,
        _KEY_PASS_B: pass_b,
        _KEY_ID_A: id_a,
        _KEY_ID_B: id_b,
    })
    print(f"[ok] credentials + user IDs written to {env_file} (mode 0600)")
    print(
        "[note] re-source .env in the shell that will run run.sh — it was "
        "sourced before these values existed."
    )
    return 0


_SLOT_KEYS = (
    ("A", _KEY_ID_A, _KEY_EMAIL_A, _KEY_PASS_A),
    ("B", _KEY_ID_B, _KEY_EMAIL_B, _KEY_PASS_B),
)


def cleanup(args, env: dict[str, str], env_file: Path, http) -> int:
    """Delete the seeded accounts. Idempotent.

    Primary path: delete by the stored ``PENTEST_USER_*_ID``. Fallback: when
    an ID is missing, look the account up by email — the stored email if it
    matches the deterministic pattern this script mints, or the slot's
    DEFAULT deterministic email when nothing is stored at all. The default
    sweep covers the worst orphan state: a provision run that died before
    its single .env write leaves accounts standing remotely with .env
    untouched. Custom (operator-supplied) emails are NEVER deleted by
    lookup. When nothing is recorded locally AND no connection config is
    available, teardown is a friendly no-op instead of demanding a key it
    has nothing certain to do with.
    """
    stored_ids = {slot: env.get(id_key, "") for slot, id_key, _, _ in _SLOT_KEYS}
    fallback_emails: dict[str, str] = {}
    for slot, id_key, email_key, _ in _SLOT_KEYS:
        if env.get(id_key, ""):
            continue
        stored_email = env.get(email_key, "")
        if _is_provisioned_email(stored_email):
            fallback_emails[slot] = stored_email
        elif not stored_email:
            # Nothing stored for this slot: sweep the script's own default
            # email in case a failed run created the account but never got
            # to write .env.
            fallback_emails[slot] = _default_email(slot.lower())
        # else: custom stored email — never delete by lookup.

    nothing_recorded = not any(stored_ids.values()) and not any(
        _is_provisioned_email(env.get(email_key, "")) for _, _, email_key, _ in _SLOT_KEYS
    )
    have_config = bool(
        (args.project_url or env.get("SUPABASE_PROJECT_URL"))
        and (env.get(_SERVICE_ROLE_ENV) or env.get(_ACCESS_TOKEN_ENV))
    )
    if nothing_recorded and not have_config:
        print(
            "[ok] nothing recorded in .env to tear down. (To also sweep the "
            f"default {_DETERMINISTIC_EMAIL_PREFIX}* accounts remotely, set "
            "SUPABASE_PROJECT_URL and SUPABASE_SERVICE_ROLE_KEY and re-run.)"
        )
        return 0

    project_url = _resolve_project_url(args, env)
    service_role_key = _resolve_service_role_key(http, env, project_url)

    remaining: list[str] = []
    cleared: dict[str, str | None] = {}
    deleted_any = False
    for slot, id_key, email_key, pass_key in _SLOT_KEYS:
        user_id = stored_ids[slot]
        if not user_id and slot in fallback_emails:
            try:
                user_id = _find_user_id_by_email(
                    http, project_url, service_role_key, fallback_emails[slot]
                ) or ""
            except RuntimeError as exc:
                print(f"[fail] account {slot} email lookup failed: {_scrub(str(exc))}",
                      file=sys.stderr)
                remaining.append(f"account {slot} ({fallback_emails[slot]})")
                continue
            if not user_id:
                # Confirmed absent remotely — stored deterministic creds (if
                # any) are dead; clear them so the next teardown can fast-path.
                if _is_provisioned_email(env.get(email_key, "")):
                    cleared[email_key] = None
                    cleared[pass_key] = None
                continue
        if not user_id:
            continue
        try:
            _admin_delete_user(http, project_url, service_role_key, user_id)
            print(f"[ok] account {slot} deleted (id: {user_id})")
            deleted_any = True
            cleared[id_key] = None
            # A deleted script-named account's credentials are dead — clear
            # them so the next provision mints fresh ones and a second
            # teardown is a true no-op.
            if _is_provisioned_email(env.get(email_key, "")):
                cleared[email_key] = None
                cleared[pass_key] = None
        except RuntimeError as exc:
            print(f"[fail] account {slot} (id: {user_id}) NOT deleted: {_scrub(str(exc))}",
                  file=sys.stderr)
            remaining.append(f"account {slot} (id: {user_id})")

    if cleared:
        update_env_file(env_file, cleared)
    if remaining:
        print(
            f"[fail] teardown incomplete — still standing: {', '.join(remaining)}. "
            "Re-run after fixing the error above, or delete them in the dashboard.",
            file=sys.stderr,
        )
        return 1
    if deleted_any:
        print("[ok] teardown complete — no seeded accounts remain.")
    else:
        print("[ok] nothing to tear down — no seeded accounts found.")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(
    argv: list[str] | None = None,
    http=None,
    *,
    prog: str | None = None,
    description: str | None = None,
) -> int:
    _force_utf8_streams()
    parser = argparse.ArgumentParser(
        prog=prog,
        description=description or (
            "Create (or, with --cleanup, delete) the two StackBadger test "
            "accounts. Automated for Supabase Auth via the GoTrue Admin API; "
            "other providers print documented manual steps."
        ),
    )
    parser.add_argument(
        "--provider",
        default="supabase-auth",
        choices=["supabase-auth", *sorted(_MANUAL_PROVIDERS)],
        help="Target auth provider (default: supabase-auth, the only automated one).",
    )
    parser.add_argument("--cleanup", action="store_true",
                        help="Delete the accounts recorded in .env instead of creating them.")
    parser.add_argument("--project-url", default=None,
                        help="Supabase project URL (default: SUPABASE_PROJECT_URL from env/.env).")
    parser.add_argument("--allow-custom-domain", action="store_true",
                        help="Permit a non-*.supabase.co project URL (custom domain / "
                             "self-hosted). Off by default: the Admin API calls carry the "
                             "service-role key, so an unrecognized host is refused.")
    parser.add_argument("--env-file", default=str(_DEFAULT_ENV_FILE), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.provider in _MANUAL_PROVIDERS:
        # Exit 2, NOT 0: printing instructions is not a provisioning success,
        # and an agent gating on "exit 0 -> accounts exist" must be able to
        # tell the two apart (LAUNCH.md Step 3a).
        if args.cleanup:
            print(
                f"--cleanup only automates Supabase Auth. For {args.provider}, "
                "delete the two test accounts in the provider dashboard — the "
                "same place they were created."
            )
        else:
            print(_MANUAL_PROVIDERS[args.provider])
        return EXIT_MANUAL_STEPS

    env_file = Path(args.env_file)
    env: dict[str, str] = dict(os.environ)
    load_dotenv(env_file, env)

    _RUNTIME_SECRETS.clear()  # fresh registry per invocation (tests call main() repeatedly)

    # Everything that can see a secret runs inside this scrubbed boundary:
    # secrets are registered the moment they exist (env keys here; fetched
    # keys and generated passwords at their creation sites), every error
    # print routes through _scrub(), and the top-level handler scrubs the
    # message AND traceback before printing. No secret reaches stdout/stderr.
    _register_secret(env.get(_SERVICE_ROLE_ENV, ""), "SERVICE_ROLE_KEY")
    _register_secret(env.get(_ACCESS_TOKEN_ENV, ""), "ACCESS_TOKEN")
    own_client = http is None
    if own_client:
        import httpx
        http = httpx.Client()
    try:
        if args.cleanup:
            return cleanup(args, env, env_file, http)
        return provision(args, env, env_file, http)
    except Exception:
        print(_scrub(f"ERROR: {traceback.format_exc()}"), file=sys.stderr)
        return 1
    finally:
        if own_client:
            http.close()


if __name__ == "__main__":
    sys.path.insert(0, str(_SCRIPT_DIR))
    sys.exit(main())
