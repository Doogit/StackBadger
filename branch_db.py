"""Supabase branch database lifecycle management.

Provides create, wait, and delete operations for disposable Supabase
branch databases used during full-mode pentest runs (--branch flag).

Requires SUPABASE_ACCESS_TOKEN (personal access token from
https://supabase.com/dashboard/account/tokens).
"""

from __future__ import annotations

import sys
import time

import httpx

_API_BASE = "https://api.supabase.com/v1"


def create_branch(
    project_ref: str,
    access_token: str,
    branch_name: str | None = None,
) -> tuple[str, str, str]:
    """Create a Supabase branch database.

    Returns (branch_id, branch_url, branch_anon_key).
    """
    if branch_name is None:
        branch_name = f"pentest-{int(time.time())}"

    url = f"{_API_BASE}/projects/{project_ref}/branches"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    resp = httpx.post(
        url,
        json={"branch_name": branch_name, "region": "us-east-1"},
        headers=headers,
        timeout=30.0,
    )

    if resp.status_code not in (200, 201):
        print(
            f"Branch creation failed: HTTP {resp.status_code} — {resp.text[:500]}",
            file=sys.stderr,
        )
        raise RuntimeError(f"Branch creation failed: HTTP {resp.status_code}")

    data = resp.json()
    branch_id = data.get("id", "")
    # The branch database URL follows the pattern: https://<branch_ref>.supabase.co
    db_ref = data.get("ref", data.get("project_ref", ""))
    branch_url = f"https://{db_ref}.supabase.co" if db_ref else ""
    branch_anon_key = data.get("anon_key", "")

    return branch_id, branch_url, branch_anon_key


def wait_for_ready(
    branch_id: str,
    project_ref: str,
    access_token: str,
    timeout: int = 120,
    poll_interval: int = 5,
) -> None:
    """Poll branch status until ACTIVE_HEALTHY or timeout."""
    url = f"{_API_BASE}/projects/{project_ref}/branches/{branch_id}"
    headers = {"Authorization": f"Bearer {access_token}"}
    deadline = time.time() + timeout

    while time.time() < deadline:
        resp = httpx.get(url, headers=headers, timeout=15.0)
        if resp.status_code == 200:
            status = resp.json().get("status", "")
            if status in ("ACTIVE_HEALTHY", "RUNNING"):
                print(f"Branch {branch_id} is ready (status: {status}).", file=sys.stderr)
                return
            print(f"Branch status: {status} — waiting...", file=sys.stderr)
        time.sleep(poll_interval)

    raise TimeoutError(
        f"Branch {branch_id} did not become ready within {timeout}s."
    )


def delete_branch(
    branch_id: str,
    project_ref: str,
    access_token: str,
) -> None:
    """Delete a Supabase branch database."""
    url = f"{_API_BASE}/projects/{project_ref}/branches/{branch_id}"
    headers = {"Authorization": f"Bearer {access_token}"}

    resp = httpx.delete(url, headers=headers, timeout=15.0)
    if resp.status_code in (200, 204, 404):
        print(f"Branch {branch_id} deleted.", file=sys.stderr)
    else:
        # Raise (mirroring create_branch) so a non-2xx/404 response — e.g. an
        # expired or insufficiently-scoped token (403), rate limit (429), or
        # Supabase outage (5xx) — is a non-zero exit. The run.sh cleanup trap
        # relies on that exit status to fire its "manually delete branch"
        # warning; without it the branch DB is silently orphaned.
        print(
            f"Branch deletion returned HTTP {resp.status_code}: {resp.text[:300]}",
            file=sys.stderr,
        )
        raise RuntimeError(
            f"Branch deletion failed: HTTP {resp.status_code}"
        )
