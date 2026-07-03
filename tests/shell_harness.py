"""Shared harness for shell-level run.sh tests.

run.sh ``cd``s to its own directory and sources ``./.env``, so testing it in
place would couple tests to the developer's real ``.env`` and repo state. Each
test instead gets a SANDBOX copy of the repo (sources only, never ``.env``)
and invokes run.sh there via bash with a controlled environment.

Used by ``test_confirm_target.py``, ``test_authorization_gate.py``, and the
run.sh-delegation tests in ``test_doctor.py``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _git_bash_candidates() -> list[str]:
    return [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
    ]


def resolve_bash() -> str | None:
    """Prefer a real Git Bash over the WindowsApps WSL shim on Windows.

    `shutil.which("bash")` often resolves to `...\\WindowsApps\\bash.exe`, which
    launches the deprecated WSL shim and can hang these shell-level tests.
    Git Bash behaves like the non-interactive Bash runner the harness expects.
    """
    bash = shutil.which("bash")
    if bash and "windowsapps" not in bash.lower():
        return bash
    for candidate in _git_bash_candidates():
        if Path(candidate).exists():
            return candidate
    return bash


BASH = resolve_bash()

requires_bash = pytest.mark.skipif(BASH is None, reason="bash not available on PATH")

# Sandbox contents: everything run.sh + doctor.py can touch up to the
# discovery step. Tests, docs, reports output, and (critically) .env are
# never copied.
_SANDBOX_DIRS = ("auth", "zap", "reports", "profiles")
_SANDBOX_GLOBS = ("*.py", "run.sh", ".env.example")

# Env vars that would leak the developer's real config into a sandbox run.
_SCRUB_PREFIXES = (
    "PENTEST_",
    "CONFIRM_",
    "SUPABASE_",
    "CLERK_",
    "FIREBASE_",
    "TARGET_BASE_URL",
    "JWT_TOKEN",
    "SESSION_COOKIE",
)


def make_sandbox(tmp_path: Path) -> Path:
    """Copy the repo's source files (no .env, no tests) into tmp_path."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    for pattern in _SANDBOX_GLOBS:
        for src in _REPO_ROOT.glob(pattern):
            if src.is_file():
                shutil.copy2(src, sandbox / src.name)
    for dirname in _SANDBOX_DIRS:
        shutil.copytree(
            _REPO_ROOT / dirname,
            sandbox / dirname,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    return sandbox


def stub_doctor(sandbox: Path, exit_code: int) -> None:
    """Replace the sandbox's doctor.py with a stub exiting *exit_code*."""
    (sandbox / "doctor.py").write_text(
        "import sys\n"
        f"print('[stub-doctor] exiting {exit_code}')\n"
        f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )


def run_sh(
    sandbox: Path,
    args: list[str],
    env_overrides: dict[str, str] | None = None,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess:
    """Invoke ``bash run.sh <args>`` in the sandbox with a scrubbed env."""
    env = {
        k: v
        for k, v in os.environ.items()
        if not any(k.startswith(p) or k == p for p in _SCRUB_PREFIXES)
    }
    # Forward slashes so Git Bash's `command -v` treats it as a path.
    env["PYTHON_BIN"] = sys.executable.replace("\\", "/")
    env.update(env_overrides or {})
    return subprocess.run(
        [BASH, "run.sh", *args],
        cwd=sandbox,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
