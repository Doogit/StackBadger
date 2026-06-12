"""Profile loader for the pentest harness.

Usage:
    from profile import load_profile
    profile = load_profile("profiles/clerk-supabase-example.yaml")
    print(profile.target.base_url)
    print(profile.stack.auth)
    print(profile.endpoints.authenticated)
    print(profile.supabase.tables.user_facing)
"""

from __future__ import annotations

import yaml
from pathlib import Path
from typing import Any


class _AttrDict:
    """Wraps a dict so keys are accessible as attributes.

    Missing keys return None rather than raising AttributeError so callers
    can safely access optional profile sections without guard clauses.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._raw_data = data
        for key, value in data.items():
            if isinstance(value, dict):
                object.__setattr__(self, key, _AttrDict(value))
            elif isinstance(value, list):
                object.__setattr__(self, key, _wrap_list(value))
            else:
                object.__setattr__(self, key, value)

    def __getattr__(self, name: str) -> None:  # type: ignore[return]
        # Return None for missing optional sections instead of raising.
        return None

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like get() for safe access with a custom default."""
        val = getattr(self, key)
        return val if val is not None else default

    def __getitem__(self, key: str) -> Any:
        """Dict-like bracket access, required for keys with special chars."""
        return self._raw_data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._raw_data

    def __iter__(self):
        return iter(self._raw_data)

    def items(self):
        return self._raw_data.items()

    def keys(self):
        return self._raw_data.keys()

    def values(self):
        return self._raw_data.values()

    def __repr__(self) -> str:
        return f"_AttrDict({self._raw_data!r})"


def _wrap_list(lst: list[Any]) -> list[Any]:
    """Recursively wrap dicts inside lists."""
    result = []
    for item in lst:
        if isinstance(item, dict):
            result.append(_AttrDict(item))
        elif isinstance(item, list):
            result.append(_wrap_list(item))
        else:
            result.append(item)
    return result


class Profile:
    """Typed view over a parsed YAML profile.

    Attributes correspond to top-level YAML keys.  Accessing a missing
    optional section (e.g. ``profile.supabase_rpcs`` when the key is absent)
    returns ``None`` rather than raising.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data
        for key, value in data.items():
            if isinstance(value, dict):
                object.__setattr__(self, key, _AttrDict(value))
            elif isinstance(value, list):
                object.__setattr__(self, key, _wrap_list(value))
            else:
                object.__setattr__(self, key, value)

    def __getattr__(self, name: str) -> None:  # type: ignore[return]
        return None

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like get() for safe access with a custom default."""
        val = getattr(self, key)
        return val if val is not None else default

    def raw(self) -> dict[str, Any]:
        """Return the original parsed dict."""
        return self._data


def resolve_profile_path(default_dir: str | Path | None = None) -> str:
    """Resolve the active profile path from CLI args or env var.

    Resolution order:
      1. ``--profile <path>`` in ``sys.argv``  (honors pytest CLI option)
      2. ``PENTEST_PROFILE`` environment variable

    Raises ``ValueError`` if no profile is specified via either mechanism.
    This is intentional for R12 portability: the harness must never silently
    default to a site-specific profile file.

    This is safe to call at module-import / collection time, before pytest
    fixtures are available.
    """
    import sys as _sys
    import os as _os

    # 1. Parse --profile from sys.argv (matches conftest.py pytest_addoption).
    for i, arg in enumerate(_sys.argv):
        if arg == "--profile" and i + 1 < len(_sys.argv):
            return _sys.argv[i + 1]
        if arg.startswith("--profile="):
            return arg.split("=", 1)[1]

    # 2. Environment variable.
    env = _os.environ.get("PENTEST_PROFILE")
    if env:
        return env

    raise ValueError(
        "No profile specified. Pass --profile <path> or set the "
        "PENTEST_PROFILE environment variable."
    )


def _resolve_payment_path(data: dict, path_key: str) -> Any:
    """Return the first truthy ``path_key`` across all payment config blocks.

    Consults the modern ``payments`` block plus the legacy ``payments_config`` /
    ``payments_cfg`` aliases independently, so a non-empty block missing the key
    does not mask a sibling block that supplies it. Non-dict blocks are skipped.
    """
    for key in ("payments", "payments_config", "payments_cfg"):
        block = data.get(key)
        if isinstance(block, dict) and block.get(path_key):
            return block.get(path_key)
    return None


def load_profile(path: str | Path) -> Profile:
    """Parse a YAML profile file and return a :class:`Profile` object.

    Args:
        path: Path to the YAML profile file.

    Returns:
        A :class:`Profile` instance with typed attribute access.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If ``target.base_url`` is missing (required field).
        yaml.YAMLError: If the file is not valid YAML.
    """
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Profile not found: {resolved}")

    with resolved.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise ValueError(f"Profile must be a YAML mapping, got {type(data).__name__}")

    # Validate required fields.
    target = data.get("target")
    if not isinstance(target, dict) or not target.get("base_url"):
        raise ValueError("Profile is missing required field: target.base_url")

    # Validate optional probe-exclusion fields: must be lists of strings when
    # present. (No emptiness check — the effective list is always the union
    # with the defaults; see exclusions.py.)
    for _excl_field in ("exclude_paths", "exclude_tables"):
        _excl_val = data.get(_excl_field)
        if _excl_val is None:
            continue
        if not isinstance(_excl_val, list) or not all(
            isinstance(item, str) for item in _excl_val
        ):
            raise ValueError(
                f"Profile field '{_excl_field}' must be a list of strings, "
                f"got {type(_excl_val).__name__}"
            )

    # Validate the optional auth block: auth.verify_path must be a root-relative
    # path string when present (None is fine — the assembler injects a null
    # default into frozen runtime profiles).
    auth_block = data.get("auth")
    if auth_block is not None:
        if not isinstance(auth_block, dict):
            raise ValueError(
                f"Profile field 'auth' must be a mapping, got {type(auth_block).__name__}"
            )
        verify_path = auth_block.get("verify_path")
        if verify_path is not None:
            if not isinstance(verify_path, str) or not verify_path.startswith("/"):
                raise ValueError(
                    "Profile field 'auth.verify_path' must be a string path "
                    f"starting with '/', got {verify_path!r}"
                )

    # Warn if source_file_map references endpoints not declared in the profile.
    import warnings as _warnings

    # Warn when a known auth/storage/payments provider is declared but its
    # required config block is absent.  These are warnings, not errors, because
    # auto-discovery may populate the values at runtime.
    stack = data.get("stack") or {}
    auth_provider = stack.get("auth")
    storage_provider = stack.get("storage")
    payments_raw = stack.get("payments")
    # payments may be a string (single provider) or a list (multiple).
    if isinstance(payments_raw, str):
        payments_list = [payments_raw]
    elif isinstance(payments_raw, list):
        payments_list = payments_raw
    else:
        payments_list = []

    if auth_provider == "firebase" and not data.get("firebase"):
        _warnings.warn(
            "stack.auth is 'firebase' but no 'firebase' config block found. "
            "Add a 'firebase' block with api_key and project_id, or let "
            "discovery populate it.",
            stacklevel=2,
        )
    if auth_provider == "nextauth" and not data.get("nextauth"):
        _warnings.warn(
            "stack.auth is 'nextauth' but no 'nextauth' config block found. "
            "Add a 'nextauth' block with signin_path and session_path, or let "
            "discovery populate it.",
            stacklevel=2,
        )
    if auth_provider == "supabase-auth" and not data.get("supabase"):
        _warnings.warn(
            "stack.auth is 'supabase-auth' but no 'supabase' config block found. "
            "Add a 'supabase' block with at least project_url, or let "
            "discovery populate it.",
            stacklevel=2,
        )
    if storage_provider == "s3" and not data.get("aws"):
        _warnings.warn(
            "stack.storage is 's3' but no 'aws' config block found. "
            "Add an 'aws' block with s3_bucket and s3_region.",
            stacklevel=2,
        )
    if storage_provider == "r2" and not data.get("cloudflare"):
        _warnings.warn(
            "stack.storage is 'r2' but no 'cloudflare' config block found. "
            "Add a 'cloudflare' block with r2_account_id and r2_bucket.",
            stacklevel=2,
        )
    if "paddle" in payments_list:
        if not _resolve_payment_path(data, "paddle_webhook_path"):
            _warnings.warn(
                "stack.payments contains 'paddle' but payments.paddle_webhook_path "
                "is not set. Add it under a 'payments' block or legacy "
                "payments_config/payments_cfg block.",
                stacklevel=2,
            )
    if "lemonsqueezy" in payments_list:
        if not _resolve_payment_path(data, "lemonsqueezy_webhook_path"):
            _warnings.warn(
                "stack.payments contains 'lemonsqueezy' but "
                "payments.lemonsqueezy_webhook_path is not set. "
                "Add it under a 'payments' block or legacy payments_config/payments_cfg block.",
                stacklevel=2,
            )

    source_file_map = data.get("source_file_map", {})
    if source_file_map and isinstance(source_file_map, dict):
        declared_paths: set[str] = set()
        for group in (data.get("endpoints") or {}).values():
            if isinstance(group, list):
                for ep in group:
                    if isinstance(ep, dict) and ep.get("path"):
                        declared_paths.add(ep["path"])
        for sfm_path in source_file_map:
            if sfm_path not in declared_paths:
                _warnings.warn(
                    f"source_file_map key '{sfm_path}' does not match any "
                    f"declared endpoint path",
                    stacklevel=2,
                )

    return Profile(data)
