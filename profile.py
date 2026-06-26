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


def _validate_oauth_block(data: dict[str, Any]) -> None:
    """Validate the optional ``oauth.delegated_send`` block shape.

    Schema (every field optional — the OAuth probes skip when a field is absent):

        oauth:
          delegated_send:
            provider: google            # google | microsoft (free-form string)
            authorize_url: <app route that initiates the flow / 302s to the AS>
            redirect_uris: [<callback url>, ...]
            token_endpoint: <app BFF token-exchange route>
            required_scopes: [<scope the app legitimately needs>, ...]
            send_endpoints:   [{path: <str>, method: <str>, probe_body: <map>}, ...]
            status_endpoints: [{path: <str>, method: <str>}, ...]

    ``send_endpoints[].probe_body`` is the operator-supplied request body (e.g. a
    safe test recipient) the §P1-D delegated-send write-probe sends; without it
    the probe skips rather than sending a blind/malformed request. ``method``
    defaults to POST (send) / GET (status) when omitted.

    Raises ``ValueError`` if a present field has the wrong type, so a malformed
    profile fails loudly at load time rather than a probe silently misreading it.
    """
    oauth = data.get("oauth")
    if oauth is None:
        return
    if not isinstance(oauth, dict):
        raise ValueError(
            f"Profile field 'oauth' must be a mapping, got {type(oauth).__name__}"
        )
    ds = oauth.get("delegated_send")
    if ds is None:
        return
    if not isinstance(ds, dict):
        raise ValueError(
            "Profile field 'oauth.delegated_send' must be a mapping, "
            f"got {type(ds).__name__}"
        )

    for str_field in ("provider", "authorize_url", "token_endpoint"):
        val = ds.get(str_field)
        if val is not None and not isinstance(val, str):
            raise ValueError(
                f"Profile field 'oauth.delegated_send.{str_field}' must be a "
                f"string, got {type(val).__name__}"
            )

    for list_field in ("redirect_uris", "required_scopes"):
        val = ds.get(list_field)
        if val is None:
            continue
        if not isinstance(val, list) or not all(isinstance(item, str) for item in val):
            raise ValueError(
                f"Profile field 'oauth.delegated_send.{list_field}' must be a "
                f"list of strings, got {type(val).__name__}"
            )

    for ep_field in ("send_endpoints", "status_endpoints"):
        val = ds.get(ep_field)
        if val is None:
            continue
        if not isinstance(val, list):
            raise ValueError(
                f"Profile field 'oauth.delegated_send.{ep_field}' must be a list "
                f"of endpoint mappings, got {type(val).__name__}"
            )
        for item in val:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise ValueError(
                    f"Each entry in 'oauth.delegated_send.{ep_field}' must be a "
                    "mapping with a string 'path' field"
                )
            method = item.get("method")
            if method is not None and not isinstance(method, str):
                raise ValueError(
                    f"Entry method in 'oauth.delegated_send.{ep_field}' must be a "
                    f"string when present, got {type(method).__name__}"
                )
            # probe_body drives the §P1-D delegated-send write-probe. A non-mapping
            # value (e.g. a bare string) is coerced to {} downstream, which would
            # SILENTLY skip the only live token-leakage check — reject it at load
            # so a misconfigured profile fails loudly instead of looking clean.
            probe_body = item.get("probe_body")
            if probe_body is not None and not isinstance(probe_body, dict):
                raise ValueError(
                    f"probe_body in 'oauth.delegated_send.{ep_field}' must be a "
                    f"mapping when present, got {type(probe_body).__name__}"
                )


def _validate_step(step: Any, ctx: str) -> None:
    """Validate a ``{path, method, probe_body}`` step mapping (``path`` required).

    Shared by the ``business_logic`` flow/quota validators. ``method`` and
    ``probe_body`` are optional but type-checked when present so a misconfigured
    step fails at load time rather than a probe silently misreading it.
    """
    if not isinstance(step, dict) or not isinstance(step.get("path"), str):
        raise ValueError(f"'{ctx}' must be a mapping with a string 'path' field")
    method = step.get("method")
    if method is not None and not isinstance(method, str):
        raise ValueError(
            f"'{ctx}.method' must be a string when present, got {type(method).__name__}"
        )
    probe_body = step.get("probe_body")
    if probe_body is not None and not isinstance(probe_body, dict):
        raise ValueError(
            f"'{ctx}.probe_body' must be a mapping when present, got "
            f"{type(probe_body).__name__}"
        )


def _validate_status_list(value: Any, ctx: str) -> None:
    """Validate an optional list-of-HTTP-status-codes field (ints, not bools)."""
    if value is None:
        return
    if not isinstance(value, list) or not all(
        isinstance(s, int) and not isinstance(s, bool) for s in value
    ):
        raise ValueError(f"'{ctx}' must be a list of integer status codes, got {value!r}")


def _validate_business_logic_block(data: dict[str, Any]) -> None:
    """Validate the optional ``business_logic`` block shape (§P2-G probes).

    Schema (every field optional — the business-logic probes skip cleanly when a
    section is absent; a present field must have the right type or a probe would
    misread it):

        business_logic:
          flows:                        # step-sequence enforcement (V2.3.1 / CWE-841)
            - name: <str>               # optional label shown in the report
              gated_step:               # the step that MUST reject when called out of order
                path: <str>             # required (root-relative, e.g. /checkout/confirm)
                method: <str>           # optional, defaults POST
                probe_body: <map>       # optional request body
              reject_statuses: [<int>]  # optional; statuses that count as a correct rejection
              success_signal: <str>     # optional; substring proving the gated action ran
          quota:                        # per-user quota / anti-automation (V2.4.1 / CWE-799)
            endpoint:
              path: <str>               # required
              method: <str>             # optional, defaults POST
              probe_body: <map>         # optional
            burst: <int>                # optional; number of requests to send (>=2)
            limit_statuses: [<int>]     # optional; statuses that indicate the quota fired

    A flow's ``gated_step`` and the quota ``endpoint`` are required *within* their
    block (a flow with no gated step, or a quota with no endpoint, cannot drive a
    probe). Raises ``ValueError`` on any shape error, mirroring
    ``_validate_oauth_block`` — a malformed profile fails loudly at load rather
    than a probe silently skipping and overstating coverage.
    """
    bl = data.get("business_logic")
    if bl is None:
        return
    if not isinstance(bl, dict):
        raise ValueError(
            f"Profile field 'business_logic' must be a mapping, got {type(bl).__name__}"
        )

    flows = bl.get("flows")
    if flows is not None:
        if not isinstance(flows, list):
            raise ValueError(
                "Profile field 'business_logic.flows' must be a list of flow "
                f"mappings, got {type(flows).__name__}"
            )
        for flow in flows:
            if not isinstance(flow, dict):
                raise ValueError("Each entry in 'business_logic.flows' must be a mapping")
            _validate_step(flow.get("gated_step"), "business_logic.flows[].gated_step")
            name = flow.get("name")
            if name is not None and not isinstance(name, str):
                raise ValueError(
                    "'business_logic.flows[].name' must be a string when present, "
                    f"got {type(name).__name__}"
                )
            signal = flow.get("success_signal")
            if signal is not None and not isinstance(signal, str):
                raise ValueError(
                    "'business_logic.flows[].success_signal' must be a string when "
                    f"present, got {type(signal).__name__}"
                )
            _validate_status_list(
                flow.get("reject_statuses"), "business_logic.flows[].reject_statuses"
            )

    quota = bl.get("quota")
    if quota is not None:
        if not isinstance(quota, dict):
            raise ValueError(
                "Profile field 'business_logic.quota' must be a mapping, got "
                f"{type(quota).__name__}"
            )
        _validate_step(quota.get("endpoint"), "business_logic.quota.endpoint")
        burst = quota.get("burst")
        if burst is not None and (
            not isinstance(burst, int) or isinstance(burst, bool) or burst < 2
        ):
            # >= 2: a single request can never observe a per-user limit (the
            # control only shows as the Nth+1 rejection), so burst=1 would always
            # mis-read as 'quota absent'.
            raise ValueError(
                f"'business_logic.quota.burst' must be an integer >= 2 when present "
                f"(a single request cannot observe a quota), got {burst!r}"
            )
        _validate_status_list(
            quota.get("limit_statuses"), "business_logic.quota.limit_statuses"
        )


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

    # Validate the optional oauth/delegated_send block (used by the §P1-B OAuth
    # client-observable probes and §P1-D token-storage probe). Shape only — the
    # probes skip cleanly when fields are absent, so every field is optional, but
    # a present field must have the right type or a probe would misread it.
    _validate_oauth_block(data)

    # Validate the optional business_logic block (§P2-G step-sequence + per-user
    # quota probes). Shape only — the probes skip cleanly when a section is
    # absent, but a present field must be correctly typed or a probe would
    # misread it and silently skip.
    _validate_business_logic_block(data)

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
