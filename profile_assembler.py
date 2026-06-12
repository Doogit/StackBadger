"""Runtime profile assembler for the pentest harness.

Merges live-discovered config with optional YAML overrides to produce
a complete runtime profile without any pre-authored secrets.

Usage:
    from profile_assembler import assemble_profile
    profile = assemble_profile("https://example.com")
    profile = assemble_profile("https://example.com", yaml_path="profiles/clerk-supabase-example.yaml")
"""

from __future__ import annotations

import os
import sys
from typing import Any

from discover import discover_live
from exclusions import effective_exclude_paths, effective_exclude_tables
from profile import Profile, load_profile
from providers import ProviderManifest

# Default stack used for the canonical black-box target (Clerk + Supabase + Stripe) and
# whenever live discovery fingerprints nothing. Keeping these defaults lets the
# marker-gated suite (@pytest.mark.clerk/.supabase/.stripe) run in discovery-only
# mode without an explicit profile.
_DEFAULT_STACK: dict[str, str] = {
    "auth": "clerk",
    "database": "supabase",
    "payments": "stripe",
    "hosting": "netlify",
    "storage": "supabase",
}

# The auth provider of the default stack. A manifest whose auth is this value
# (or unfingerprinted/None) is treated as the canonical-target family and
# inherits the full default stack; any other auth provider gets a clean
# manifest-only stack. Named so the link between "the default stack's auth" and
# "who inherits defaults" is explicit rather than a bare string literal.
_DEFAULT_STACK_AUTH: str = _DEFAULT_STACK["auth"]


def _manifest_has_signal(manifest: "ProviderManifest | None") -> bool:
    """Return True if a ProviderManifest carries any positive fingerprint.

    A manifest with no auth/database/storage/payments signal, no S3 flag, and
    an empty (or only-``service_role_key_found=False``) extracted_config is
    treated as "nothing detected" — the caller then falls back to the default
    stack. ``manifest is None`` (e.g. WAF-blocked discovery, or a mocked
    discover_live return that omits the ``providers`` key) also returns False.
    """
    if manifest is None:
        return False
    cfg = getattr(manifest, "extracted_config", None) or {}
    # service_role_key_found is a bool that is legitimately False, so it must
    # not count as a signal on its own; any *other* truthy config value does.
    other_config_signal = any(
        bool(v) for k, v in cfg.items() if k != "service_role_key_found"
    )
    role_key_signal = bool(cfg.get("service_role_key_found"))
    return bool(
        manifest.auth
        or manifest.database
        or manifest.storage
        or manifest.payments
        or manifest.s3_compatible
        or other_config_signal
        or role_key_signal
    )


def _resolve_stack(manifest: "ProviderManifest | None") -> dict[str, Any]:
    """Build the ``stack`` block from a discovered ProviderManifest.

    Rules:
      - Nothing fingerprinted -> the full default Clerk/Supabase/Stripe stack.
      - Clerk (or no auth) fingerprinted -> start from the default stack and
        override only the fields the manifest positively detected. This keeps
        Stripe/Supabase marker gating intact for the canonical target, where
        Stripe is never fingerprinted (``detect_providers`` has no Stripe
        pattern) and must remain the default.
      - A non-Clerk auth provider fingerprinted -> derive the stack purely from
        the manifest so Clerk-stack defaults never leak onto a different stack.

    Note: a manifest with some signal but ``auth is None`` (e.g. a Supabase DB
    detected but no auth provider fingerprinted) is intentionally treated as the
    canonical-target family and keeps ``auth='clerk'``. This protects the
    canonical no-profile run from a flaky Clerk-key miss; non-Clerk auth targets
    (incl. Supabase Auth, which shares Supabase's fingerprint and is not
    auto-detected) must be named explicitly via ``--profile``.
    """
    if not _manifest_has_signal(manifest):
        return dict(_DEFAULT_STACK)

    inherits_defaults = manifest.auth in (None, _DEFAULT_STACK_AUTH)
    stack: dict[str, Any] = dict(_DEFAULT_STACK) if inherits_defaults else {}
    if manifest.auth:
        stack["auth"] = manifest.auth
    if manifest.database:
        stack["database"] = manifest.database
    if manifest.storage:
        stack["storage"] = manifest.storage
    if manifest.payments:
        # Preserve the single-string shape the marker gating expects when only
        # one provider is present; use a list for genuine multi-provider stacks.
        stack["payments"] = (
            manifest.payments[0]
            if len(manifest.payments) == 1
            else list(manifest.payments)
        )
    return stack


def _apply_manifest_config(
    data: dict[str, Any], manifest: "ProviderManifest | None", stack: dict[str, Any]
) -> None:
    """Populate provider config blocks from a manifest's extracted_config.

    Currently fills the ``firebase`` block (api_key, project_id) when the
    resolved stack actually uses Firebase/Firestore, so an incidental Google
    API key on an otherwise-Clerk target does not graft a spurious firebase
    block. These are defaults — YAML and env layers still override them.
    """
    if manifest is None:
        return
    cfg = getattr(manifest, "extracted_config", None) or {}

    uses_firebase = (
        stack.get("auth") == "firebase"
        or stack.get("storage") == "firebase"
        or stack.get("database") == "firestore"
    )
    if uses_firebase:
        firebase: dict[str, Any] = {}
        if cfg.get("firebase_api_key"):
            firebase["api_key"] = cfg["firebase_api_key"]
        if cfg.get("firebase_project_id"):
            firebase["project_id"] = cfg["firebase_project_id"]
        if firebase:
            data.setdefault("firebase", {}).update(firebase)


def assemble_profile(
    target_url: str,
    yaml_path: str | None = None,
) -> Profile:
    """Assemble a runtime profile by merging discovered config with YAML overrides.

    Config precedence (highest wins):
        1. Environment variables (TARGET_BASE_URL, SUPABASE_ANON_KEY, etc.)
        2. Profile YAML explicit values
        3. Live-discovered values from the target site's JS bundle

    Args:
        target_url: The target site URL to discover config from.
        yaml_path: Optional path to a YAML profile for structural overrides
            (endpoints, tables, RPCs). If None, only discovered config is used.

    Returns:
        A :class:`Profile` instance compatible with existing conftest fixtures.

    Raises:
        ValueError: If the assembled profile is missing required fields
            (target.base_url) after all merge layers.
    """
    # Layer 3: Live discovery (lowest precedence).
    discovered = discover_live(target_url)

    # Start building the merged data dict.
    #
    # The stack block is derived from the discovered ProviderManifest when the
    # target was fingerprinted (multi-stack support), and falls back to the
    # default Clerk/Supabase/Stripe stack otherwise. YAML and env layers below
    # still override these values when provided.
    manifest = discovered.get("providers")
    data: dict[str, Any] = {
        "target": {
            "base_url": target_url,
        },
        "stack": _resolve_stack(manifest),
    }

    # Populate provider config blocks (e.g. firebase.api_key) from the manifest.
    _apply_manifest_config(data, manifest, data["stack"])

    # Apply discovered values.
    if discovered.get("api_prefix"):
        data["target"]["api_prefix"] = discovered["api_prefix"]

    if discovered.get("supabase_url") or discovered.get("supabase_anon_key"):
        data["supabase"] = {}
        if discovered.get("supabase_url"):
            data["supabase"]["project_url"] = discovered["supabase_url"]
        if discovered.get("supabase_anon_key"):
            data["supabase"]["anon_key"] = discovered["supabase_anon_key"]

    if discovered.get("clerk_publishable_key") or discovered.get("clerk_fapi_host"):
        data["clerk"] = {}
        if discovered.get("clerk_publishable_key"):
            data["clerk"]["publishable_key"] = discovered["clerk_publishable_key"]
        if discovered.get("clerk_fapi_host"):
            data["clerk"]["frontend_api"] = discovered["clerk_fapi_host"]

    # Layer 2: YAML profile overrides (middle precedence).
    if yaml_path:
        yaml_profile = load_profile(yaml_path)
        yaml_data = yaml_profile.raw()
        data = _deep_merge(data, yaml_data)
        # The CLI target_url must not be overwritten by YAML's target.base_url.
        # YAML provides structural metadata; the target is always the CLI arg.
        data.setdefault("target", {})["base_url"] = target_url

    # Layer 1: Environment variable overrides (highest precedence).
    env_overrides = _env_overrides()
    if env_overrides:
        data = _deep_merge(data, env_overrides)

    # Probe exclusions: bake the effective lists (union of user-supplied and
    # the default-on lists) into the assembled profile so every seam — pytest
    # enumeration, discovery, ZAP plan injection — reads ONE explicit value
    # from the frozen artifact. An empty/absent user list still gets the
    # defaults; there is no opt-out via the profile.
    data["exclude_paths"] = effective_exclude_paths(data.get("exclude_paths"))
    data["exclude_tables"] = effective_exclude_tables(data.get("exclude_tables"))

    # auth.verify_path: optional fast-fail route, carried verbatim from the
    # YAML layer with a null default. NEVER inferred — a guessed path that
    # 200s anonymously (e.g. a CDN-cached page) would fake a passing check.
    auth_block = data.get("auth")
    if not isinstance(auth_block, dict):
        data["auth"] = {"verify_path": None}
    else:
        auth_block.setdefault("verify_path", None)

    # Validate minimum required fields.
    target = data.get("target")
    if not isinstance(target, dict) or not target.get("base_url"):
        raise ValueError(
            "Assembled profile is missing required field: target.base_url. "
            "Provide a target URL or set TARGET_BASE_URL env var."
        )

    supabase = data.get("supabase", {})
    if not supabase.get("project_url"):
        print(
            "[warn] assemble_profile: supabase.project_url not discovered and "
            "not in YAML. Supabase-dependent tests will be skipped.",
            file=sys.stderr,
        )
    if not supabase.get("anon_key"):
        print(
            "[warn] assemble_profile: supabase.anon_key not discovered and "
            "not in YAML. Supabase-dependent tests will be skipped.",
            file=sys.stderr,
        )

    return Profile(data)


def _env_overrides() -> dict[str, Any]:
    """Build an override dict from recognized environment variables."""
    overrides: dict[str, Any] = {}

    target_url = os.environ.get("TARGET_BASE_URL")
    if target_url:
        overrides.setdefault("target", {})["base_url"] = target_url

    anon_key = os.environ.get("SUPABASE_ANON_KEY")
    if anon_key:
        overrides.setdefault("supabase", {})["anon_key"] = anon_key

    project_url = os.environ.get("SUPABASE_PROJECT_URL")
    if project_url:
        overrides.setdefault("supabase", {})["project_url"] = project_url

    fapi_host = os.environ.get("CLERK_FAPI_HOST")
    if fapi_host:
        overrides.setdefault("clerk", {})["frontend_api"] = fapi_host

    return overrides


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep-merge *override* into *base*, with override values winning.

    - Dicts are merged recursively.
    - None values in override are skipped (YAML sections with only comments
      parse as null — these must not clobber discovered values).
    - Lists and other non-dict values from override replace base entirely.
    """
    result = dict(base)
    for key, value in override.items():
        if value is None:
            # Skip null overrides — they represent empty YAML sections
            # (e.g., "clerk:" with only comments), not intentional deletions.
            continue
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
