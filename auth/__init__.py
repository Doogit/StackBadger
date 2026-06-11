"""Auth adapter factory for the pentest harness."""

from __future__ import annotations

import os

from .base import AbstractAuthAdapter, AuthConfigError
from .clerk import ClerkAuthAdapter
from .firebase import FirebaseAuthAdapter
from .nextauth import NextAuthAdapter
from .supabase_auth import SupabaseAuthAdapter

_ADAPTER_REGISTRY: dict[str, callable] = {
    "clerk": lambda profile: _create_clerk_adapter(profile),
    "firebase": lambda profile: _create_firebase_adapter(profile),
    "nextauth": lambda profile: _create_nextauth_adapter(profile),
    "supabase-auth": lambda profile: _create_supabase_auth_adapter(profile),
}

_SUPPORTED_ADAPTERS = list(_ADAPTER_REGISTRY.keys())


def create_adapter(profile) -> AbstractAuthAdapter:
    """Return an auth adapter instance driven by ``profile.stack.auth``.

    Looks up the auth value in :data:`_ADAPTER_REGISTRY` and delegates
    construction to the registered factory callable.

    Args:
        profile: A parsed YAML profile (_AttrDict).  ``profile.stack.auth``
                 must be one of the supported adapter names.

    Returns:
        An :class:`AbstractAuthAdapter` instance for the profile's auth stack.

    Raises:
        AuthConfigError: If ``profile.stack.auth`` names an unsupported
            adapter or is empty, or if required credentials are missing.
    """
    auth_value = (profile.stack and profile.stack.auth) or ""
    factory = _ADAPTER_REGISTRY.get(auth_value)
    if factory is not None:
        return factory(profile)
    raise AuthConfigError(
        f"Unsupported auth adapter '{auth_value}'. "
        f"Supported adapters: {_SUPPORTED_ADAPTERS}"
    )


def _create_clerk_adapter(profile) -> ClerkAuthAdapter:
    """Build a ClerkAuthAdapter from profile + env vars."""
    # FAPI host: from profile.clerk.frontend_api or env var.
    fapi_host = os.environ.get("CLERK_FAPI_HOST") or ""
    if not fapi_host:
        fapi_host = (profile.clerk and profile.clerk.frontend_api) or ""
    if not fapi_host:
        raise AuthConfigError(
            "Clerk FAPI host not available. Set CLERK_FAPI_HOST env var "
            "or include clerk.frontend_api in the profile YAML."
        )

    # Ensure scheme is present.
    if not fapi_host.startswith("http"):
        fapi_host = f"https://{fapi_host}"

    # Build accounts dict from env vars.
    accounts: dict[str, dict[str, str]] = {}
    email_a = os.environ.get("PENTEST_USER_A_EMAIL", "")
    pass_a = os.environ.get("PENTEST_USER_A_PASSWORD", "")
    if email_a and pass_a:
        accounts["user_a"] = {"email": email_a, "password": pass_a}

    email_b = os.environ.get("PENTEST_USER_B_EMAIL", "")
    pass_b = os.environ.get("PENTEST_USER_B_PASSWORD", "")
    if email_b and pass_b:
        accounts["user_b"] = {"email": email_b, "password": pass_b}

    if not accounts:
        raise AuthConfigError(
            "No test account credentials found. Set PENTEST_USER_A_EMAIL and "
            "PENTEST_USER_A_PASSWORD environment variables."
        )

    # Target origin for CORS.
    target_origin = (profile.target and profile.target.base_url) or None

    return ClerkAuthAdapter(
        fapi_host=fapi_host,
        accounts=accounts,
        target_origin=target_origin,
    )


def _create_firebase_adapter(profile) -> FirebaseAuthAdapter:
    """Build a FirebaseAuthAdapter from profile + env vars."""
    # API key: from env var or profile.firebase.api_key.
    api_key = os.environ.get("FIREBASE_API_KEY") or ""
    if not api_key:
        api_key = (
            (profile.firebase and profile.firebase.api_key) or ""
            if hasattr(profile, "firebase") and profile.firebase
            else ""
        )
    if not api_key:
        raise AuthConfigError(
            "Firebase API key not available. Set FIREBASE_API_KEY env var "
            "or include firebase.api_key in the profile YAML."
        )

    # Build accounts dict from env vars (same pattern as Clerk).
    accounts: dict[str, dict[str, str]] = {}
    email_a = os.environ.get("PENTEST_USER_A_EMAIL", "")
    pass_a = os.environ.get("PENTEST_USER_A_PASSWORD", "")
    if email_a and pass_a:
        accounts["user_a"] = {"email": email_a, "password": pass_a}

    email_b = os.environ.get("PENTEST_USER_B_EMAIL", "")
    pass_b = os.environ.get("PENTEST_USER_B_PASSWORD", "")
    if email_b and pass_b:
        accounts["user_b"] = {"email": email_b, "password": pass_b}

    if not accounts:
        raise AuthConfigError(
            "No test account credentials found. Set PENTEST_USER_A_EMAIL and "
            "PENTEST_USER_A_PASSWORD environment variables."
        )

    # Target origin for CORS.
    target_origin = (profile.target and profile.target.base_url) or None

    return FirebaseAuthAdapter(
        api_key=api_key,
        accounts=accounts,
        target_origin=target_origin,
    )


def _create_supabase_auth_adapter(profile) -> SupabaseAuthAdapter:
    """Build a SupabaseAuthAdapter from profile + env vars."""
    # Project URL: from env var or profile.supabase.project_url.
    project_url = os.environ.get("SUPABASE_PROJECT_URL") or ""
    if not project_url:
        project_url = (
            (profile.supabase and profile.supabase.project_url) or ""
            if hasattr(profile, "supabase") and profile.supabase
            else ""
        )
    if not project_url:
        raise AuthConfigError(
            "Supabase project URL not available. Set SUPABASE_PROJECT_URL env var "
            "or include supabase.project_url in the profile YAML."
        )

    if not project_url.startswith("https://"):
        raise AuthConfigError(
            f"Supabase project_url must use https:// scheme, got: {project_url[:30]}"
        )

    # Anon key: from env var or profile.supabase.anon_key.
    anon_key = os.environ.get("SUPABASE_ANON_KEY") or ""
    if not anon_key:
        anon_key = (
            (profile.supabase and profile.supabase.anon_key) or ""
            if hasattr(profile, "supabase") and profile.supabase
            else ""
        )
    if not anon_key:
        raise AuthConfigError(
            "Supabase anon key not available. Set SUPABASE_ANON_KEY env var "
            "or include supabase.anon_key in the profile YAML."
        )

    # Build accounts dict from env vars (same pattern as Clerk/Firebase).
    accounts: dict[str, dict[str, str]] = {}
    email_a = os.environ.get("PENTEST_USER_A_EMAIL", "")
    pass_a = os.environ.get("PENTEST_USER_A_PASSWORD", "")
    if email_a and pass_a:
        accounts["user_a"] = {"email": email_a, "password": pass_a}

    email_b = os.environ.get("PENTEST_USER_B_EMAIL", "")
    pass_b = os.environ.get("PENTEST_USER_B_PASSWORD", "")
    if email_b and pass_b:
        accounts["user_b"] = {"email": email_b, "password": pass_b}

    if not accounts:
        raise AuthConfigError(
            "No test account credentials found. Set PENTEST_USER_A_EMAIL and "
            "PENTEST_USER_A_PASSWORD environment variables."
        )

    return SupabaseAuthAdapter(
        project_url=project_url,
        anon_key=anon_key,
        accounts=accounts,
    )


def _create_nextauth_adapter(profile) -> NextAuthAdapter:
    """Build a NextAuthAdapter from profile + env vars."""
    # Base URL: required — from profile.target.base_url (canonical) or
    # profile.target.url (legacy alias per #605).
    base_url = ""
    if profile.target:
        base_url = profile.target.base_url or profile.target.url or ""
    if not base_url:
        raise AuthConfigError(
            "NextAuth adapter requires a target base URL. "
            "Set target.base_url in the profile YAML."
        )

    # Build accounts dict from env vars (same pattern as other adapters).
    accounts: dict[str, dict[str, str]] = {}
    email_a = os.environ.get("PENTEST_USER_A_EMAIL", "")
    pass_a = os.environ.get("PENTEST_USER_A_PASSWORD", "")
    if email_a and pass_a:
        accounts["user_a"] = {"email": email_a, "password": pass_a}

    email_b = os.environ.get("PENTEST_USER_B_EMAIL", "")
    pass_b = os.environ.get("PENTEST_USER_B_PASSWORD", "")
    if email_b and pass_b:
        accounts["user_b"] = {"email": email_b, "password": pass_b}

    if not accounts:
        raise AuthConfigError(
            "No test account credentials found. Set PENTEST_USER_A_EMAIL and "
            "PENTEST_USER_A_PASSWORD environment variables."
        )

    # Optional custom endpoint paths from profile.nextauth config block.
    # Accept both canonical keys (csrf_path, signin_path, ...) and legacy
    # keys (csrf_url, signin_url, ...) that existing profile templates use.
    nextauth_cfg = profile.nextauth if hasattr(profile, "nextauth") and profile.nextauth else None
    path_kwargs: dict[str, str] = {}
    _LEGACY_KEY_MAP = {
        "csrf_path": "csrf_url",
        "signin_path": "signin_url",
        "callback_path": "callback_url",
        "session_path": "session_url",
    }
    if nextauth_cfg:
        for key, legacy_key in _LEGACY_KEY_MAP.items():
            val = getattr(nextauth_cfg, key, None) or getattr(nextauth_cfg, legacy_key, None)
            if val:
                path_kwargs[key] = val

    return NextAuthAdapter(
        base_url=base_url,
        accounts=accounts,
        **path_kwargs,
    )
