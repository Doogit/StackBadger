"""Dual-output report aggregator.

Merges ZAP JSON + pytest JSON into:
  1. Human-readable HTML (reports/output/report.html)
  2. Machine-readable JSON for agent-driven remediation (reports/output/agent-findings.json)

Usage:
    python -m reports.aggregate \\
        --pytest-report report.json \\
        [--zap-report zap-report.json] \\
        [--evidence-dir reports/evidence/] \\
        [--output-dir reports/output/] \\
        [--profile profiles/mysite.yaml]

Exit codes:
  0 — no findings
  1 — HIGH or CRITICAL findings exist
  2 — only MEDIUM, LOW, or INFO findings (no HIGH/CRITICAL)
  3 — infrastructure error (parse failure, missing inputs)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent

ZAP_RISK_MAP: dict[int, str] = {
    0: "INFO",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
}

# Map test file stem → severity
TEST_SEVERITY_MAP: dict[str, str] = {
    "test_auth_bypass": "HIGH",
    "test_rls_bypass": "HIGH",
    "test_idor": "HIGH",
    "test_storage_bypass": "MEDIUM",
    "test_webhook_spoofing": "HIGH",
    "test_injection": "HIGH",
    "test_file_upload": "MEDIUM",
    "test_auth_flows": "MEDIUM",
    "test_payment_gate": "HIGH",
    "test_api_surface": "MEDIUM",
    "test_cors_headers": "LOW",
    "test_info_disclosure": "LOW",
    "test_anon_session": "MEDIUM",
    "test_firebase_auth_adapter": "MEDIUM",   # adapter hard-stops
    "test_firestore_rules": "HIGH",
    "test_firebase_storage": "HIGH",
    "test_supabase_auth_adapter": "MEDIUM",   # adapter hard-stops
    "test_nextauth_adapter": "MEDIUM",        # adapter hard-stops
    "test_s3_storage": "HIGH",
    "test_webhook_paddle": "HIGH",
    "test_webhook_lemonsqueezy": "MEDIUM",    # replay finding is MEDIUM
    "test_session": "HIGH",                   # V7.4.1 logout/fixation are L1 HIGH
    "test_data_protection": "MEDIUM",         # no-store is MEDIUM; token-in-URL self-escalates to HIGH inline
    "test_oauth_flow": "HIGH",                # token leakage / missing state+PKCE are HIGH; scope/nonce overridden MEDIUM
    "test_mass_assignment": "HIGH",           # persisted privileged field = privilege escalation (CWE-915)
}

# Per-test severity overrides (test function name → severity).
# Takes precedence over file-stem severity.  Used both to upgrade
# (e.g. signature-bypass → HIGH/CRITICAL) and to prevent wrong upgrades
# (e.g. parse-order test stays MEDIUM even when file-stem maps to HIGH).
_TEST_NAME_SEVERITY_OVERRIDES: dict[str, str] = {
    "test_missing_x_signature": "HIGH",
    "test_forged_x_signature": "HIGH",
    "test_missing_paddle_signature": "HIGH",
    "test_empty_paddle_signature": "HIGH",
    "test_forged_paddle_signature": "HIGH",
    "test_body_signature_mismatch": "HIGH",
    # test_event_type_spoofing_bypass: no override — true bypass emits
    # "CRITICAL:" in pytest.fail() which _extract_severity_from_message()
    # picks up; non-bypass failures (405/422) stay at the file-stem default.
    "test_event_type_spoofing_robustness": "HIGH",
    # Parse-order test: non-bypass failure path is MEDIUM (correct category).
    # When the test detects a true bypass (status 200), the pytest.fail message
    # contains "CRITICAL" which the aggregator parses and overrides this entry.
    "test_json_parsing_before_verification": "MEDIUM",
    # Cache-Control no-store probe lives in test_cors_headers.py (file-stem LOW)
    # but is a V14.3.2/CWE-524 data-protection control rated MEDIUM in
    # test_data_protection.py. Override so the same control reports consistently.
    "test_authenticated_response_is_not_cacheable": "MEDIUM",
    # OAuth client controls: scope-minimisation (V10.2.3) and OIDC nonce (V10.5.1)
    # are MEDIUM; the file-stem default (HIGH) covers token leakage / state / PKCE.
    "test_oauth_requests_minimal_scopes": "MEDIUM",
    "test_oauth_oidc_emits_nonce": "MEDIUM",
    # Phase-2 §P2-B/§P2-E probes extend existing modules, so their severity is
    # pinned at the test-function level (independent of the host file's stem),
    # mirroring the cache-control entry above. TRACE/method-hardening is MEDIUM (and
    # would default MEDIUM from the api_surface stem regardless); cookie-authed
    # CSRF is HIGH (acting as the victim); frame-ancestors is a MEDIUM floor in
    # test_cors_headers.py (LOW stem) and self-escalates to HIGH inline when the
    # page is framable by any origin (no X-Frame-Options fallback).
    "test_trace_method_is_rejected": "MEDIUM",
    "test_state_change_requires_anti_csrf_token": "HIGH",
    "test_csp_frame_ancestors_restricts_framing": "MEDIUM",
}

# Per-test category overrides (test function name → category).
# Takes precedence over file-stem category.  Prevents non-signature tests
# in provider-specific files (LemonSqueezy, Paddle) from being classified
# under the provider's webhook-signature category when the test actually
# exercises replay protection, robustness, or spoofing concerns.
_TEST_NAME_CATEGORY_OVERRIDES: dict[str, str] = {
    # Replay / idempotency probes
    "test_replay_protection_informational": "webhook_replay",
    # Robustness probes (handler crash on unknown event types)
    "test_event_type_spoofing_robustness": "webhook_robustness",
    "test_unexpected_event_type": "webhook_robustness",
    # Spoofing / bypass probes (forged event accepted)
    "test_event_type_spoofing_bypass": "webhook_spoofing",
    # Parse-order probes (JSON deserialised before HMAC gate)
    "test_json_parsing_before_verification": "webhook_parse_order",
    # Phase-2 §P2-B/§P2-E probes extend existing modules (test_api_surface.py /
    # test_cors_headers.py); route each to its own ASVS category so the finding
    # is not filed under the host module's default (api_surface / cors_headers).
    "test_trace_method_is_rejected": "method_hardening",
    "test_state_change_requires_anti_csrf_token": "csrf",
    "test_csp_frame_ancestors_restricts_framing": "frame_ancestors",
}

_STANDALONE_FINDING_CATEGORY_OVERRIDES: dict[str, str] = {
    "lemonsqueezy_no_replay_protection": "webhook_replay",
}

_STANDALONE_FINDING_FAILED_TEST_NAMES: dict[str, str] = {
    "lemonsqueezy_no_replay_protection": "test_replay_protection_informational",
}

# Map test file stem → security category
TEST_CATEGORY_MAP: dict[str, str] = {
    "test_auth_bypass": "auth_bypass",
    "test_rls_bypass": "rls_bypass",
    "test_idor": "idor",
    "test_storage_bypass": "storage_bypass",
    "test_webhook_spoofing": "webhook_spoofing",
    "test_injection": "injection",
    "test_file_upload": "file_upload",
    "test_auth_flows": "auth_flows",
    "test_payment_gate": "payment_gate",
    "test_api_surface": "api_surface",
    "test_cors_headers": "cors_headers",
    "test_info_disclosure": "info_disclosure",
    "test_anon_session": "anon_session",
    "test_firebase_auth_adapter": "firebase_auth",
    "test_firestore_rules": "firestore_rules",
    "test_firebase_storage": "firebase_storage",
    "test_supabase_auth_adapter": "supabase_auth",
    "test_nextauth_adapter": "nextauth",
    "test_s3_storage": "s3_storage",
    "test_webhook_paddle": "webhook_paddle",
    "test_webhook_lemonsqueezy": "webhook_lemonsqueezy",
    "test_session": "session",
    "test_data_protection": "data_protection",
    "test_oauth_flow": "oauth",
    "test_mass_assignment": "mass_assignment",
}

# ZAP alert name → endpoint path heuristic
ZAP_ALERT_CATEGORY_MAP: dict[str, str] = {
    "Content Security Policy": "cors_headers",
    "X-Frame-Options": "cors_headers",
    "Strict-Transport-Security": "cors_headers",
    "Cross-Domain Misconfiguration": "cors_headers",
    "SQL Injection": "injection",
    "Server Side Request Forgery": "injection",
    "Remote Code Execution": "injection",
    "Path Traversal": "injection",
    "Information Disclosure": "info_disclosure",
    "Application Error": "info_disclosure",
    "Stack Trace": "info_disclosure",
    "Authentication": "auth_bypass",
    "Session": "auth_bypass",
    "Broken Access Control": "idor",
    "IDOR": "idor",
    "File Upload": "file_upload",
    "Webhook": "webhook_spoofing",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ---------------------------------------------------------------------------
# ID generator
# ---------------------------------------------------------------------------

_CATEGORY_PREFIXES: dict[str, str] = {
    "auth_bypass": "AUTH",
    "rls_bypass": "RLS",
    "idor": "IDOR",
    "storage_bypass": "STOR",
    "webhook_spoofing": "HOOK",
    "injection": "INJ",
    "file_upload": "FUPLOAD",
    "auth_flows": "AFLW",
    "payment_gate": "PAY",
    "api_surface": "API",
    "cors_headers": "CORS",
    "info_disclosure": "INFO",
    "anon_session": "ANON",
    "webhook_replay": "WREPLAY",
    "webhook_robustness": "WROBUST",
    "webhook_parse_order": "WPARSE",
    "zap": "ZAP",
    "firebase_auth": "FBAU",
    "firestore_rules": "FIRE",
    "firebase_storage": "FSTO",
    "supabase_auth": "SUPA",
    "nextauth": "NEXT",
    "s3_storage": "S3ST",
    "webhook_paddle": "PADL",
    "webhook_lemonsqueezy": "LMSQ",
    "session": "SESS",
    "data_protection": "DATAP",
    "oauth": "OAUTH",
    "mass_assignment": "MASS",
    "method_hardening": "METH",
    "csrf": "CSRF",
    "frame_ancestors": "FRAME",
}

# Provider layer categories (direct-API tests, not app endpoints)
_PROVIDER_CATEGORIES: set[str] = {
    "firebase_auth", "firestore_rules", "firebase_storage",
    "supabase_auth", "nextauth", "s3_storage",
    "webhook_paddle", "webhook_lemonsqueezy",
}

# Provider category → architectural layer, shown in the provider-layer report
# table. Authoritative source for the layer column (the template no longer
# carries its own copy). Keys must stay in sync with _PROVIDER_CATEGORIES.
_PROVIDER_LAYER_MAP: dict[str, str] = {
    "firebase_auth": "auth",
    "firestore_rules": "database",
    "firebase_storage": "storage",
    "supabase_auth": "auth",
    "nextauth": "auth",
    "s3_storage": "storage",
    "webhook_paddle": "webhook",
    "webhook_lemonsqueezy": "webhook",
}

_counters: dict[str, int] = {}


def _next_id(category: str) -> str:
    prefix = _CATEGORY_PREFIXES.get(category, "FIND")
    _counters[prefix] = _counters.get(prefix, 0) + 1
    return f"{prefix}-{_counters[prefix]:03d}"


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_zap_report(path: Path) -> list[dict]:
    """Parse ZAP traditional-json-plus format → list of alert dicts."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[warn] Could not parse ZAP report {path}: {exc}", file=sys.stderr)
        return []

    alerts: list[dict] = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            alerts.append(alert)
    return alerts


def load_pytest_report(path: Path) -> dict:
    """Parse pytest-json-report format."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[error] Could not parse pytest report {path}: {exc}", file=sys.stderr)
        sys.exit(3)  # infrastructure error


def _is_standalone_finding_payload(payload: Any) -> bool:
    """Return True when an evidence payload is a reportable standalone finding.

    The ``finding`` slug is the discriminator (node-bound evidence captures never
    carry it); ``severity``/``title``/``description`` need only be present, so a
    finding with a legitimately empty description is not misrouted to the
    node-bound evidence map.
    """
    return (
        isinstance(payload, dict)
        and bool(payload.get("finding"))
        and all(key in payload for key in ("severity", "title", "description"))
    )


def load_evidence(evidence_dir: Path) -> tuple[dict[str, list[dict]], list[dict]]:
    """Load node-bound evidence plus standalone finding payloads."""
    evidence_map: dict[str, list[dict]] = {}
    standalone_findings: list[dict] = []
    if not evidence_dir.exists():
        return evidence_map, standalone_findings
    for fpath in evidence_dir.glob("*.json"):
        try:
            payload = json.loads(fpath.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if _is_standalone_finding_payload(payload):
            standalone_findings.append(payload)
            continue
        # filename = <sanitised_node_id>[_label].json
        # sanitised_node_id = tests/test_foo.py__test_name  (:: → __)
        stem = fpath.stem
        # Strip trailing _<label> segment — heuristic: if last segment
        # doesn't start with a digit or "test", it's a label.
        parts = stem.rsplit("_", 1)
        key = parts[0] if len(parts) > 1 and not parts[1].startswith("test") else stem
        evidence_map.setdefault(key, []).append(payload)
    return evidence_map, standalone_findings


def load_profile(path: Path) -> dict:
    """Load YAML profile; return empty dict on failure."""
    if not path.exists():
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {}


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _extract_endpoint_from_url(url: str, source_file_map: dict) -> tuple[str, str]:
    """Return (endpoint_path, method) from a ZAP instance URL."""
    for ep in source_file_map:
        if ep in url:
            return ep, "GET"
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        for ep in source_file_map:
            if path.endswith(ep.lstrip("/")):
                return ep, "GET"
    except Exception:
        pass
    return url, "GET"


def _affected_files_for_endpoint(endpoint: str, source_file_map: dict) -> list[str]:
    return [source_file_map[endpoint]] if endpoint in source_file_map else []


def _category_from_zap_alert(alert_name: str) -> str:
    for keyword, cat in ZAP_ALERT_CATEGORY_MAP.items():
        if keyword.lower() in alert_name.lower():
            return cat
    return "zap"


def _scope_estimate(severity: str) -> str:
    return {"CRITICAL": "large", "HIGH": "medium", "MEDIUM": "small", "LOW": "trivial", "INFO": "trivial"}.get(severity, "small")


def _remediation_for_category(category: str, severity: str, stack_info: dict) -> str:
    auth_provider = stack_info.get("auth", "the auth provider")
    database = stack_info.get("database", "")
    payments = stack_info.get("payments", "")

    if database == "supabase":
        rls_text = (
            "Audit Supabase RLS policies for all user-facing tables. "
            "Ensure every SELECT/INSERT/UPDATE/DELETE policy uses "
            "`(auth.jwt() ->> 'sub') = user_id` or equivalent org scoping."
        )
        storage_text = (
            "Restrict Supabase Storage bucket policies so only the file owner can read/write. "
            "Use signed URLs with short TTLs for download links. "
            "Validate the file owner claim in the server-side handler before generating signed URLs."
        )
        injection_text = (
            "Use parameterised queries or Supabase RPC with typed parameters. "
            "Never interpolate user input into SQL strings. "
            "Validate and sanitise all inputs at the function boundary."
        )
        anon_text = (
            "Audit the `merge_anon_session` RPC for privilege escalation. "
            "Ensure anonymous session data cannot be merged into a user account "
            "without explicit user consent and re-authentication."
        )
    else:
        rls_text = (
            "Audit row-level access control policies for all user-facing tables. "
            "Ensure every query is scoped to the authenticated user."
        )
        storage_text = (
            "Restrict storage bucket policies so only the file owner can read/write. "
            "Use signed URLs with short TTLs for download links. "
            "Validate the file owner claim in the server-side handler before issuing signed URLs."
        )
        injection_text = (
            "Use parameterised queries with typed parameters. "
            "Never interpolate user input into query strings. "
            "Validate and sanitise all inputs at the handler boundary."
        )
        anon_text = (
            "Audit the anonymous session merge path for privilege escalation. "
            "Ensure anonymous session data cannot be merged into a user account "
            "without explicit user consent and re-authentication."
        )

    if payments == "stripe":
        payment_text = (
            "Verify payment status server-side by querying Stripe directly before granting access. "
            "Do not rely on client-supplied payment confirmation. "
            "Check the Stripe payment intent status in the server-side handler."
        )
        webhook_text = (
            "Validate webhook signatures before processing. "
            f"For {auth_provider.title()}: verify the provider's HMAC/Svix signature. "
            "For Stripe: verify the `stripe-signature` header using the Stripe SDK. "
            "Reject any request whose signature does not match."
        )
    else:
        payment_text = (
            "Verify payment status server-side by querying the payment provider directly before granting access. "
            "Do not rely on client-supplied payment confirmation."
        )
        webhook_text = (
            "Validate webhook signatures before processing. "
            "Verify the provider's HMAC signature on every inbound webhook request. "
            "Reject any request whose signature does not match."
        )

    plans = {
        "auth_bypass": (
            f"Verify every server-side handler validates the {auth_provider.title()} JWT before processing. "
            f"Add an Authorization header check and return 401 immediately if missing or invalid."
        ),
        "rls_bypass": rls_text,
        "idor": (
            "Add ownership checks server-side before returning or modifying any resource. "
            "Do not rely solely on access-control policies; validate the resource owner in the handler "
            "and return 403 if the requester does not own the resource."
        ),
        "storage_bypass": storage_text,
        "webhook_spoofing": webhook_text,
        "webhook_lemonsqueezy": (
            "Validate the Lemon Squeezy X-Signature HMAC on every inbound webhook. "
            "Reject any request whose signature does not match the configured signing secret."
        ),
        "webhook_paddle": (
            "Validate the Paddle webhook signature (ts + h1 scheme) on every inbound webhook. "
            "Reject any request whose signature does not match the configured signing secret."
        ),
        "webhook_replay": (
            "Implement idempotency checks using the webhook event ID. "
            "Store processed event IDs in a short-lived cache or database table "
            "and reject or silently acknowledge duplicate deliveries."
        ),
        "webhook_robustness": (
            "Ensure the webhook handler gracefully handles unrecognised event types. "
            "Return a 2xx or 4xx response — never crash with 500 on unknown events."
        ),
        "webhook_parse_order": (
            "Verify the HMAC signature over the raw request body bytes before deserialising JSON. "
            "Parsing the body first can cause HMAC mismatches for legitimate webhooks "
            "and may mask signature bypass vulnerabilities."
        ),
        "injection": injection_text,
        "file_upload": (
            "Validate file MIME type server-side (not just the extension). "
            "Limit file size in the handler before passing to storage. "
            "Scan uploaded files for malicious content before processing."
        ),
        "auth_flows": (
            "Review the full auth flow for race conditions and state-confusion bugs. "
            "Ensure token refresh is atomic and session tokens cannot be reused after logout."
        ),
        "payment_gate": payment_text,
        "api_surface": (
            "Remove or restrict undocumented endpoints. "
            "Return 404 for any path not in the documented API surface. "
            "Add rate limiting to all public-facing endpoints."
        ),
        "cors_headers": (
            "Set a strict Content-Security-Policy header. "
            "Add X-Frame-Options: DENY and Strict-Transport-Security with a long max-age. "
            "Configure CORS to allow only the production domain origin."
        ),
        "info_disclosure": (
            "Remove stack traces and internal error details from API responses. "
            "Return generic error messages to clients. "
            "Log full errors server-side only."
        ),
        "anon_session": anon_text,
        "data_protection": (
            "Set Cache-Control: no-store (or no-cache, private) on every "
            "authenticated or sensitive response so credentials and PII are not "
            "written to shared or browser caches. Never place tokens, API keys, "
            "or PII in URLs, query strings, or redirect Location headers — carry "
            "them in headers or POST bodies instead. Add Referrer-Policy: "
            "strict-origin-when-cross-origin so URLs do not leak to third-party "
            "origins. Header defaults differ per host (Netlify/Vercel/"
            "Cloudflare); set these explicitly in your platform config rather "
            "than relying on the host default."
        ),
        "session": (
            "Invalidate sessions server-side on logout — revoke the refresh "
            "token and clear the session record so a captured credential cannot "
            "be replayed. Issue a fresh session token on every authentication "
            "(never reuse a pre-auth token). Require recent re-authentication "
            "before sensitive account changes (password, email, MFA)."
        ),
        "oauth": (
            "On the OAuth authorization request, generate an unguessable `state` "
            "and validate it on the callback (CSRF defence), send a PKCE "
            "`code_challenge` with `code_challenge_method=S256`, request only the "
            "scopes the feature needs, and for OIDC flows send a `nonce`. Never "
            "return delegated-send access or refresh tokens to the browser — hold "
            "them server-side in a secrets vault and expose only narrow "
            "send/status endpoints. Confirm the authorization server enforces "
            "redirect-URI exact-match, single-use authorization codes, and PKCE "
            "(Google/Microsoft; verify via provider attestation, Track C)."
        ),
        "mass_assignment": (
            "Allow-list the fields each write handler may bind from the request "
            "body; never spread a client object onto the stored record. For "
            "PostgREST, restrict writable columns with column-level GRANTs and an "
            "RLS WITH CHECK clause so privileged columns (role, is_admin, "
            "ownership, balances) cannot be set by the client role. For Firestore, "
            "block writes to privilege-bearing fields in Security Rules unless the "
            "request carries the appropriate custom claim. Strip or reject unknown "
            "keys at the API boundary."
        ),
        "method_hardening": (
            "Disable the HTTP TRACE (and TRACK) method at the web server, CDN, or "
            "function gateway. Allow only the methods each route needs (typically "
            "GET/POST/PUT/PATCH/DELETE/OPTIONS) and return 405 Method Not Allowed "
            "for everything else, so the method surface cannot be abused for "
            "Cross-Site Tracing or unexpected-verb handling."
        ),
        "csrf": (
            "Protect every state-changing, cookie-authenticated endpoint with an "
            "anti-CSRF token (synchronizer or double-submit) that the server "
            "validates, and reject requests whose Origin/Referer is not same-site. "
            "Set session cookies SameSite=Lax or Strict so the browser does not "
            "attach them to cross-site requests. Where practical, prefer a "
            "non-ambient credential (Authorization: Bearer) for API calls, which "
            "is not auto-sent cross-origin."
        ),
        "frame_ancestors": (
            "Add a Content-Security-Policy with a restrictive frame-ancestors "
            "directive: frame-ancestors 'none' to forbid framing, or 'self' to "
            "allow same-origin only. Keep X-Frame-Options: DENY/SAMEORIGIN as a "
            "fallback for older browsers. Header defaults differ per host "
            "(Netlify/Vercel/Cloudflare); set the CSP explicitly in your platform "
            "config rather than relying on the host default."
        ),
        "zap": (
            "Review the flagged endpoint and apply the remediation recommended by the ZAP alert. "
            "Consult OWASP guidance for the specific vulnerability class."
        ),
        "firebase_auth": "Review Firebase MFA and App Check configuration for the test accounts.",
        "firestore_rules": (
            "Audit Firestore Security Rules for all collections. "
            "Ensure rules require request.auth.uid match on document owner field."
        ),
        "firebase_storage": (
            "Restrict Firebase Storage Security Rules to owner-only access. "
            "Audit download token generation."
        ),
        "supabase_auth": "Review Supabase Auth CAPTCHA and MFA configuration for test accounts.",
        "nextauth": "Review NextAuth credential provider configuration.",
        "s3_storage": (
            "Block public listing. "
            "Scope presigned URL issuance to the authenticated user's resources. "
            "Set short expiry (<1h reads, <15m writes)."
        ),
    }
    return plans.get(category, "Review the flagged code path and apply secure coding best practices.")


def _root_cause_for_category(category: str) -> str:
    causes = {
        "auth_bypass": "Missing or insufficient JWT validation in the server-side handler.",
        "rls_bypass": "Supabase RLS policy missing, misconfigured, or using wrong user-id extraction.",
        "idor": "Server returns or modifies resources without verifying ownership against the authenticated user.",
        "storage_bypass": "Storage bucket policy allows reads/writes beyond the owning user's scope.",
        "webhook_spoofing": "Webhook handler accepts requests without verifying the provider's HMAC signature.",
        "webhook_lemonsqueezy": "Lemon Squeezy webhook handler does not verify the X-Signature HMAC.",
        "webhook_paddle": "Paddle webhook handler does not verify the signature header (ts + h1 scheme).",
        "webhook_replay": "Webhook handler processes duplicate deliveries without idempotency checks.",
        "webhook_robustness": "Webhook handler crashes (500) on unrecognised event types instead of failing gracefully.",
        "webhook_parse_order": "Webhook handler deserialises JSON body before verifying the HMAC signature.",
        "injection": "User input reaches a SQL or shell context without parameterisation or sanitisation.",
        "file_upload": "File processing trusts client-supplied MIME type or does not enforce size limits server-side.",
        "auth_flows": "Authentication state machine allows unexpected transitions or token reuse.",
        "payment_gate": "Access control relies on client-supplied payment status rather than server-verified Stripe state.",
        "api_surface": "Undocumented or unrestricted endpoints are reachable from the public internet.",
        "cors_headers": "Missing or permissive security response headers allow cross-origin attacks or information leakage.",
        "info_disclosure": "Error responses expose internal implementation details, stack traces, or server configuration.",
        "anon_session": "Anonymous session merge RPC can be triggered without adequate ownership validation.",
        "session": "Session not invalidated on logout, reused across authentications, or sensitive changes allowed without re-authentication.",
        "data_protection": "Sensitive responses are cacheable (missing Cache-Control: no-store) or tokens/PII are exposed in URLs, query strings, or redirect Location headers.",
        "oauth": "OAuth client flow omits a CSRF state, PKCE code_challenge, or OIDC nonce, requests excessive scopes, or serialises delegated-send tokens to the browser instead of holding them server-side.",
        "mass_assignment": "The write handler binds client-supplied fields onto the stored object instead of allow-listing writable columns, so a privileged field (role, is_admin, balance) included in the payload is persisted.",
        "method_hardening": "The server honors the HTTP TRACE method, echoing the request back to the client (Cross-Site Tracing) and signalling a permissive method configuration.",
        "csrf": "A state-changing endpoint authenticated by an ambient cookie session does not verify request origin or an anti-CSRF token, so a forged cross-site request carrying the victim's session cookie is accepted.",
        "frame_ancestors": "The Content-Security-Policy lacks a restrictive frame-ancestors directive, so framing is controlled (if at all) only by the legacy X-Frame-Options header.",
        "zap": "Vulnerability identified by automated ZAP scanner; see alert details.",
        "firebase_auth": "Firebase Auth adapter detected a blocking condition (MFA, App Check).",
        "firestore_rules": "Firestore Security Rules misconfigured — allows unauthorized read/write.",
        "firebase_storage": "Firebase Storage Security Rules too permissive — allows cross-user or public access.",
        "supabase_auth": "Supabase Auth (GoTrue) adapter detected a blocking condition (CAPTCHA, MFA AAL).",
        "nextauth": "NextAuth adapter detected a blocking condition (CAPTCHA, form change).",
        "s3_storage": "S3/R2 bucket policy or presigned URL issuer misconfigured.",
    }
    return causes.get(category, "Unclassified vulnerability.")


def _why_it_matters_for_category(category: str) -> str:
    matters = {
        "auth_bypass": (
            "An attacker can access any user's data or perform actions as any user "
            "without possessing valid credentials, leading to full account compromise."
        ),
        "rls_bypass": (
            "Row-level security is the last line of defence in Supabase. "
            "A bypass allows an attacker to read or modify any row in the database, "
            "exposing all user data and potentially enabling data theft or fraud."
        ),
        "idor": (
            "An attacker can enumerate object IDs and access another user's records, "
            "calculations, or generated documents."
        ),
        "storage_bypass": (
            "An attacker can download or overwrite other users' uploaded files, "
            "enabling data theft or tampering with stored evidence."
        ),
        "webhook_spoofing": (
            "A forged webhook can trigger account creation, payment confirmation, or "
            "subscription changes without real events occurring."
        ),
        "webhook_lemonsqueezy": (
            "A forged Lemon Squeezy webhook can trigger subscription activation, "
            "payment confirmation, or license grants without real events occurring."
        ),
        "webhook_paddle": (
            "A forged Paddle webhook can trigger subscription activation, "
            "payment confirmation, or entitlement grants without real events occurring."
        ),
        "webhook_replay": (
            "Without replay protection, a captured valid webhook can be replayed "
            "indefinitely, potentially triggering duplicate subscription activations, "
            "payment credits, or other side effects."
        ),
        "webhook_robustness": (
            "A crash on unknown event types can be exploited for denial of service "
            "and may leak internal error details to attackers via 500 responses."
        ),
        "webhook_parse_order": (
            "Parsing JSON before signature verification can cause the handler to "
            "process tampered payloads or behave inconsistently for equivalent "
            "payloads with different whitespace, undermining HMAC integrity."
        ),
        "injection": (
            "SQL injection can expose the entire database. "
            "Command injection can achieve remote code execution on the server."
        ),
        "file_upload": (
            "Malicious file uploads can lead to stored XSS, server-side code execution, "
            "or denial of service through resource exhaustion."
        ),
        "auth_flows": (
            "Broken auth flows can allow session hijacking, token theft, or "
            "privilege escalation between user accounts."
        ),
        "payment_gate": (
            "A client-side payment bypass allows users to access paid features "
            "without paying, directly harming revenue."
        ),
        "api_surface": (
            "Exposed internal endpoints may lack authentication or rate limiting, "
            "enabling abuse, scraping, or denial of service."
        ),
        "cors_headers": (
            "Missing security headers expose users to clickjacking, MIME sniffing attacks, "
            "cross-site scripting via relaxed CSP, and protocol downgrade attacks."
        ),
        "info_disclosure": (
            "Stack traces and internal error details help attackers map the application "
            "architecture and craft targeted exploits."
        ),
        "anon_session": (
            "Merging anonymous session data without validation can allow an attacker to "
            "inject malicious data into a legitimate user's account."
        ),
        "session": (
            "A session that survives logout lets a stolen or shared credential be "
            "replayed indefinitely. A reused or fixable session token enables "
            "session fixation, and unguarded sensitive changes let an attacker who "
            "briefly holds a session permanently take over the account."
        ),
        "data_protection": (
            "A token or PII in a URL is written to browser history, server and "
            "proxy access logs, and the Referer header sent to third-party "
            "origins, so a single leaked URL can hand an attacker a live "
            "credential. Sensitive responses cached by a shared proxy or the "
            "browser disk cache can be read back by a later user of the same "
            "machine or network, exposing other users' data."
        ),
        "oauth": (
            "A missing OAuth `state` lets an attacker graft their own "
            "authorization code into a victim's session (login CSRF); missing "
            "PKCE lets an intercepted code be redeemed by an attacker; a missing "
            "OIDC nonce allows ID-token replay. Over-broad scopes turn a single "
            "leaked delegated-send token into access far beyond sending mail, and "
            "a token serialised to the browser can be exfiltrated by any XSS or "
            "logging sink and used to send mail or read data as the user."
        ),
        "mass_assignment": (
            "If a client can set a privileged field the UI never exposes "
            "(is_admin, role, balance, a verification flag), it can escalate its "
            "own privileges, grant itself paid entitlements, or tamper with "
            "balances directly from a write payload, with no other vulnerability "
            "required."
        ),
        "method_hardening": (
            "An enabled TRACE method can be abused for Cross-Site Tracing: with a "
            "second flaw it lets an attacker read request headers the browser "
            "otherwise hides from script (including session cookies), and it marks "
            "a permissive method surface that may accept other unsafe verbs."
        ),
        "csrf": (
            "Cross-site request forgery lets an attacker's page perform "
            "state-changing actions as a logged-in victim (change settings, move "
            "funds, delete data) without stealing the credential, because the "
            "browser attaches the session cookie automatically to the forged "
            "request."
        ),
        "frame_ancestors": (
            "Without a restrictive CSP frame-ancestors directive the page can be "
            "embedded in an attacker-controlled iframe and used for clickjacking, "
            "overlaying the real UI to trick the user into unintended clicks. "
            "Browsers honor frame-ancestors over X-Frame-Options, and some "
            "contexts ignore X-Frame-Options entirely."
        ),
        "zap": (
            "This vulnerability class can be exploited to compromise application "
            "integrity, user data, or service availability."
        ),
        "firebase_auth": (
            "A blocking adapter condition may prevent legitimate users from authenticating "
            "or may indicate a misconfiguration that bypasses security controls."
        ),
        "firestore_rules": (
            "Misconfigured Firestore Security Rules allow unauthenticated or cross-user "
            "reads and writes, exposing all stored user data."
        ),
        "firebase_storage": (
            "Overly permissive Storage rules allow attackers to download or overwrite "
            "other users' files, enabling data theft or evidence tampering."
        ),
        "supabase_auth": (
            "A blocking adapter condition may indicate CAPTCHA or MFA misconfiguration "
            "that prevents legitimate auth flows or weakens account security."
        ),
        "nextauth": (
            "A blocking adapter condition may indicate a credential provider misconfiguration "
            "that prevents legitimate auth flows or exposes session state."
        ),
        "s3_storage": (
            "Public bucket listing exposes all stored objects. "
            "Mis-scoped presigned URLs allow cross-user file access or exfiltration."
        ),
    }
    return matters.get(category, "This vulnerability may impact application security.")


def build_zap_findings(alerts: list[dict], source_file_map: dict, stack_info: dict) -> list[dict]:
    """Convert ZAP alert dicts to normalised finding dicts."""
    findings = []
    for alert in alerts:
        alert_name: str = alert.get("name", alert.get("alert", "Unknown ZAP Alert"))
        risk_code = int(alert.get("riskcode", 0))
        severity = ZAP_RISK_MAP.get(risk_code, "INFO")
        category = _category_from_zap_alert(alert_name)

        # Extract endpoint from first instance URL
        instances = alert.get("instances", alert.get("instance", []))
        if isinstance(instances, dict):
            instances = [instances]
        endpoint = ""
        method = "GET"
        raw_url = ""
        if instances:
            first = instances[0]
            raw_url = first.get("uri", first.get("url", ""))
            endpoint, method = _extract_endpoint_from_url(raw_url, source_file_map)
            method = first.get("method", method)

        finding_id = _next_id(category)
        findings.append({
            "id": finding_id,
            "title": alert_name,
            "severity": severity,
            "category": category,
            "source": "zap",
            "endpoint": endpoint or raw_url,
            "method": method,
            "description": alert.get("desc", alert.get("description", "")),
            "solution": alert.get("solution", ""),
            "reference": alert.get("reference", ""),
            "evidence": {
                "request": {"url": raw_url, "method": method},
                "response": {"instances": instances},
            },
            "affected_files": _affected_files_for_endpoint(endpoint, source_file_map),
            "root_cause": _root_cause_for_category(category),
            "why_it_matters": _why_it_matters_for_category(category),
            "remediation_plan": _remediation_for_category(category, severity, stack_info),
            "test_to_verify": (
                f"pytest tests/test_{category}.py -k validate"
                if category != "zap" else
                "Re-run ZAP scan against the patched endpoint."
            ),
            "related_findings": [],
            "scope_estimate": _scope_estimate(severity),
            "false_positive": False,
            "known_exception_reason": None,
        })
    return findings


def _test_stem_from_nodeid(node_id: str) -> str:
    """Extract test file stem from pytest node ID.

    e.g. "tests/test_auth_bypass.py::TestClass::test_no_auth" → "test_auth_bypass"
    """
    # node_id format: path/to/test_foo.py::test_name or tests/test_foo.py::Class::test_name
    # The lookbehind anchors "test_" to a path-component boundary so a filename
    # like "not_a_test_file.py" does not yield a spurious "test_file" stem.
    match = re.search(r"(?<![a-zA-Z0-9_])(test_[a-z0-9_]+)\.py", node_id)
    return match.group(1) if match else ""


def _endpoint_from_nodeid(node_id: str, source_file_map: dict) -> tuple[str, str]:
    """Heuristic: look for endpoint path fragments in test name."""
    node_lower = node_id.lower()
    for ep in source_file_map:
        ep_slug = ep.lstrip("/").replace("-", "_")
        if ep_slug in node_lower:
            return ep, "POST"
    return "", "POST"


def _evidence_for_nodeid(node_id: str, evidence_map: dict[str, list[dict]]) -> dict:
    """Find the best-matching evidence entry for a pytest node ID."""
    sanitised = node_id.replace("::", "__").replace("/", "_").replace("\\", "_")
    # Try exact match first
    if sanitised in evidence_map:
        records = evidence_map[sanitised]
        if records:
            r = records[0]
            return {"request": r.get("request", {}), "response": r.get("response", {})}
    # Try prefix match
    for key, records in evidence_map.items():
        if sanitised.startswith(key) or key.startswith(sanitised):
            if records:
                r = records[0]
                return {"request": r.get("request", {}), "response": r.get("response", {})}
    return {"request": {}, "response": {}}


def _extract_severity_from_message(message: str) -> str | None:
    """Extract an explicit severity keyword from a pytest.fail() message.

    Convention: tests that self-escalate on true bypass detection prefix the
    failure message with a severity keyword followed by a colon, e.g.:
        pytest.fail("CRITICAL: webhook accepted forged signature ...")

    In pytest-json-report, ``call.longrepr`` is a traceback string like:
        ``Failed: CRITICAL: webhook accepted forged signature ...``
    so we search for the severity label after common prefixes, not just at
    the start of the string.

    Returns the severity string (CRITICAL, HIGH, MEDIUM) if found, otherwise
    None (caller falls through to map-based lookup).
    """
    if not message:
        return None
    # Search for "CRITICAL:", "HIGH:", "MEDIUM:" after optional pytest prefix.
    # Handles both raw messages and longrepr strings ("Failed: CRITICAL: ...").
    m = re.search(r"(?:^|Failed:\s*)(CRITICAL|HIGH|MEDIUM):", message)
    return m.group(1) if m else None


def build_pytest_findings(
    pytest_data: dict,
    evidence_map: dict[str, list[dict]],
    source_file_map: dict,
    stack_info: dict,
) -> list[dict]:
    """Convert failed pytest tests to normalised finding dicts."""
    findings = []
    tests = pytest_data.get("tests", [])
    for test in tests:
        outcome = test.get("outcome", "")
        if outcome not in ("failed", "error"):
            continue

        node_id: str = test.get("nodeid", "")
        stem = _test_stem_from_nodeid(node_id)
        test_func = node_id.split("::")[-1] if "::" in node_id else ""

        # Extract error message from pytest report (needed before severity resolution)
        call_info = test.get("call", {}) or {}
        longrepr = call_info.get("longrepr", "") or test.get("longrepr", "") or ""
        if isinstance(longrepr, dict):
            longrepr = longrepr.get("reprcrash", {}).get("message", str(longrepr))

        # Severity resolution order:
        # 1. Inline severity keyword from pytest.fail message (e.g. "CRITICAL: ...")
        #    — this lets tests self-escalate on true bypass detection.
        # 2. _TEST_NAME_SEVERITY_OVERRIDES (per-test-function map entry)
        # 3. TEST_SEVERITY_MAP (per-file-stem default)
        longrepr_severity = _extract_severity_from_message(longrepr) if longrepr else None
        severity = (
            longrepr_severity
            or _TEST_NAME_SEVERITY_OVERRIDES.get(test_func)
            or TEST_SEVERITY_MAP.get(stem, "MEDIUM")
        )
        category = (
            _TEST_NAME_CATEGORY_OVERRIDES.get(test_func)
            or TEST_CATEGORY_MAP.get(stem, "api_surface")
        )
        endpoint, method = _endpoint_from_nodeid(node_id, source_file_map)
        ev = _evidence_for_nodeid(node_id, evidence_map)

        finding_id = _next_id(category)
        test_name = node_id.split("::")[-1] if "::" in node_id else node_id
        findings.append({
            "id": finding_id,
            "title": f"{stem.replace('test_', '').replace('_', ' ').title()} — {test_name}",
            "severity": severity,
            "category": category,
            "source": "pytest",
            "endpoint": endpoint,
            "method": method,
            "description": longrepr[:1000] if longrepr else f"Test {node_id} failed.",
            "solution": "",
            "reference": "",
            "evidence": ev,
            "affected_files": _affected_files_for_endpoint(endpoint, source_file_map),
            "root_cause": _root_cause_for_category(category),
            "why_it_matters": _why_it_matters_for_category(category),
            "remediation_plan": _remediation_for_category(category, severity, stack_info),
            "test_to_verify": f"pytest {node_id}",
            "related_findings": [],
            "scope_estimate": _scope_estimate(severity),
            "false_positive": False,
            "known_exception_reason": None,
        })
    return findings


def failed_test_names(pytest_data: dict) -> set[str]:
    """Return the bare names of tests that failed or errored.

    Parametrize suffixes (``[case]``) are stripped so a parametrized probe still
    matches a bare name in :data:`_STANDALONE_FINDING_FAILED_TEST_NAMES`.
    """
    return {
        test.get("nodeid", "").split("::")[-1].split("[", 1)[0]
        for test in pytest_data.get("tests", [])
        if test.get("outcome", "") in ("failed", "error")
    }


def build_evidence_findings(
    standalone_findings: list[dict],
    source_file_map: dict,
    stack_info: dict,
    failed_test_names: set[str],
) -> list[dict]:
    """Convert standalone evidence payloads into normalised findings."""
    findings: list[dict] = []
    for payload in standalone_findings:
        finding_name = payload.get("finding", "")
        duplicate_test_name = _STANDALONE_FINDING_FAILED_TEST_NAMES.get(finding_name)
        if duplicate_test_name and duplicate_test_name in failed_test_names:
            continue

        category = (
            _STANDALONE_FINDING_CATEGORY_OVERRIDES.get(finding_name)
            or payload.get("category")
            or "api_surface"
        )
        endpoint = payload.get("endpoint") or payload.get("webhook_path") or ""
        severity = payload.get("severity", "MEDIUM")
        description = payload.get("description", "")
        note = payload.get("note")
        if note:
            description = f"{description}\n\nNote: {note}"

        findings.append({
            "id": _next_id(category),
            "title": payload.get("title", finding_name or "Standalone finding"),
            "severity": severity,
            "category": category,
            "source": "evidence",
            "endpoint": endpoint,
            "method": payload.get("method", "POST"),
            "description": description,
            "solution": payload.get("remediation", ""),
            "reference": "",
            "evidence": {"request": {}, "response": payload},
            "affected_files": _affected_files_for_endpoint(endpoint, source_file_map),
            "root_cause": _root_cause_for_category(category),
            "why_it_matters": _why_it_matters_for_category(category),
            "remediation_plan": payload.get("remediation") or _remediation_for_category(category, severity, stack_info),
            "test_to_verify": "Re-run the associated pentest harness probe.",
            "related_findings": [],
            "scope_estimate": _scope_estimate(severity),
            "false_positive": False,
            "known_exception_reason": None,
        })
    return findings


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_HERE)),
        autoescape=True,
        keep_trailing_newline=True,
    )


def _top3(findings: list[dict]) -> list[dict]:
    """Return up to 3 highest-severity findings."""
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return sorted_findings[:3]


def _counts_by_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _endpoint_categories() -> list[str]:
    """Non-provider categories shown as endpoint coverage-matrix columns.

    Provider-only categories have endpoint=="" and would read as uncovered on
    every endpoint row, so they are excluded here and reported separately in the
    provider-layer section. Deduplicated (preserving order) in case two stems
    ever map to the same category string.
    """
    return list(dict.fromkeys(
        c for c in TEST_CATEGORY_MAP.values() if c not in _PROVIDER_CATEGORIES
    ))


def _coverage_matrix(findings: list[dict], profile: dict) -> list[dict]:
    """Build endpoint × category coverage matrix rows."""
    # Collect all endpoints from profile
    all_endpoints: list[str] = []
    for group in profile.get("endpoints", {}).values():
        for ep in group:
            all_endpoints.append(ep.get("path", ""))

    all_categories = _endpoint_categories()

    # Build a set of (endpoint, category) pairs that have findings
    hit: set[tuple[str, str]] = set()
    for f in findings:
        hit.add((f.get("endpoint", ""), f.get("category", "")))

    rows = []
    for ep in all_endpoints:
        row: dict[str, Any] = {"endpoint": ep, "categories": {}}
        for cat in all_categories:
            row["categories"][cat] = (ep, cat) in hit
        rows.append(row)
    return rows


def render_html(
    findings: list[dict],
    profile: dict,
    output_dir: Path,
    generated_at: str,
    run_ts: str | None = None,
) -> Path:
    env = _jinja_env()
    tmpl = env.get_template("human_template.html.j2")
    counts = _counts_by_severity(findings)
    top3 = _top3(findings)
    matrix = _coverage_matrix(findings, profile)
    categories = _endpoint_categories()

    # Derive site name from profile for report branding.
    site_name = "Security Test"
    if profile:
        base_url = (profile.get("target") or {}).get("base_url", "")
        if base_url:
            # Extract domain name without scheme, e.g. "example.com" → "example"
            domain = base_url.split("://")[-1].rstrip("/").split(".")[0]
            site_name = domain.title() if domain else site_name

    # Provider layer findings (direct-API tests, not app endpoints)
    provider_findings = [f for f in findings if f.get("category") in _PROVIDER_CATEGORIES]

    # Map provider category → actual test module filename (inverted from
    # TEST_CATEGORY_MAP). e.g. "firebase_auth" → "test_firebase_auth_adapter.py".
    # Scoped to provider categories so non-provider stems do not bloat the map.
    provider_modules: dict[str, str] = {
        cat: f"{stem}.py"
        for stem, cat in TEST_CATEGORY_MAP.items()
        if cat in _PROVIDER_CATEGORIES
    }

    html = tmpl.render(
        findings=sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99)),
        counts=counts,
        top3=top3,
        matrix=matrix,
        categories=categories,
        generated_at=generated_at,
        total=len(findings),
        site_name=site_name,
        provider_findings=provider_findings,
        provider_modules=provider_modules,
        provider_layers=_PROVIDER_LAYER_MAP,
    )
    suffix = f"-{run_ts}" if run_ts else ""
    out = output_dir / f"report{suffix}.html"
    out.write_text(html, encoding="utf-8")
    return out


def render_agent_json(
    findings: list[dict],
    output_dir: Path,
    generated_at: str,
    run_ts: str | None = None,
) -> Path:
    env = _jinja_env()
    tmpl = env.get_template("agent_template.json.j2")
    agent_json = tmpl.render(
        findings=sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99)),
        generated_at=generated_at,
    )
    suffix = f"-{run_ts}" if run_ts else ""
    out = output_dir / f"agent-findings{suffix}.json"
    # Validate JSON before writing; fall back to minimal valid JSON on failure
    try:
        json.loads(agent_json)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Agent JSON template produced invalid JSON: {exc}", file=sys.stderr)
        agent_json = json.dumps({"error": "template produced invalid JSON", "findings": []}, indent=2)
    out.write_text(agent_json, encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge ZAP + pytest reports into HTML and agent JSON outputs."
    )
    parser.add_argument(
        "--zap-report",
        type=Path,
        default=None,
        help="Path to ZAP JSON report (optional).",
    )
    parser.add_argument(
        "--pytest-report",
        type=Path,
        required=True,
        help="Path to pytest JSON report (required).",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path("reports/evidence"),
        help="Directory containing evidence JSON files (default: reports/evidence/).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/output"),
        help="Directory for output files (default: reports/output/).",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        help="Path to site profile YAML.",
    )
    parser.add_argument(
        "--run-ts",
        type=str,
        default=None,
        help="Run timestamp for output filenames (e.g. 20260506T220000Z).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Ensure output dir exists
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Load inputs
    zap_alerts = load_zap_report(args.zap_report) if args.zap_report else []
    if not args.zap_report:
        print("[info] No --zap-report provided; running in pytest-only mode.", file=sys.stderr)

    pytest_data = load_pytest_report(args.pytest_report)
    evidence_map, standalone_findings = load_evidence(args.evidence_dir)
    profile = load_profile(args.profile)
    source_file_map = profile.get("source_file_map", {})
    stack_info = profile.get("stack", {})

    # Test names (without parametrize suffixes) that failed or errored — used to
    # suppress a standalone evidence finding when its probe already reported a
    # pytest failure, avoiding a double-count.
    failed_names = failed_test_names(pytest_data)

    # Build findings (not auto-deduplicated — source-tagged)
    findings: list[dict] = []
    findings.extend(build_zap_findings(zap_alerts, source_file_map, stack_info))
    findings.extend(build_pytest_findings(pytest_data, evidence_map, source_file_map, stack_info))
    findings.extend(
        build_evidence_findings(
            standalone_findings,
            source_file_map,
            stack_info,
            failed_names,
        )
    )

    if not findings:
        print("[info] No findings to report.", file=sys.stderr)

    # Render outputs
    html_path = render_html(findings, profile, args.output_dir, generated_at, run_ts=args.run_ts)
    json_path = render_agent_json(findings, args.output_dir, generated_at, run_ts=args.run_ts)

    high_count = sum(1 for f in findings if f["severity"] in ("HIGH", "CRITICAL"))
    non_high_count = sum(1 for f in findings if f["severity"] in ("MEDIUM", "LOW", "INFO"))
    print(
        f"[done] {len(findings)} finding(s): "
        f"{_counts_by_severity(findings)}",
        file=sys.stderr,
    )
    print(f"  HTML  -> {html_path}", file=sys.stderr)
    print(f"  JSON  -> {json_path}", file=sys.stderr)

    if high_count > 0:
        return 1
    if non_high_count > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
