"""Paddle webhook signature bypass probes.

Test categories:
- Paddle webhook signature verification (missing, empty, forged, body mismatch,
  unexpected event type, JSON-parsing-before-verification)

Separate from test_webhook_spoofing.py because aggregate.py assigns severity
by file stem.  These tests carry @pytest.mark.paddle and are skipped
automatically when the active profile does not list 'paddle' in stack.payments.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path as _Path

import pytest

# ---------------------------------------------------------------------------
# Collection-time profile loading
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile, resolve_profile_path  # noqa: E402
from tests.helpers import is_spa_catchall, send_request  # noqa: E402


def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()

def _resolve_paddle_webhook_path(profile) -> str:
    """Resolve Paddle webhook path from all supported profile key aliases.

    load_profile() accepts the path from:
      1. payments.paddle_webhook_path   (canonical)
      2. payments_config.paddle_webhook_path  (legacy alias)
      3. payments_cfg.paddle_webhook_path     (legacy alias)

    Mirror that fallback order here so legacy profiles don't silently skip
    all Paddle probes.
    """
    if not profile:
        return ""
    # 1. Canonical: payments.paddle_webhook_path
    if profile.payments and getattr(profile.payments, "paddle_webhook_path", None):
        return profile.payments.paddle_webhook_path
    # 2. Legacy alias: payments_config.paddle_webhook_path
    if profile.payments_config and getattr(profile.payments_config, "paddle_webhook_path", None):
        return profile.payments_config.paddle_webhook_path
    # 3. Legacy alias: payments_cfg.paddle_webhook_path
    if profile.payments_cfg and getattr(profile.payments_cfg, "paddle_webhook_path", None):
        return profile.payments_cfg.paddle_webhook_path
    return ""


_PADDLE_WEBHOOK_PATH = _resolve_paddle_webhook_path(_PROFILE)

# ---------------------------------------------------------------------------
# Webhook event body
# ---------------------------------------------------------------------------

_PADDLE_EVENT_BODY = {
    "event_type": "subscription.created",
    "data": {
        "id": "sub_01h0test000000000000000000",
        "status": "active",
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _webhook_url(profile) -> str:
    """Build the full Paddle webhook URL from profile."""
    base = (profile.target.base_url or "").rstrip("/")
    # _PADDLE_WEBHOOK_PATH already includes /api/... prefix
    return f"{base}{_PADDLE_WEBHOOK_PATH}"


def _forged_paddle_signature() -> str:
    """Return a plausible-format but invalid Paddle-Signature header value."""
    ts = int(time.time())
    h1 = secrets.token_hex(32)  # 64 hex chars
    return f"ts={ts};h1={h1}"


def _valid_paddle_signature(body: bytes, secret: str) -> str:
    """Compute a valid Paddle-Signature (HMAC-SHA256 over ts:body)."""
    ts = str(int(time.time()))
    signed_payload = ts.encode() + b":" + body
    h1 = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return f"ts={ts};h1={h1}"


def _get_paddle_webhook_secret(profile) -> str | None:
    """Resolve the Paddle webhook signing secret from profile or env.

    Checks canonical and legacy alias blocks (payments_config, payments_cfg)
    to mirror the fallback order used by _resolve_paddle_webhook_path().

    Returns None when no secret is available (caller should skip).
    """
    if profile:
        # 1. Canonical: payments.paddle_webhook_secret
        if profile.payments:
            secret = getattr(profile.payments, "paddle_webhook_secret", None)
            if secret:
                return secret
        # 2. Legacy alias: payments_config.paddle_webhook_secret
        if profile.payments_config:
            secret = getattr(profile.payments_config, "paddle_webhook_secret", None)
            if secret:
                return secret
        # 3. Legacy alias: payments_cfg.paddle_webhook_secret
        if profile.payments_cfg:
            secret = getattr(profile.payments_cfg, "paddle_webhook_secret", None)
            if secret:
                return secret
    return os.environ.get("PADDLE_WEBHOOK_SECRET") or None


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


@pytest.mark.paddle
class TestPaddleWebhookSignature:
    """Probe Paddle webhook endpoint for signature enforcement weaknesses."""

    def test_missing_paddle_signature(self, profile, evidence):
        """POST with no Paddle-Signature header must be rejected (400 or 401).

        A 200 response here means the endpoint processes webhook events without
        any signature check — CRITICAL finding.
        """
        if not _PADDLE_WEBHOOK_PATH:
            pytest.skip("payments.paddle_webhook_path not set in profile")

        url = _webhook_url(profile)
        body = json.dumps(_PADDLE_EVENT_BODY).encode()
        resp = send_request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            body=body,
        )

        # SPA catch-all guard — must run before any CRITICAL assertion
        if is_spa_catchall(resp):
            evidence.capture(resp, "paddle_missing_sig_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp.status_code == 404:
            evidence.capture(resp, "paddle_missing_sig_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        if 200 <= resp.status_code < 300:
            evidence.capture(resp, "paddle_missing_sig_critical")
            pytest.fail(
                f"CRITICAL: Paddle webhook signature not enforced — "
                f"{url} returned {resp.status_code} with no Paddle-Signature header"
            )

        assert resp.status_code in (400, 401, 403), (
            f"Expected 400/401/403 for missing Paddle-Signature; got {resp.status_code}"
        )

    def test_empty_paddle_signature(self, profile, evidence):
        """POST with empty Paddle-Signature header must be rejected."""
        if not _PADDLE_WEBHOOK_PATH:
            pytest.skip("payments.paddle_webhook_path not set in profile")

        url = _webhook_url(profile)
        body = json.dumps(_PADDLE_EVENT_BODY).encode()
        resp = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "Paddle-Signature": "",
            },
            body=body,
        )

        if is_spa_catchall(resp):
            evidence.capture(resp, "paddle_empty_sig_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp.status_code == 404:
            evidence.capture(resp, "paddle_empty_sig_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        if 200 <= resp.status_code < 300:
            evidence.capture(resp, "paddle_empty_sig_critical")
            pytest.fail(
                f"CRITICAL: Paddle webhook signature not enforced — "
                f"{url} returned {resp.status_code} with empty Paddle-Signature header"
            )

        assert resp.status_code in (400, 401, 403), (
            f"Expected rejection for empty Paddle-Signature; got {resp.status_code}"
        )

    def test_forged_paddle_signature(self, profile, evidence):
        """POST with a well-formed but HMAC-invalid Paddle-Signature must be rejected.

        Format: ts=<unix>;h1=<64 random hex chars>.  If 200 is returned the
        HMAC verification step is bypassed — CRITICAL finding.
        """
        if not _PADDLE_WEBHOOK_PATH:
            pytest.skip("payments.paddle_webhook_path not set in profile")

        url = _webhook_url(profile)
        body = json.dumps(_PADDLE_EVENT_BODY).encode()
        forged_sig = _forged_paddle_signature()
        resp = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "Paddle-Signature": forged_sig,
            },
            body=body,
        )

        if is_spa_catchall(resp):
            evidence.capture(resp, "paddle_forged_sig_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp.status_code == 404:
            evidence.capture(resp, "paddle_forged_sig_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        if 200 <= resp.status_code < 300:
            evidence.capture(resp, "paddle_forged_sig_critical")
            pytest.fail(
                f"CRITICAL: webhook HMAC verification bypassed — "
                f"{url} returned {resp.status_code} for a forged Paddle-Signature"
            )

        assert resp.status_code in (400, 401, 403), (
            f"Expected rejection for forged Paddle-Signature; got {resp.status_code}"
        )

    @pytest.mark.write_probe
    def test_body_signature_mismatch(self, profile, evidence):
        """Signature computed over original body but body modified before sending.

        Simulates a body-tampering attack: attacker captures a legitimately
        signed payload and replays the signature with a modified body.  The
        HMAC verification must reject the mismatch.

        Requires the Paddle webhook secret so the signature over original_body
        is genuinely valid — otherwise this duplicates the forged-signature test.
        """
        if not _PADDLE_WEBHOOK_PATH:
            pytest.skip("payments.paddle_webhook_path not set in profile")

        secret = _get_paddle_webhook_secret(profile)
        if not secret:
            pytest.skip(
                "payments.paddle_webhook_secret not set in profile and "
                "PADDLE_WEBHOOK_SECRET env var not set — cannot compute "
                "a real HMAC for the body-tampering probe"
            )

        url = _webhook_url(profile)
        original_body = json.dumps(_PADDLE_EVENT_BODY).encode()

        # Baseline: confirm the computed signature is accepted with the original body.
        # If the baseline fails, the secret is stale and the mismatch test is meaningless.
        baseline_sig = _valid_paddle_signature(original_body, secret)
        baseline_resp = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "Paddle-Signature": baseline_sig,
            },
            body=original_body,
        )

        if is_spa_catchall(baseline_resp):
            evidence.capture(baseline_resp, "paddle_body_mismatch_baseline_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if baseline_resp.status_code == 404:
            evidence.capture(baseline_resp, "paddle_body_mismatch_baseline_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        if not (200 <= baseline_resp.status_code < 300):
            evidence.capture(baseline_resp, "paddle_body_mismatch_baseline_rejected")
            pytest.skip(
                f"Baseline request was not accepted (status {baseline_resp.status_code}) — "
                "cannot assess body-mismatch behaviour when baseline is rejected. "
                "Check that the webhook secret is current."
            )

        # Now send the tampered body with the signature computed over the original body.
        tampered_body_dict = dict(_PADDLE_EVENT_BODY)
        tampered_body_dict["event_type"] = "subscription.canceled"
        tampered_body = json.dumps(tampered_body_dict).encode()

        # Compute a real signature over original_body, then send with tampered_body
        real_sig = _valid_paddle_signature(original_body, secret)
        resp = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "Paddle-Signature": real_sig,
            },
            body=tampered_body,
        )

        if is_spa_catchall(resp):
            evidence.capture(resp, "paddle_body_mismatch_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp.status_code == 404:
            evidence.capture(resp, "paddle_body_mismatch_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        if 200 <= resp.status_code < 300:
            evidence.capture(resp, "paddle_body_mismatch_critical")
            pytest.fail(
                f"CRITICAL: webhook accepted body/signature mismatch — "
                f"{url} returned {resp.status_code} for a tampered payload with mismatched signature"
            )

        assert resp.status_code in (400, 401, 403), (
            f"Expected rejection for body/signature mismatch; got {resp.status_code}"
        )

    def test_unexpected_event_type(self, profile, evidence):
        """Unexpected event_type with forged signature — robustness probe only.

        This is not a security finding.  The endpoint should reject at the
        signature gate (400/401/403) before reaching event-type dispatch.
        A 500 indicates a crash on unknown event types.
        """
        if not _PADDLE_WEBHOOK_PATH:
            pytest.skip("payments.paddle_webhook_path not set in profile")

        url = _webhook_url(profile)
        unexpected_body = {
            "event_type": "pentest.synthetic_unknown_event",
            "data": {"id": "pentest-probe"},
        }
        body = json.dumps(unexpected_body).encode()
        forged_sig = _forged_paddle_signature()
        resp = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "Paddle-Signature": forged_sig,
            },
            body=body,
        )

        if is_spa_catchall(resp):
            evidence.capture(resp, "paddle_unexpected_event_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp.status_code == 404:
            evidence.capture(resp, "paddle_unexpected_event_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        if resp.status_code == 500:
            evidence.capture(resp, "paddle_unexpected_event_500")
        assert resp.status_code != 500, (
            f"{url} returned 500 for unknown Paddle event type; "
            "handler must not crash on unrecognised events"
        )
        if 200 <= resp.status_code < 300:
            evidence.capture(resp, "paddle_unexpected_event_bypass")
            pytest.fail(
                f"CRITICAL: {url} accepted forged-signature unknown event "
                f"(status {resp.status_code}) — signature gate bypassed"
            )
        # Forged signature should be rejected at the HMAC gate
        assert resp.status_code in (400, 401, 403), (
            f"Expected signature rejection (400/401/403) for forged request; got {resp.status_code}"
        )

    def test_json_parsing_before_verification(self, profile, evidence):
        """Detect JSON-parsing-before-verification via pretty-print vs minified response diff.

        If the server parses the JSON body before verifying the signature it
        may behave differently for equivalent payloads with different whitespace.
        Differing responses indicate the handler deserialises the body before
        running the HMAC gate — MEDIUM finding.
        """
        if not _PADDLE_WEBHOOK_PATH:
            pytest.skip("payments.paddle_webhook_path not set in profile")

        url = _webhook_url(profile)
        forged_sig = _forged_paddle_signature()

        pretty_body = json.dumps(_PADDLE_EVENT_BODY, indent=4).encode()
        minified_body = json.dumps(_PADDLE_EVENT_BODY, separators=(",", ":")).encode()

        resp_pretty = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "Paddle-Signature": forged_sig,
            },
            body=pretty_body,
        )

        if is_spa_catchall(resp_pretty):
            evidence.capture(resp_pretty, "paddle_json_parse_order_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp_pretty.status_code == 404:
            evidence.capture(resp_pretty, "paddle_json_parse_order_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        resp_minified = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "Paddle-Signature": forged_sig,
            },
            body=minified_body,
        )

        if is_spa_catchall(resp_minified):
            pytest.skip("[WARN] Webhook path returned SPA catch-all for minified body")

        if resp_pretty.status_code != resp_minified.status_code:
            evidence.capture(resp_pretty, "paddle_json_parse_order_pretty")
            evidence.capture(resp_minified, "paddle_json_parse_order_minified")
            pytest.fail(
                f"MEDIUM: JSON-parsing-before-verification — "
                f"{url} returned {resp_pretty.status_code} for pretty JSON "
                f"but {resp_minified.status_code} for minified JSON with the same forged signature. "
                "This indicates the server deserialises the body before the HMAC gate runs."
            )

        # Both responses must be rejected — confirm the gate fires regardless
        for resp, label in ((resp_pretty, "pretty"), (resp_minified, "minified")):
            if 200 <= resp.status_code < 300 and not is_spa_catchall(resp):
                evidence.capture(resp, f"paddle_json_parse_order_{label}_accepted")
                pytest.fail(
                    f"CRITICAL: Paddle webhook accepted {label} JSON with forged signature "
                    f"(status {resp.status_code}) — HMAC verification bypassed"
                )
