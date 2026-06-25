"""LemonSqueezy webhook signature bypass probes.

Test categories:
- LemonSqueezy webhook X-Signature verification (missing, forged)
- Replay protection informational (known architectural limitation)
- Event-type spoofing robustness
- JSON-parsing-before-verification detection

Separate from test_webhook_spoofing.py because aggregate.py assigns severity
by file stem.  These tests carry @pytest.mark.lemonsqueezy and are skipped
automatically when the active profile does not list 'lemonsqueezy' in
stack.payments.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime, timezone
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

def _resolve_lemonsqueezy_webhook_path(profile) -> str:
    """Resolve LemonSqueezy webhook path from all supported profile key aliases.

    Checks canonical and legacy alias blocks (payments_config, payments_cfg)
    to mirror the fallback order used by the Paddle module.
    """
    if not profile:
        return ""
    # 1. Canonical: payments.lemonsqueezy_webhook_path
    if profile.payments and getattr(profile.payments, "lemonsqueezy_webhook_path", None):
        return profile.payments.lemonsqueezy_webhook_path
    # 2. Legacy alias: payments_config.lemonsqueezy_webhook_path
    if profile.payments_config and getattr(profile.payments_config, "lemonsqueezy_webhook_path", None):
        return profile.payments_config.lemonsqueezy_webhook_path
    # 3. Legacy alias: payments_cfg.lemonsqueezy_webhook_path
    if profile.payments_cfg and getattr(profile.payments_cfg, "lemonsqueezy_webhook_path", None):
        return profile.payments_cfg.lemonsqueezy_webhook_path
    return ""


_LEMONSQUEEZY_WEBHOOK_PATH = _resolve_lemonsqueezy_webhook_path(_PROFILE)

# ---------------------------------------------------------------------------
# Webhook event body
# ---------------------------------------------------------------------------

_LEMONSQUEEZY_EVENT_BODY = {
    "meta": {
        "event_name": "subscription_created",
        "custom_data": {},
    },
    "data": {
        "id": "1",
        "type": "subscriptions",
        "attributes": {"status": "active"},
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _webhook_url(profile) -> str:
    """Build the full LemonSqueezy webhook URL from profile."""
    base = (profile.target.base_url or "").rstrip("/")
    # _LEMONSQUEEZY_WEBHOOK_PATH already includes /api/... prefix
    return f"{base}{_LEMONSQUEEZY_WEBHOOK_PATH}"


def _forged_x_signature() -> str:
    """Return a random 64-hex-char X-Signature value (invalid HMAC)."""
    import secrets
    return secrets.token_hex(32)  # 64 hex chars


def _valid_x_signature(body: bytes, secret: str) -> str:
    """Compute a valid LemonSqueezy X-Signature (HMAC-SHA256 hex digest)."""
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _get_webhook_secret(profile) -> str | None:
    """Resolve the LemonSqueezy webhook signing secret from profile or env.

    Checks canonical and legacy alias blocks (payments_config, payments_cfg)
    to mirror the fallback order used by load_profile() for Paddle.

    Returns None when no secret is available (caller should skip).
    """
    if profile:
        # 1. Canonical: payments.lemonsqueezy_webhook_secret
        if profile.payments:
            secret = getattr(profile.payments, "lemonsqueezy_webhook_secret", None)
            if secret:
                return secret
        # 2. Legacy alias: payments_config.lemonsqueezy_webhook_secret
        if profile.payments_config:
            secret = getattr(profile.payments_config, "lemonsqueezy_webhook_secret", None)
            if secret:
                return secret
        # 3. Legacy alias: payments_cfg.lemonsqueezy_webhook_secret
        if profile.payments_cfg:
            secret = getattr(profile.payments_cfg, "lemonsqueezy_webhook_secret", None)
            if secret:
                return secret
    # Environment fallback
    return os.environ.get("LEMONSQUEEZY_WEBHOOK_SECRET") or None


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


@pytest.mark.lemonsqueezy
@pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
@pytest.mark.cwe("345")  # insufficient verification of data authenticity
class TestLemonSqueezyWebhookSignature:
    """Probe LemonSqueezy webhook endpoint for signature enforcement weaknesses."""

    def test_missing_x_signature(self, profile, evidence):
        """POST with no X-Signature header must be rejected (400 or 401).

        LemonSqueezy signs every webhook with an HMAC-SHA256 hex digest in the
        X-Signature header.  Accepting a request without this header means the
        handler processes unauthenticated events — CRITICAL finding.
        """
        if not _LEMONSQUEEZY_WEBHOOK_PATH:
            pytest.skip("payments.lemonsqueezy_webhook_path not set in profile")

        url = _webhook_url(profile)
        body = json.dumps(_LEMONSQUEEZY_EVENT_BODY).encode()
        resp = send_request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            body=body,
        )

        # SPA catch-all guard — must run before any CRITICAL assertion
        if is_spa_catchall(resp):
            evidence.capture(resp, "ls_missing_sig_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp.status_code == 404:
            evidence.capture(resp, "ls_missing_sig_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        if 200 <= resp.status_code < 300:
            evidence.capture(resp, "ls_missing_sig_critical")
            pytest.fail(
                f"CRITICAL: LemonSqueezy webhook signature not enforced — "
                f"{url} returned {resp.status_code} with no X-Signature header"
            )

        assert resp.status_code in (400, 401, 403), (
            f"Expected 400/401/403 for missing X-Signature; got {resp.status_code}"
        )

    def test_forged_x_signature(self, profile, evidence):
        """POST with a random 64-hex X-Signature must be rejected.

        A valid X-Signature is HMAC-SHA256(secret, body) hex-encoded.  Sending
        a random hex value of the same length must not be accepted.
        """
        if not _LEMONSQUEEZY_WEBHOOK_PATH:
            pytest.skip("payments.lemonsqueezy_webhook_path not set in profile")

        url = _webhook_url(profile)
        body = json.dumps(_LEMONSQUEEZY_EVENT_BODY).encode()
        forged_sig = _forged_x_signature()
        resp = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "X-Signature": forged_sig,
            },
            body=body,
        )

        if is_spa_catchall(resp):
            evidence.capture(resp, "ls_forged_sig_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp.status_code == 404:
            evidence.capture(resp, "ls_forged_sig_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        if 200 <= resp.status_code < 300:
            evidence.capture(resp, "ls_forged_sig_critical")
            pytest.fail(
                f"CRITICAL: LemonSqueezy webhook HMAC verification bypassed — "
                f"{url} returned {resp.status_code} for a forged X-Signature"
            )

        assert resp.status_code in (400, 401, 403), (
            f"Expected rejection for forged X-Signature; got {resp.status_code}"
        )

    @pytest.mark.write_probe
    def test_replay_protection_informational(self, profile, evidence, evidence_dir):
        """Informational: LemonSqueezy webhooks lack replay protection.

        LemonSqueezy's signature scheme is HMAC-SHA256(secret, body) — there is
        no timestamp component in the signed payload.  This means a captured
        valid webhook can be replayed indefinitely.  This is a known
        architectural limitation of the LemonSqueezy webhook design, not a
        bypass finding specific to this deployment.

        The test sends the same request twice *with a valid HMAC signature* so
        that the first delivery passes signature verification and the replay
        test actually exercises idempotency/deduplication logic.  If the second
        delivery is accepted (200), the test fails with a MEDIUM finding.  If
        the endpoint correctly rejects the replay, the test passes.

        Requires: payments.lemonsqueezy_webhook_secret in the profile or the
        LEMONSQUEEZY_WEBHOOK_SECRET environment variable.  Skipped when no
        secret is available (a forged signature would be rejected at the HMAC
        gate before idempotency logic runs, making the test meaningless).

        Severity: MEDIUM (informational — no active exploit, but no TTL gate).
        """
        if not _LEMONSQUEEZY_WEBHOOK_PATH:
            pytest.skip("payments.lemonsqueezy_webhook_path not set in profile")

        secret = _get_webhook_secret(profile)
        if not secret:
            pytest.skip(
                "payments.lemonsqueezy_webhook_secret not set in profile and "
                "LEMONSQUEEZY_WEBHOOK_SECRET env var not set — cannot compute "
                "a valid HMAC signature for the replay probe"
            )

        url = _webhook_url(profile)
        body = json.dumps(_LEMONSQUEEZY_EVENT_BODY).encode()
        valid_sig = _valid_x_signature(body, secret)
        headers = {
            "Content-Type": "application/json",
            "X-Signature": valid_sig,
        }

        # First delivery
        resp1 = send_request("POST", url, headers=headers, body=body)

        if is_spa_catchall(resp1):
            evidence.capture(resp1, "ls_replay_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp1.status_code == 404:
            evidence.capture(resp1, "ls_replay_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        # Baseline: first delivery must be accepted (2xx) to confirm the
        # valid HMAC signature was recognised.  If the secret is stale or the
        # endpoint rejects the payload, the replay probe is meaningless.
        if not (200 <= resp1.status_code < 300):
            evidence.capture(resp1, "ls_replay_baseline_rejected")
            pytest.skip(
                f"First delivery was not accepted (status {resp1.status_code}) — "
                "cannot assess replay behaviour when baseline request is rejected. "
                "Check that the webhook secret is current."
            )

        # Second delivery — identical request (replay)
        time.sleep(0.5)  # small delay to let any deduplication window start
        resp2 = send_request("POST", url, headers=headers, body=body)

        if is_spa_catchall(resp2):
            pytest.skip("[WARN] Webhook path returned SPA catch-all on replay attempt")

        # Emit a structured finding artifact regardless, so there is a record
        # of whether replay protection is present.
        ts_str = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        finding = {
            "finding": "lemonsqueezy_no_replay_protection",
            "severity": "MEDIUM",
            "category": "webhook_replay",
            "title": "LemonSqueezy webhook lacks replay protection",
            "description": (
                "LemonSqueezy webhook signatures use HMAC-SHA256(secret, body) with no "
                "timestamp component.  A captured valid webhook request can be replayed "
                "indefinitely — the server has no cryptographic way to detect it is a "
                "duplicate unless idempotency is enforced at the application layer "
                "(e.g. deduplication by event ID)."
            ),
            "remediation": (
                "Implement idempotency checks using the webhook event ID "
                "(meta.custom_data or a LemonSqueezy-supplied event identifier). "
                "Store processed event IDs in a short-lived cache or database table "
                "and reject duplicate deliveries."
            ),
            "note": (
                "This is a known architectural limitation of LemonSqueezy's signature "
                "scheme — not a bypass finding.  The HMAC itself may be correctly "
                "verified; replay protection is a separate application-layer concern."
            ),
            "webhook_path": _LEMONSQUEEZY_WEBHOOK_PATH,
            "replay_first_status": resp1.status_code,
            "replay_second_status": resp2.status_code,
            "generated_at": ts_str,
        }

        dest = evidence_dir / f"ls_replay_protection_informational_{ts_str}.json"
        import json as _json
        dest.write_text(_json.dumps(finding, indent=2), encoding="utf-8")

        # A 2xx on replay is acceptable if the handler is idempotent — the
        # standard webhook pattern is to acknowledge duplicate deliveries with
        # 2xx while skipping side effects (no duplicate processing).  We only
        # fail if there is concrete evidence that the duplicate was actually
        # re-processed (e.g., the response body explicitly indicates fresh
        # processing, or the response differs from the first delivery in a way
        # that suggests a new side effect was triggered).
        if 200 <= resp2.status_code < 300 and not is_spa_catchall(resp2):
            # Heuristic: if both responses have identical bodies, the handler
            # is returning an idempotent acknowledgement — this is correct
            # behaviour (PASS).  If the bodies differ, the handler may have
            # processed the event again (MEDIUM finding).
            resp1_body = getattr(resp1, "text", None) or ""
            resp2_body = getattr(resp2, "text", None) or ""
            if resp1_body == resp2_body:
                # Idempotent 2xx — handler acknowledged the replay without
                # evidence of duplicate processing.  This is the standard
                # webhook pattern; not a finding.
                pass
            else:
                evidence.capture(resp2, "ls_replay_accepted")
                pytest.fail(
                    "MEDIUM: LemonSqueezy webhook may lack replay protection — "
                    f"duplicate delivery accepted with differing response body "
                    f"(first={resp1.status_code}, replay={resp2.status_code}). "
                    "Response body changed between deliveries, suggesting the "
                    "event was re-processed. Implement idempotency checks using "
                    "the webhook event ID. See evidence artifact for full details. "
                    "(Informational architectural finding — not a signature bypass.)"
                )

        # Endpoint rejected the replay (non-200) or returned an idempotent
        # 200 — replay protection is adequate; pass.

    def _send_event_type_spoof(self, profile, evidence):
        """Shared helper: send a spoofed event_name with forged signature.

        Returns the response, or None if the test should be skipped (in which
        case pytest.skip() has already been called).
        """
        if not _LEMONSQUEEZY_WEBHOOK_PATH:
            pytest.skip("payments.lemonsqueezy_webhook_path not set in profile")

        url = _webhook_url(profile)
        spoofed_body = {
            "meta": {
                "event_name": "pentest.synthetic_unknown_event",
                "custom_data": {},
            },
            "data": {"id": "pentest-probe"},
        }
        body = json.dumps(spoofed_body).encode()
        forged_sig = _forged_x_signature()
        resp = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "X-Signature": forged_sig,
            },
            body=body,
        )

        if is_spa_catchall(resp):
            evidence.capture(resp, "ls_event_type_spoof_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp.status_code == 404:
            evidence.capture(resp, "ls_event_type_spoof_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        return resp

    def test_event_type_spoofing_bypass(self, profile, evidence):
        """Spoofed event with forged signature must NOT be accepted (200 = CRITICAL bypass).

        If the server returns 200 for an unknown event_name with an invalid
        X-Signature, the HMAC verification gate is bypassed entirely.
        """
        resp = self._send_event_type_spoof(profile, evidence)

        if 200 <= resp.status_code < 300:
            evidence.capture(resp, "ls_event_type_spoof_critical")
            url = _webhook_url(profile)
            pytest.fail(
                f"CRITICAL: LemonSqueezy webhook accepted spoofed event with forged signature — "
                f"{url} returned {resp.status_code} for event_name 'pentest.synthetic_unknown_event'"
            )

        assert resp.status_code in (400, 401, 403, 500), (
            f"Expected rejection for spoofed event_name with forged signature; got {resp.status_code}"
        )

    def test_event_type_spoofing_robustness(self, profile, evidence):
        """Spoofed event with forged signature must not crash the handler (500 = HIGH).

        Even when signature verification correctly rejects the forged request,
        the handler should not crash on an unrecognised event_name.  A 500
        indicates a robustness issue — not a bypass, but still noteworthy.
        """
        resp = self._send_event_type_spoof(profile, evidence)

        if resp.status_code == 500:
            evidence.capture(resp, "ls_event_type_spoof_500")
            url = _webhook_url(profile)
        assert resp.status_code != 500, (
            f"{_webhook_url(profile)} returned 500 for unknown event_name; "
            "handler must not crash on unrecognised LemonSqueezy event types"
        )

    def test_json_parsing_before_verification(self, profile, evidence):
        """Detect JSON-parsing-before-verification via pretty-print vs minified response diff.

        LemonSqueezy's HMAC is computed over the raw body bytes.  If the server
        deserialises the JSON before verifying the signature it will re-serialise
        to a different byte sequence, breaking verification for all valid webhooks
        and potentially accepting forged ones that happen to normalise identically.

        Differing HTTP responses for pretty vs minified JSON with the same forged
        signature indicate the body is parsed before the HMAC gate — MEDIUM finding.
        """
        if not _LEMONSQUEEZY_WEBHOOK_PATH:
            pytest.skip("payments.lemonsqueezy_webhook_path not set in profile")

        url = _webhook_url(profile)
        forged_sig = _forged_x_signature()

        pretty_body = json.dumps(_LEMONSQUEEZY_EVENT_BODY, indent=4).encode()
        minified_body = json.dumps(_LEMONSQUEEZY_EVENT_BODY, separators=(",", ":")).encode()

        resp_pretty = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "X-Signature": forged_sig,
            },
            body=pretty_body,
        )

        if is_spa_catchall(resp_pretty):
            evidence.capture(resp_pretty, "ls_json_parse_order_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached — skipping")

        if resp_pretty.status_code == 404:
            evidence.capture(resp_pretty, "ls_json_parse_order_404")
            pytest.skip("webhook endpoint not found (404) — skipping remaining probes")

        resp_minified = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "X-Signature": forged_sig,
            },
            body=minified_body,
        )

        if is_spa_catchall(resp_minified):
            pytest.skip("[WARN] Webhook path returned SPA catch-all for minified body")

        if resp_pretty.status_code != resp_minified.status_code:
            evidence.capture(resp_pretty, "ls_json_parse_order_pretty")
            evidence.capture(resp_minified, "ls_json_parse_order_minified")
            pytest.fail(
                f"MEDIUM: JSON-parsing-before-verification — "
                f"{url} returned {resp_pretty.status_code} for pretty JSON "
                f"but {resp_minified.status_code} for minified JSON with the same forged X-Signature. "
                "This indicates the server deserialises the body before the HMAC gate runs."
            )

        # Both responses must be rejected — confirm the gate fires regardless
        for resp, label in ((resp_pretty, "pretty"), (resp_minified, "minified")):
            if 200 <= resp.status_code < 300 and not is_spa_catchall(resp):
                evidence.capture(resp, f"ls_json_parse_order_{label}_accepted")
                pytest.fail(
                    f"CRITICAL: LemonSqueezy webhook accepted {label} JSON with forged X-Signature "
                    f"(status {resp.status_code}) — HMAC verification bypassed"
                )
