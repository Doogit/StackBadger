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


def _valid_paddle_signature(body: bytes, secret: str, ts: int | None = None) -> str:
    """Compute a valid Paddle-Signature (HMAC-SHA256 over ts:body).

    `ts` defaults to the current unix time; pass an explicit (e.g. stale)
    timestamp to exercise the replay/freshness window. The HMAC is still
    genuinely valid for that timestamp, so a compliant receiver must reject it
    on age alone, not on signature mismatch.
    """
    ts_str = str(ts if ts is not None else int(time.time()))
    signed_payload = ts_str.encode() + b":" + body
    h1 = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return f"ts={ts_str};h1={h1}"


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
    """Probe Paddle webhook endpoint for signature enforcement weaknesses.

    asvs/cwe tags are applied per method, not at the class level: the signature
    probes map to V4.1.5 / CWE-345 (per-message authenticity), while the
    stale-timestamp replay probe maps to V2.3.3 / CWE-294 (replay / idempotency),
    so the coverage ledger does not count replay coverage as signature coverage.
    """

    @pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
    @pytest.mark.cwe("345")  # insufficient verification of data authenticity
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

    @pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
    @pytest.mark.cwe("345")  # insufficient verification of data authenticity
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

    @pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
    @pytest.mark.cwe("345")  # insufficient verification of data authenticity
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
    @pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
    @pytest.mark.cwe("345")  # insufficient verification of data authenticity
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

    @pytest.mark.write_probe
    @pytest.mark.asvs("2.3.3")  # replay / business-logic idempotency (§P2-F), distinct from signature integrity
    @pytest.mark.cwe("294")  # capture-replay
    def test_replay_stale_timestamp_rejected(self, profile, evidence):
        """A validly-signed event with a stale timestamp should not be reprocessed (replay window).

        Paddle binds a unix timestamp into the signed payload (ts:body) so the
        receiver can reject replays outside a short freshness window (Paddle's SDK
        default is 5 seconds). This probe computes a *genuinely valid* HMAC over a
        timestamp ~10 minutes in the past, so a rejection is attributable to the
        freshness window rather than a signature mismatch.

        Acceptance of the stale event is ambiguous black-box: a handler that
        deduplicates by event id returns an idempotent 2xx acknowledgement to the
        replay (the captured webhook had no effect, a valid replay defence), and
        that is indistinguishable from a handler that simply reprocessed it. So the
        probe reports MEDIUM only when the stale-leg response body differs from the
        baseline acknowledgement, which is positive evidence the stale event was
        processed afresh. An identical 2xx ack, or any non-2xx rejection, is treated
        as adequate, mirroring the LemonSqueezy replay-informational heuristic.

        Requires the Paddle webhook secret (to forge a valid signature over the old
        timestamp); without it a forged signature would be rejected at the HMAC gate
        before the freshness check runs, so the probe skips-inconclusive. A
        current-timestamp baseline confirms the secret is live (and supplies the
        reference ack body) before the stale-timestamp leg is interpreted.

        Severity: MEDIUM (replay/idempotency gap, not a full signature bypass).
        """
        if not _PADDLE_WEBHOOK_PATH:
            pytest.skip("payments.paddle_webhook_path not set in profile")

        secret = _get_paddle_webhook_secret(profile)
        if not secret:
            pytest.skip(
                "payments.paddle_webhook_secret not set in profile and "
                "PADDLE_WEBHOOK_SECRET env var not set; cannot compute a real "
                "HMAC over a stale timestamp for the replay probe"
            )

        url = _webhook_url(profile)
        body = json.dumps(_PADDLE_EVENT_BODY).encode()

        # Baseline: a current-timestamp valid signature must be accepted. If it is
        # not, the secret is stale and a stale-timestamp rejection below would be
        # meaningless (we could not attribute it to the freshness window). The
        # baseline ack body is also the reference for the reprocessing heuristic.
        baseline_sig = _valid_paddle_signature(body, secret)
        baseline_resp = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "Paddle-Signature": baseline_sig,
            },
            body=body,
        )

        if is_spa_catchall(baseline_resp):
            evidence.capture(baseline_resp, "paddle_replay_baseline_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached; skipping")

        if baseline_resp.status_code == 404:
            evidence.capture(baseline_resp, "paddle_replay_baseline_404")
            pytest.skip("webhook endpoint not found (404); skipping remaining probes")

        if not (200 <= baseline_resp.status_code < 300):
            evidence.capture(baseline_resp, "paddle_replay_baseline_rejected")
            pytest.skip(
                f"Baseline current-timestamp request was not accepted "
                f"(status {baseline_resp.status_code}); cannot assess the replay "
                "window when the baseline is rejected. Check that the webhook secret "
                "is current."
            )

        baseline_body = getattr(baseline_resp, "text", None) or ""

        # Stale leg: a genuinely valid signature over a ~10-minute-old timestamp,
        # replaying the same event the baseline just delivered.
        stale_ts = int(time.time()) - 600
        stale_sig = _valid_paddle_signature(body, secret, ts=stale_ts)
        resp = send_request(
            "POST",
            url,
            headers={
                "Content-Type": "application/json",
                "Paddle-Signature": stale_sig,
            },
            body=body,
        )

        if is_spa_catchall(resp):
            evidence.capture(resp, "paddle_replay_stale_spa_catchall")
            pytest.skip("webhook path returned SPA catch-all; endpoint not reached; skipping")

        if resp.status_code == 404:
            evidence.capture(resp, "paddle_replay_stale_404")
            pytest.skip("webhook endpoint not found (404); skipping remaining probes")

        if 200 <= resp.status_code < 300:
            stale_body = getattr(resp, "text", None) or ""
            if stale_body and stale_body != baseline_body:
                # Different response than the baseline ack: positive evidence the
                # stale event was reprocessed rather than idempotently acknowledged.
                evidence.capture(resp, "paddle_replay_stale_reprocessed")
                pytest.fail(
                    f"MEDIUM: Paddle webhook accepted a validly-signed event with a "
                    f"stale timestamp ({stale_ts}, ~10 min old): {url} returned "
                    f"{resp.status_code} and a response body differing from the "
                    "baseline acknowledgement, which suggests the stale event was "
                    "reprocessed rather than deduplicated (a dedup-aware handler that "
                    "returns a distinct duplicate-ack body is the known false-positive "
                    "corner of this heuristic). Reject signatures whose timestamp is "
                    "outside a short tolerance (Paddle's default is 5 seconds) and "
                    "deduplicate by event id."
                )
            # Identical 2xx: most likely an idempotent acknowledgement of the
            # duplicate event id, which neutralises the replay. Indistinguishable
            # black-box from a missing freshness window that happened to no-op, so
            # not reported as a finding (matches the LemonSqueezy replay heuristic).
            evidence.capture(resp, "paddle_replay_stale_idempotent_ack")
            return

        # Non-2xx: the stale event was not accepted (freshness window or other
        # rejection); the replay was not honoured. Handler crashes on the stale
        # event are a robustness concern owned by test_unexpected_event_type.
        return

    @pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
    @pytest.mark.cwe("345")  # insufficient verification of data authenticity
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

    @pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
    @pytest.mark.cwe("345")  # insufficient verification of data authenticity
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
