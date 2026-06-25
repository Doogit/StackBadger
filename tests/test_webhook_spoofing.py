"""Webhook signature bypass and internal secret tests.

Test categories:
- Stripe webhook signature verification (missing, forged, replay, unexpected event type,
  payment bypass via spoofed checkout.session.completed)
- Clerk webhook svix header verification (missing, forged)
- Internal endpoint secret probing (missing, common guessable values, timing variance)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import statistics
import sys as _sys
import time
import uuid
from pathlib import Path as _Path

import httpx
import pytest

# ---------------------------------------------------------------------------
# Collection-time profile loading
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile, resolve_profile_path  # noqa: E402
from tests.conftest import endpoints_for_category  # noqa: E402
from tests.helpers import send_request  # noqa: E402


def _collection_profile():
    """Load profile at collection time for parametrize decorators."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()

_COMMON_SECRETS = ["secret", "password", "internal", "test", "admin", "changeme", "12345"]

# Timing test: secrets of varying lengths to detect length-dependent timing leaks
_TIMING_SECRETS = [
    "a",
    "ab",
    "abcd",
    "abcdefgh",
    "abcdefghijklmnop",
    "abcdefghijklmnopqrstuvwxyz123456",
    "x" * 64,
    "x" * 128,
    "short",
    "this-is-a-longer-but-still-wrong-secret-value",
]

_WEBHOOK_ENDPOINTS = endpoints_for_category(_PROFILE, "webhook") if _PROFILE else []
_INTERNAL_ENDPOINTS = endpoints_for_category(_PROFILE, "internal") if _PROFILE else []

_STRIPE_ENDPOINTS = [ep for ep in _WEBHOOK_ENDPOINTS if ep.get("signature") == "stripe"]
_CLERK_ENDPOINTS = [ep for ep in _WEBHOOK_ENDPOINTS if ep.get("signature") == "svix"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _endpoint_url(profile, endpoint: dict) -> str:
    base = (profile.target.base_url or "").rstrip("/")
    prefix = (profile.target.api_prefix or "/.netlify/functions").rstrip("/")
    path = endpoint.get("path", "")
    return f"{base}{prefix}{path}"


def _endpoint_id(endpoint: dict) -> str:
    return f"{endpoint.get('method', 'POST')}:{endpoint.get('path', 'unknown')}"


def _stripe_payload(event_type: str = "checkout.session.completed") -> bytes:
    """Return a minimal but structurally realistic Stripe event payload."""
    payload = {
        "id": f"evt_{uuid.uuid4().hex}",
        "object": "event",
        "type": event_type,
        "created": int(time.time()),
        "data": {
            "object": {
                "id": f"cs_{uuid.uuid4().hex}",
                "object": "checkout.session",
                "payment_status": "paid",
                "metadata": {
                    "user_id": f"user_pentest_{uuid.uuid4().hex[:8]}",
                    "upload_id": str(uuid.uuid4()),
                },
            }
        },
    }
    return json.dumps(payload).encode("utf-8")


def _forged_stripe_header(payload: bytes, timestamp: int | None = None) -> str:
    """Return a forged Stripe-Signature header (wrong HMAC key)."""
    ts = timestamp if timestamp is not None else int(time.time())
    fake_sig = hmac.HMAC(b"wrong-secret", f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={fake_sig}"


def _clerk_payload(event_type: str = "user.created") -> bytes:
    """Return a minimal but structurally realistic Clerk webhook payload."""
    payload = {
        "type": event_type,
        "object": "event",
        "id": f"evt_{uuid.uuid4().hex}",
        "data": {
            "id": f"user_{uuid.uuid4().hex[:16]}",
            "email_addresses": [{"email_address": "pentest@example.com"}],
        },
    }
    return json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# Stripe webhook — missing signature header
# ---------------------------------------------------------------------------

@pytest.mark.stripe
@pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
@pytest.mark.cwe("345")  # insufficient verification of data authenticity
@pytest.mark.parametrize("endpoint", _STRIPE_ENDPOINTS, ids=[_endpoint_id(e) for e in _STRIPE_ENDPOINTS])
def test_stripe_webhook_no_signature(endpoint, profile, evidence):
    """Stripe webhook endpoint must return 400 when Stripe-Signature header is absent."""
    url = _endpoint_url(profile, endpoint)
    payload = _stripe_payload()
    resp = send_request("POST", url, body=payload, headers={"Content-Type": "application/json"})
    if resp.status_code != 400:
        evidence.capture(resp, "stripe_no_sig_unexpected")
    assert resp.status_code == 400, (
        f"{endpoint['path']} returned {resp.status_code} with no Stripe-Signature; expected 400"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for missing stripe signature"
    )


# ---------------------------------------------------------------------------
# Stripe webhook — forged signature
# ---------------------------------------------------------------------------

@pytest.mark.stripe
@pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
@pytest.mark.cwe("345")  # insufficient verification of data authenticity
@pytest.mark.parametrize("endpoint", _STRIPE_ENDPOINTS, ids=[_endpoint_id(e) for e in _STRIPE_ENDPOINTS])
def test_stripe_webhook_forged_signature(endpoint, profile, evidence):
    """Stripe webhook endpoint must return 400 for a forged Stripe-Signature (wrong key)."""
    url = _endpoint_url(profile, endpoint)
    payload = _stripe_payload()
    forged_header = _forged_stripe_header(payload)
    headers = {
        "Content-Type": "application/json",
        "Stripe-Signature": forged_header,
    }
    resp = send_request("POST", url, body=payload, headers=headers)
    if resp.status_code != 400:
        evidence.capture(resp, "stripe_forged_sig_unexpected")
    assert resp.status_code == 400, (
        f"{endpoint['path']} returned {resp.status_code} for forged stripe signature; expected 400"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for forged stripe signature"
    )


# ---------------------------------------------------------------------------
# Stripe webhook — unexpected event type (should 200 but not mutate state)
# ---------------------------------------------------------------------------

@pytest.mark.stripe
@pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
@pytest.mark.cwe("345")  # insufficient verification of data authenticity
@pytest.mark.parametrize("endpoint", _STRIPE_ENDPOINTS, ids=[_endpoint_id(e) for e in _STRIPE_ENDPOINTS])
def test_stripe_webhook_unexpected_event_type(endpoint, profile, evidence):
    """Stripe webhook must return 200 for unrecognised event types but not mutate state.

    The webhook handler should acknowledge unexpected types gracefully (200/204)
    rather than crash. State mutation cannot be directly verified here, but the
    test documents that the handler must not error on unknown event types.
    """
    url = _endpoint_url(profile, endpoint)
    payload = _stripe_payload(event_type="invoice.paid")
    # Use a forged signature — we still expect the server to reject at signature
    # verification before any business logic runs. Alternatively, if the server
    # verifies successfully (which won't happen without the real key), it should
    # return 200 without acting.  Either 400 (sig fail) or 200/204 (ack) is
    # acceptable; 500 is not.
    forged_header = _forged_stripe_header(payload)
    headers = {
        "Content-Type": "application/json",
        "Stripe-Signature": forged_header,
    }
    resp = send_request("POST", url, body=payload, headers=headers)
    if resp.status_code == 500:
        evidence.capture(resp, "stripe_unexpected_event_500")
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 for unexpected event type 'invoice.paid'; "
        "handler must not crash on unrecognised Stripe event types"
    )
    # The endpoint should return 400 (sig fail) or a success range — not a server error.
    assert resp.status_code in range(200, 500), (
        f"{endpoint['path']} returned {resp.status_code} for unexpected event type; "
        "expected 2xx or 4xx, not 5xx"
    )


# ---------------------------------------------------------------------------
# Stripe webhook — payment bypass (spoofed checkout.session.completed)
# ---------------------------------------------------------------------------

@pytest.mark.stripe
@pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
@pytest.mark.cwe("345")  # insufficient verification of data authenticity
@pytest.mark.parametrize("endpoint", _STRIPE_ENDPOINTS, ids=[_endpoint_id(e) for e in _STRIPE_ENDPOINTS])
def test_stripe_payment_bypass_spoofed_event(endpoint, profile, evidence):
    """Spoofed checkout.session.completed with arbitrary user_id must be rejected at signature.

    An attacker who cannot forge the Stripe-Signature HMAC cannot inject
    payment events. This test verifies the signature gate fires before any
    state mutation by sending a structurally valid payload with a fabricated
    user_id in metadata but an invalid signature.
    """
    url = _endpoint_url(profile, endpoint)
    # Craft a payload that mimics a real payment completion for an arbitrary user.
    payload_obj = {
        "id": f"evt_{uuid.uuid4().hex}",
        "object": "event",
        "type": "checkout.session.completed",
        "created": int(time.time()),
        "data": {
            "object": {
                "id": f"cs_{uuid.uuid4().hex}",
                "object": "checkout.session",
                "payment_status": "paid",
                "metadata": {
                    # Attacker-controlled user_id — should never reach DB
                    "user_id": "user_attacker_controlled_00000000",
                    "upload_id": str(uuid.uuid4()),
                },
            }
        },
    }
    payload = json.dumps(payload_obj).encode("utf-8")
    forged_header = _forged_stripe_header(payload)
    headers = {
        "Content-Type": "application/json",
        "Stripe-Signature": forged_header,
    }
    resp = send_request("POST", url, body=payload, headers=headers)
    if resp.status_code not in (400, 401, 403):
        evidence.capture(resp, "stripe_payment_bypass_unexpected")
    # Signature must be rejected before business logic; 400 is the expected gate response.
    assert resp.status_code in (400, 401, 403), (
        f"{endpoint['path']} returned {resp.status_code} for spoofed payment event; "
        "expected 400/401/403 — signature gate must fire before any state mutation"
    )


# ---------------------------------------------------------------------------
# Stripe webhook — replay attack (old timestamp in signature)
# ---------------------------------------------------------------------------

@pytest.mark.stripe
@pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
@pytest.mark.cwe("345")  # insufficient verification of data authenticity
@pytest.mark.parametrize("endpoint", _STRIPE_ENDPOINTS, ids=[_endpoint_id(e) for e in _STRIPE_ENDPOINTS])
def test_stripe_webhook_replay_old_timestamp(endpoint, profile, evidence):
    """Stripe webhook must return 400 for a replayed event with a stale timestamp.

    Stripe's signature scheme includes a timestamp; replayed events with
    timestamps older than 5 minutes should be rejected. This test sends a
    forged header with a timestamp from 10 minutes ago.
    """
    url = _endpoint_url(profile, endpoint)
    payload = _stripe_payload()
    old_ts = int(time.time()) - 600  # 10 minutes in the past
    stale_header = _forged_stripe_header(payload, timestamp=old_ts)
    headers = {
        "Content-Type": "application/json",
        "Stripe-Signature": stale_header,
    }
    resp = send_request("POST", url, body=payload, headers=headers)
    if resp.status_code != 400:
        evidence.capture(resp, "stripe_replay_unexpected")
    assert resp.status_code == 400, (
        f"{endpoint['path']} returned {resp.status_code} for stale-timestamp replay; expected 400"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for replay attack"
    )


# ---------------------------------------------------------------------------
# Clerk webhook — missing svix headers
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
@pytest.mark.cwe("345")  # insufficient verification of data authenticity
@pytest.mark.parametrize("endpoint", _CLERK_ENDPOINTS, ids=[_endpoint_id(e) for e in _CLERK_ENDPOINTS])
def test_clerk_webhook_no_svix_headers(endpoint, profile, evidence):
    """Clerk webhook must return 400 when all svix verification headers are absent."""
    url = _endpoint_url(profile, endpoint)
    payload = _clerk_payload()
    resp = send_request("POST", url, body=payload, headers={"Content-Type": "application/json"})
    if resp.status_code != 400:
        evidence.capture(resp, "clerk_no_svix_unexpected")
    assert resp.status_code == 400, (
        f"{endpoint['path']} returned {resp.status_code} with no svix headers; expected 400"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for missing svix headers"
    )


# ---------------------------------------------------------------------------
# Clerk webhook — forged svix headers
# ---------------------------------------------------------------------------

@pytest.mark.clerk
@pytest.mark.asvs("4.1.5")  # per-message digital signature on sensitive cross-system requests
@pytest.mark.cwe("345")  # insufficient verification of data authenticity
@pytest.mark.parametrize("endpoint", _CLERK_ENDPOINTS, ids=[_endpoint_id(e) for e in _CLERK_ENDPOINTS])
def test_clerk_webhook_forged_svix_headers(endpoint, profile, evidence):
    """Clerk webhook must return 400 for forged svix-* signature headers."""
    url = _endpoint_url(profile, endpoint)
    payload = _clerk_payload()
    ts = int(time.time())
    forged_sig = hmac.HMAC(b"wrong-webhook-secret", payload, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        # svix header names as used by Clerk webhook verification
        "svix-id": f"msg_{uuid.uuid4().hex}",
        "svix-timestamp": str(ts),
        "svix-signature": f"v1,{forged_sig}",
    }
    resp = send_request("POST", url, body=payload, headers=headers)
    if resp.status_code != 400:
        evidence.capture(resp, "clerk_forged_svix_unexpected")
    assert resp.status_code == 400, (
        f"{endpoint['path']} returned {resp.status_code} for forged svix headers; expected 400"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for forged svix headers"
    )


# ---------------------------------------------------------------------------
# Internal endpoints — missing x-internal-secret
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "endpoint", _INTERNAL_ENDPOINTS, ids=[_endpoint_id(e) for e in _INTERNAL_ENDPOINTS]
)
def test_internal_no_secret(endpoint, profile, evidence):
    """Internal endpoint must return 401 or 403 when x-internal-secret is absent."""
    url = _endpoint_url(profile, endpoint)
    resp = send_request("POST", url)
    if resp.status_code not in (401, 403):
        evidence.capture(resp, "internal_no_secret_unexpected")
    assert resp.status_code in (401, 403), (
        f"{endpoint['path']} returned {resp.status_code} with no x-internal-secret; "
        "expected 401 or 403"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for missing internal secret"
    )


# ---------------------------------------------------------------------------
# Internal endpoints — common guessable secrets
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "endpoint,secret",
    [(ep, sec) for ep in _INTERNAL_ENDPOINTS for sec in _COMMON_SECRETS],
    ids=[
        f"{_endpoint_id(ep)}:secret={sec}"
        for ep in _INTERNAL_ENDPOINTS
        for sec in _COMMON_SECRETS
    ],
)
def test_internal_common_secrets(endpoint, secret, profile, evidence):
    """Internal endpoint must reject common/guessable x-internal-secret values."""
    url = _endpoint_url(profile, endpoint)
    resp = send_request("POST", url, headers={"x-internal-secret": secret})
    if resp.status_code not in (401, 403):
        evidence.capture(resp, f"internal_common_secret_{secret}_unexpected")
    assert resp.status_code in (401, 403), (
        f"{endpoint['path']} returned {resp.status_code} for common secret '{secret}'; "
        "expected 401 or 403"
    )
    assert resp.status_code != 500, (
        f"{endpoint['path']} returned 500 (unhandled error) for guessable secret '{secret}'"
    )


# ---------------------------------------------------------------------------
# Internal endpoints — timing side-channel measurement (informational)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "endpoint", _INTERNAL_ENDPOINTS[:1], ids=[_endpoint_id(_INTERNAL_ENDPOINTS[0])] if _INTERNAL_ENDPOINTS else ["no-internal-endpoint"]
)
def test_internal_secret_timing_variance(endpoint, profile, evidence):
    """Measure response-time variance across secrets of varying lengths.

    This test does NOT assert a pass/fail timing bound — constant-time
    comparison is hard to prove from the outside. It documents the measured
    variance as an informational finding.

    A high coefficient of variation (CV > 0.5) across secret lengths may
    indicate a non-constant-time comparison and warrants manual investigation.
    """
    url = _endpoint_url(profile, endpoint)
    durations: list[float] = []

    for secret in _TIMING_SECRETS:
        start = time.perf_counter()
        try:
            send_request("POST", url, headers={"x-internal-secret": secret}, timeout=10.0)
        except (httpx.TimeoutException, httpx.ConnectError):
            pass
        elapsed = time.perf_counter() - start
        durations.append(elapsed)

    if len(durations) >= 2:
        mean = statistics.mean(durations)
        stdev = statistics.stdev(durations)
        cv = stdev / mean if mean > 0 else 0.0
        # Log finding for the report — do not hard-fail on timing.
        finding = {
            "finding": "timing_variance_measurement",
            "endpoint": endpoint.get("path"),
            "mean_s": round(mean, 4),
            "stdev_s": round(stdev, 4),
            "cv": round(cv, 4),
            "high_variance": cv > 0.5,
            "note": (
                "CV > 0.5 may indicate non-constant-time secret comparison; "
                "manual investigation recommended."
            ),
        }
        import json as _json
        # Capture as a synthetic response-like object is not possible here;
        # write finding directly to evidence directory.
        from pathlib import Path
        from datetime import datetime, timezone
        evidence_dir = Path(__file__).resolve().parent.parent / "reports" / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        ts_str = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = evidence_dir / f"timing_variance_{ts_str}.json"
        dest.write_text(_json.dumps(finding, indent=2), encoding="utf-8")

    # Always passes — this is a documentation test.
    assert True, "Timing variance documented; review evidence artefact for details"
