"""Business-logic & anti-automation probes — step-sequence + per-user quota.

ASVS 5.0:
  - V2.3.1 (L1): the application enforces the documented order of a multi-step
    business flow; a later (gated) step cannot be performed before its
    prerequisite step(s) have run. (CWE-841 — improper enforcement of behavioral
    workflow.)
  - V2.4.1 (L2): anti-automation / per-user quota; a single authenticated user
    cannot consume a resource without bound. (CWE-799 — improper control of
    interaction frequency.)

Config-driven (skip-clean)
--------------------------
These controls are inherently application-specific — there is no generic way to
know which endpoints form a flow, or what a per-user quota is, from a flat
endpoint list. Both probes therefore read an OPTIONAL top-level ``business_logic``
profile section and SKIP-with-reason when it is absent, rather than guessing a
flow from endpoint ordering. The shipped example profiles declare no
``business_logic`` block (and point at a placeholder host), so both probes skip
cleanly there; only the pure classifiers below run offline.

    business_logic:
      flows:                        # step-sequence enforcement (V2.3.1 / CWE-841)
        - name: checkout
          gated_step: {path: /checkout/confirm, method: POST, probe_body: {...}}
          success_signal: "order_id"   # optional substring proving the action ran
          reject_statuses: [409, 422]  # optional; defaults below
      quota:                        # per-user quota / anti-automation (V2.4.1 / CWE-799)
        endpoint: {path: /api/generate, method: POST, probe_body: {...}}
        burst: 60                   # optional; defaults below
        limit_statuses: [429, 402]  # optional; defaults below

Probe-accuracy discipline
-------------------------
Both classifiers prefer **skip-inconclusive-with-reason** over a guessed
pass/fail (a standing project gate). A bare 2xx on a gated step cannot, by
itself, distinguish a real out-of-order execution from a no-op success, so the
step-sequence probe only flags a HIGH bypass when an operator-declared
``success_signal`` confirms the action ran; without it a 2xx is indeterminate
and the probe skips rather than emitting a false HIGH. The classifiers are pure
and unit-tested offline at the bottom of this module.

Safety
------
Both probes send active traffic (the step-sequence probe POSTs the gated step;
the quota probe bursts authenticated requests), so both carry
``@pytest.mark.write_probe`` and run only under ``--full``/``--branch``. Both are
heavy ASVS-scope probes (``@pytest.mark.asvs_extended``, SCAN_SCOPE=asvs). They
are stack-agnostic — no provider marker — because the flow/quota targets come
from the profile, not a specific provider.

Evidence never persists response bodies (a gated-step or quota response may carry
per-user PII): every capture goes through ``FakeResponse(status, url, "[body
omitted] ...", method)`` with the query string stripped, mirroring
tests/test_data_protection.py.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
from urllib.parse import urlsplit

import httpx
import pytest

# ---------------------------------------------------------------------------
# Package-root import shim (mirrors the other test modules)
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from tests.helpers import FakeResponse, netlify_url, safe_text  # noqa: E402


# ---------------------------------------------------------------------------
# Defaults (overridable per-flow / per-quota in the profile)
# ---------------------------------------------------------------------------

# Statuses that count as the gated step CORRECTLY rejecting an out-of-order call.
# 401 is deliberately excluded: we send the gated step as an authenticated user,
# so a 401 signals an auth problem (or a bad fixture token), NOT step-order
# enforcement — treating it as "enforced" would be a false pass, so a 401 falls
# through to "inconclusive" instead. 425 (Too Early) is the most precise signal.
_REJECTION_STATUSES = frozenset({400, 403, 409, 422, 425})

# Statuses that indicate a per-user quota / rate control fired. 429 (rate) and
# 402 (payment/plan limit) are unambiguous. 403 is deliberately NOT a default
# limit status: a 403 on an authenticated burst is more likely generic authz
# denial than a quota signal, so counting it would falsely report the quota as
# enforced (a false negative). Operators whose app 403s on quota add it via
# ``limit_statuses``.
_QUOTA_LIMIT_STATUSES = frozenset({429, 402})

# Default burst size for the quota probe. Enough to trip a typical low per-user
# quota; the probe stops early on the first limit status. Override with
# ``business_logic.quota.burst`` for higher quotas.
_DEFAULT_QUOTA_BURST = 60


# ---------------------------------------------------------------------------
# Pure classifiers (unit-tested offline at the bottom of this module)
# ---------------------------------------------------------------------------

def _step_sequence_verdict(
    status: int, body_text: str, reject_statuses: set[int], success_signal: str | None
) -> str:
    """Classify an out-of-order gated-step response.

    Returns one of:
      - ``"enforced"``    — the step was rejected (status in *reject_statuses*).
      - ``"bypassed"``    — a 2xx AND *success_signal* is present in the body, so
                            the gated action demonstrably ran out of order.
      - ``"noop"``        — a 2xx but *success_signal* is configured and ABSENT,
                            so the endpoint accepted the call without performing
                            the action (the control effectively held).
      - ``"inconclusive"``— a 2xx with no *success_signal* to disambiguate, or any
                            other status (3xx/404/405/5xx/0) that proves neither
                            enforcement nor bypass.
    """
    if status in reject_statuses:
        return "enforced"
    if 200 <= status < 300:
        if success_signal:
            return "bypassed" if success_signal.lower() in body_text.lower() else "noop"
        return "inconclusive"
    return "inconclusive"


def _quota_verdict(statuses: list[int], limit_statuses: set[int]) -> str:
    """Classify a burst of per-user request statuses.

    Returns one of:
      - ``"limited"``     — at least one response hit a *limit_statuses* code, so a
                            per-user quota / rate control is present.
      - ``"unlimited"``   — every response was a 2xx success with no limit hit, so
                            the user consumed the resource without bound.
      - ``"inconclusive"``— no requests landed, or the mix includes non-success,
                            non-limit statuses (e.g. 401/500) so quota enforcement
                            cannot be observed.
    """
    if not statuses:
        return "inconclusive"
    if any(s in limit_statuses for s in statuses):
        return "limited"
    if all(200 <= s < 300 for s in statuses):
        return "unlimited"
    return "inconclusive"


# ---------------------------------------------------------------------------
# Profile readers + small helpers
# ---------------------------------------------------------------------------

def _business_logic_cfg(profile) -> dict:
    """Return the plain ``business_logic`` dict from the profile, or ``{}``.

    Reads ``profile.raw()`` so nested values are plain dicts/lists (not the
    attribute-access wrapper), letting probe bodies pass straight to httpx.
    """
    raw = profile.raw() if hasattr(profile, "raw") else {}
    bl = (raw or {}).get("business_logic")
    return bl if isinstance(bl, dict) else {}


def _flows(profile) -> list[dict]:
    flows = _business_logic_cfg(profile).get("flows")
    return [f for f in flows if isinstance(f, dict)] if isinstance(flows, list) else []


def _quota_cfg(profile) -> dict:
    quota = _business_logic_cfg(profile).get("quota")
    return quota if isinstance(quota, dict) else {}


def _strip_query(url: str) -> str:
    """Drop query + fragment so a captured URL never persists a token/PII."""
    parts = urlsplit(url)
    if not parts.scheme:
        return url.split("?", 1)[0].split("#", 1)[0]
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _slug(text: str) -> str:
    """Filesystem-safe evidence-label slug."""
    return "".join(c if c.isalnum() else "_" for c in (text or "")).strip("_") or "flow"


# ---------------------------------------------------------------------------
# V2.3.1 / CWE-841 — step-sequence enforcement
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
@pytest.mark.asvs_extended
@pytest.mark.asvs("2.3.1")
@pytest.mark.cwe("841")
def test_gated_steps_reject_out_of_order_requests(profile, user_a_client, evidence):
    """A gated step must reject a request made before its prerequisite step(s).

    For each ``business_logic.flows[]`` entry we call the ``gated_step`` directly
    as the signed-in user_a, WITHOUT first running the flow's prerequisite. A
    correct rejection (409/422/425/400/403) proves the order is enforced; a 2xx
    whose body carries the flow's ``success_signal`` proves the gated action ran
    out of order (a bypass — self-escalated to HIGH via ``pytest.fail("HIGH:")``
    above the module's MEDIUM default).

    A 2xx with no ``success_signal`` configured is INDETERMINATE (a no-op success
    cannot be told apart from real out-of-order processing), so the probe records
    it and — if no flow produced an observable enforced/bypassed verdict — skips
    rather than emitting a false pass or a false HIGH. Skips cleanly when the
    profile declares no flows.
    """
    flows = _flows(profile)
    if not flows:
        pytest.skip(
            "No business_logic.flows declared in profile — no multi-step flow to "
            "check for step-sequence enforcement (V2.3.1 / CWE-841). Declare "
            "business_logic.flows[].gated_step to enable this probe."
        )

    bypassed: list[str] = []
    held: list[str] = []
    inconclusive: list[str] = []

    for flow in flows:
        step = flow.get("gated_step") or {}
        path = step.get("path")
        name = flow.get("name") or path or "<unnamed>"
        method = (step.get("method") or "POST").upper()
        body = step.get("probe_body") or {}
        reject = set(flow.get("reject_statuses") or _REJECTION_STATUSES)
        signal = flow.get("success_signal")
        url = netlify_url(profile, path)

        try:
            resp = user_a_client.request(method, url, json=body or None, timeout=15)
        except httpx.HTTPError as exc:
            inconclusive.append(f"{name}: request error ({type(exc).__name__})")
            evidence.capture(
                FakeResponse(
                    0, _strip_query(url),
                    f"[body omitted] gated-step request error: {type(exc).__name__}",
                    method,
                ),
                label=f"{_slug(name)}_step_seq_request_error",
            )
            continue

        verdict = _step_sequence_verdict(resp.status_code, safe_text(resp), reject, signal)
        evidence.capture(
            FakeResponse(
                resp.status_code, _strip_query(url),
                f"[body omitted] gated step called out of order — verdict={verdict}",
                method,
            ),
            label=f"{_slug(name)}_step_seq_{verdict}",
        )

        if verdict == "bypassed":
            bypassed.append(f"{name} ({method} {path}) returned {resp.status_code}")
        elif verdict in ("enforced", "noop"):
            held.append(f"{name} -> {resp.status_code} ({verdict})")
        else:
            inconclusive.append(
                f"{name} -> {resp.status_code} (indeterminate; declare success_signal "
                "to disambiguate a no-op from out-of-order processing)"
            )

    if bypassed:
        # Self-escalate to HIGH so the aggregator lifts above the MEDIUM default.
        pytest.fail(
            "HIGH: gated step(s) accepted out of order — the flow does not enforce "
            "step sequence: " + "; ".join(bypassed) + ". An attacker can skip a "
            "prerequisite step (payment, verification, approval) and trigger the "
            "gated action directly (ASVS V2.3.1, CWE-841). Enforce server-side that "
            "each step's prerequisite state exists before processing."
        )

    if not held:
        pytest.skip(
            "No flow produced an observable enforced/bypassed verdict — all "
            "indeterminate: " + "; ".join(inconclusive) + ". Declare a "
            "success_signal on each flow so a 2xx response can be distinguished "
            "between a no-op and out-of-order processing (no green pass where the "
            "control is not observable)."
        )


# ---------------------------------------------------------------------------
# V2.4.1 / CWE-799 — per-user quota / anti-automation
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
@pytest.mark.asvs_extended
@pytest.mark.asvs("2.4.1")
@pytest.mark.cwe("799")
def test_authenticated_endpoint_enforces_per_user_quota(profile, user_a_client, evidence):
    """A single authenticated user must not consume a quota-bound resource without limit.

    Complements the existing ANONYMOUS rate-limit burst (test_api_surface.py): this
    bursts the profile-declared ``business_logic.quota.endpoint`` as ONE signed-in
    user and expects at least one quota/rate response (429 / 402 by default). If
    every request succeeds the per-user quota is absent (a MEDIUM finding, the
    module default — CWE-799). A mix of non-success, non-limit statuses (e.g. all
    401/500) is indeterminate and skips rather than guessing. Stops early on the
    first limit hit. Skips cleanly when the profile declares no quota target.
    """
    quota = _quota_cfg(profile)
    if not quota:
        pytest.skip(
            "No business_logic.quota declared in profile — no per-user quota target "
            "to exercise (V2.4.1 / CWE-799). Declare business_logic.quota.endpoint "
            "to enable this probe."
        )

    ep = quota.get("endpoint") or {}
    path = ep.get("path")
    method = (ep.get("method") or "POST").upper()
    body = ep.get("probe_body") or {}
    burst = int(quota.get("burst") or _DEFAULT_QUOTA_BURST)
    limit_statuses = set(quota.get("limit_statuses") or _QUOTA_LIMIT_STATUSES)
    url = netlify_url(profile, path)

    statuses: list[int] = []
    transport_error: str | None = None
    for _ in range(burst):
        try:
            resp = user_a_client.request(method, url, json=body or None, timeout=10)
        except httpx.HTTPError as exc:
            transport_error = type(exc).__name__
            break
        statuses.append(resp.status_code)
        if resp.status_code in limit_statuses:
            break

    verdict = _quota_verdict(statuses, limit_statuses)
    evidence.capture(
        FakeResponse(
            statuses[-1] if statuses else 0, _strip_query(url),
            f"[body omitted] sent {len(statuses)} authenticated {method} request(s); "
            f"verdict={verdict}; last statuses={statuses[-10:]}",
            method,
        ),
        label=f"{_slug(path)}_quota_{verdict}",
    )

    if verdict == "limited":
        return  # a per-user quota / rate control is present
    if verdict == "unlimited":
        pytest.fail(
            f"per-user quota appears absent: {len(statuses)} authenticated {method} "
            f"requests to {path} all succeeded with no {sorted(limit_statuses)} "
            "response. A single user can consume the resource without bound (ASVS "
            "V2.4.1, CWE-799). Enforce a durable server-side per-user quota."
        )

    detail = (
        f"transport error ({transport_error}) after {len(statuses)} request(s)"
        if transport_error
        else f"no success/limit verdict from statuses {statuses[-10:]}"
    )
    pytest.skip(
        f"Per-user quota indeterminate — {detail}. The endpoint returned neither a "
        "clean success run nor a quota/limit status, so quota enforcement cannot be "
        "observed (no green pass where the control is not observable)."
    )


# ---------------------------------------------------------------------------
# Offline unit tests for the pure classifiers (no live target).
# Lock the skip-inconclusive boundaries so the no-op/bypass and the
# mixed-status/unlimited splits cannot silently regress into false findings.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "status,body,signal,expected",
    [
        # Rejections -> enforced (control present). 425 Too Early is the precise one.
        (409, "", None, "enforced"),
        (422, "", None, "enforced"),
        (425, "", None, "enforced"),
        (403, "", None, "enforced"),
        (400, "", None, "enforced"),
        # 2xx + success_signal present -> demonstrable out-of-order bypass.
        (200, "order_id: 42 confirmed", "order_id", "bypassed"),
        (201, "Created resource", "created", "bypassed"),
        (200, "CONFIRMED", "confirmed", "bypassed"),  # case-insensitive
        # 2xx + success_signal configured but ABSENT -> no-op (control held).
        (200, "nothing was processed", "order_id", "noop"),
        # 2xx with no success_signal -> indeterminate (cannot disambiguate).
        (200, "ok", None, "inconclusive"),
        # 401 is NOT in the default reject set -> indeterminate (auth, not order).
        (401, "", None, "inconclusive"),
        # Other statuses prove neither enforcement nor bypass.
        (404, "", None, "inconclusive"),
        (405, "", None, "inconclusive"),
        (302, "", None, "inconclusive"),
        (500, "", "order_id", "inconclusive"),
        (0, "", None, "inconclusive"),
    ],
)
def test_step_sequence_verdict_classifies(status, body, signal, expected):
    assert (
        _step_sequence_verdict(status, body, set(_REJECTION_STATUSES), signal) == expected
    )


@pytest.mark.parametrize(
    "statuses,expected",
    [
        # A limit status anywhere -> limited (control present).
        ([200, 200, 429], "limited"),
        ([402], "limited"),
        ([429], "limited"),
        # Every response a 2xx success -> unlimited (no per-user quota).
        ([200, 200, 200], "unlimited"),
        ([201, 200], "unlimited"),
        # Empty / mixed non-success-non-limit -> indeterminate (skip, never pass).
        ([], "inconclusive"),
        ([200, 401, 200], "inconclusive"),
        ([500, 500], "inconclusive"),
        # 403 is NOT a default limit status -> a 403-terminated burst is indeterminate.
        ([200, 200, 403], "inconclusive"),
    ],
)
def test_quota_verdict_classifies(statuses, expected):
    assert _quota_verdict(statuses, set(_QUOTA_LIMIT_STATUSES)) == expected


def test_quota_verdict_honors_custom_limit_statuses():
    # An operator whose app 403s on quota opts 403 in -> the same burst is limited.
    assert _quota_verdict([200, 200, 403], {429, 402, 403}) == "limited"
