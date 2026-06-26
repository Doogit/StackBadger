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
          success_field: "order_id"    # optional JSON field (dotted path) present
                                       #   ONLY on genuine completion
          reject_statuses: [422]       # optional; opt in extra order-rejection codes
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
``success_field`` is **present as a JSON key** in the response (see
:func:`_success_field_present`); without it a 2xx is indeterminate and the probe
skips rather than emitting a false HIGH. Structured key-presence (not substring
matching) is deliberate: an error envelope that merely names the field
(``{"error": "order_id required"}``) has no such key, so a correctly-blocked flow
is never mis-flagged. The ``success_field`` should name a field returned ONLY on
genuine completion (e.g. a created resource id). A 2xx whose body lacks the field
is treated as indeterminate (``noop``), NOT as observed enforcement: only a real
rejection (4xx, default 409/425) proves the control held. The classifiers are
pure and unit-tested offline at the bottom of this module.

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

import json
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
# Kept DELIBERATELY NARROW to order-specific codes: 409 (Conflict — state
# precondition not met) and 425 (Too Early). 400/403/422 are excluded by default
# because they routinely come from a malformed probe_body, a missing CSRF token,
# or generic authz — counting them would let a target that fails the real
# workflow check still be reported "enforced" (a false negative). An operator who
# KNOWS those codes mean "prerequisite missing" for a specific endpoint opts them
# in per-flow via ``reject_statuses``. A status outside this set falls through to
# "inconclusive" (skip), never a guessed pass.
_REJECTION_STATUSES = frozenset({409, 425})

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

def _success_field_present(body_text: str, field_path: str) -> bool:
    """True iff *body_text* parses as JSON containing *field_path* with a value.

    *field_path* is a dotted key path (``order_id`` or ``data.order_id``). At each
    step a list node is searched element-wise, so a PostgREST-style ``[{...}]``
    representation is handled. Returns True only when the path resolves to at
    least one non-null, non-empty value.

    This is STRUCTURED key-presence, not substring matching: an error envelope
    that merely MENTIONS the field name (``{"error": "order_id required"}``) has
    no such key, so it is NOT a bypass. A non-JSON body (HTML/text) parses to
    nothing and is likewise not a bypass — the probe stays conservative.
    """
    if not field_path:
        return False
    try:
        nodes = [json.loads(body_text)]
    except (ValueError, TypeError):
        return False
    for key in field_path.split("."):
        nxt: list = []
        for node in nodes:
            if isinstance(node, dict) and key in node:
                nxt.append(node[key])
            elif isinstance(node, list):
                nxt.extend(item[key] for item in node if isinstance(item, dict) and key in item)
        if not nxt:
            return False
        nodes = nxt
    return any(v not in (None, "", [], {}) for v in nodes)


def _step_sequence_verdict(
    status: int, body_text: str, reject_statuses: set[int], success_field: str | None
) -> str:
    """Classify an out-of-order gated-step response.

    Returns one of:
      - ``"enforced"``    — the step was rejected (status in *reject_statuses*).
      - ``"bypassed"``    — a 2xx AND *success_field* is present (as a JSON key,
                            see :func:`_success_field_present`) in the body, so the
                            gated action demonstrably ran out of order.
      - ``"noop"``        — a 2xx but *success_field* is configured and ABSENT:
                            either the endpoint no-op'd (control held) OR the
                            action ran without returning the field. Ambiguous, so
                            the probe treats it as indeterminate — NOT as observed
                            enforcement (only a 4xx rejection proves that).
      - ``"inconclusive"``— a 2xx with no *success_field* to disambiguate, or any
                            other status (3xx/404/405/5xx/0) that proves neither
                            enforcement nor bypass.
    """
    if status in reject_statuses:
        return "enforced"
    if 200 <= status < 300:
        if success_field:
            return "bypassed" if _success_field_present(body_text, success_field) else "noop"
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
    correct order-rejection (409/425 by default, or the flow's ``reject_statuses``)
    proves the order is enforced; a 2xx whose body carries the flow's
    ``success_field`` as a JSON key proves the gated action ran out of order (a
    bypass — self-escalated to HIGH via ``pytest.fail("HIGH:")`` above the
    module's MEDIUM default).

    Only a real order-rejection counts as observed enforcement. A 2xx whose body
    lacks the field (or any 2xx with no ``success_field`` configured) is
    INDETERMINATE — a no-op success cannot be told apart from real out-of-order
    processing — so the probe records it and, if no flow returned a clean
    rejection, SKIPS rather than emitting a false pass or a false HIGH. Skips
    cleanly when the profile declares no flows.
    """
    flows = [
        f for f in (_business_logic_cfg(profile).get("flows") or [])
        if isinstance(f, dict)
    ]
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
        success_field = flow.get("success_field")
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

        verdict = _step_sequence_verdict(
            resp.status_code, safe_text(resp), reject, success_field
        )
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
        elif verdict == "enforced":
            held.append(f"{name} -> {resp.status_code} (rejected out of order)")
        elif verdict == "noop":
            inconclusive.append(
                f"{name} -> {resp.status_code} (2xx but success_field absent — "
                "no-op or field misconfigured; enforcement not observable)"
            )
        else:
            inconclusive.append(
                f"{name} -> {resp.status_code} (indeterminate; a 2xx needs a "
                "success_field to classify, other statuses prove nothing)"
            )

    if bypassed:
        # Self-escalate to HIGH so the aggregator lifts above the MEDIUM default.
        pytest.fail(
            "HIGH: gated step(s) accepted out of order with the operator-declared "
            "success_field present in the response JSON — the flow does not enforce "
            "step sequence: " + "; ".join(bypassed) + ". An attacker can skip a "
            "prerequisite step (payment, verification, approval) and trigger the "
            "gated action directly (ASVS V2.3.1, CWE-841). Enforce server-side that "
            "each step's prerequisite state exists before processing."
        )

    if not held:
        pytest.skip(
            "No flow returned a clean order-rejection (409/425, or the flow's "
            "reject_statuses) of the out-of-order call, so step-sequence enforcement "
            "was not observed: " + "; ".join(inconclusive) + ". Declare an accurate "
            "success_field (a JSON field returned only on genuine completion), or "
            "opt the endpoint's order-rejection code into reject_statuses, rather "
            "than guessing a pass (no green pass where the control is not observable)."
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
    quota = _business_logic_cfg(profile).get("quota")
    if not isinstance(quota, dict) or not quota:
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

    # A burst truncated by a transport error before any limit status is
    # INDETERMINATE, not "quota absent": a server may defend a burst by dropping
    # the connection, which would otherwise read as an all-2xx 'unlimited' run.
    # Check this BEFORE the unlimited verdict so a cut-short burst never fails.
    if transport_error:
        pytest.skip(
            f"Per-user quota indeterminate — transport error ({transport_error}) "
            f"after {len(statuses)} request(s) with no limit status seen; the burst "
            "was cut short before quota enforcement could be observed."
        )

    if verdict == "unlimited":
        pytest.fail(
            f"per-user quota appears absent: {len(statuses)} authenticated {method} "
            f"requests to {path} all succeeded with no {sorted(limit_statuses)} "
            "response. A single user can consume the resource without bound (ASVS "
            "V2.4.1, CWE-799). Enforce a durable server-side per-user quota."
        )

    pytest.skip(
        f"Per-user quota indeterminate — no success/limit verdict from statuses "
        f"{statuses[-10:]}. The endpoint returned neither a clean success run nor a "
        "quota/limit status, so quota enforcement cannot be observed (no green pass "
        "where the control is not observable)."
    )


# ---------------------------------------------------------------------------
# Offline unit tests for the pure classifiers (no live target).
# Lock the skip-inconclusive boundaries so the no-op/bypass and the
# mixed-status/unlimited splits cannot silently regress into false findings.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "status,body,field,expected",
    [
        # Order-specific rejections -> enforced. 409 Conflict / 425 Too Early only.
        (409, "", None, "enforced"),
        (425, "", None, "enforced"),
        # 400/403/422 are NOT default rejections (ambiguous: malformed body, CSRF,
        # generic authz) -> indeterminate, so a target that rejects for an unrelated
        # reason is NOT falsely credited as enforcing order.
        (400, "", None, "inconclusive"),
        (403, "", None, "inconclusive"),
        (422, "", None, "inconclusive"),
        # 2xx + success_field present as a JSON key -> demonstrable bypass.
        (200, '{"order_id": 42}', "order_id", "bypassed"),
        (201, '{"id": 9, "status": "ok"}', "id", "bypassed"),
        (200, '{"data": {"order_id": 7}}', "data.order_id", "bypassed"),  # dotted path
        (200, '[{"order_id": 1}]', "order_id", "bypassed"),               # list repr
        # FIXED false positive: a 2xx ERROR envelope that merely NAMES the field
        # has no such key -> noop, NOT a false "bypassed" HIGH. (Was the pinned
        # substring-match limitation; structured key-presence resolves it.)
        (200, '{"error": "order_id is required"}', "order_id", "noop"),
        # 2xx + field configured but absent / null / non-JSON -> noop (indeterminate).
        (200, '{"status": "queued"}', "order_id", "noop"),
        (200, '{"order_id": null}', "order_id", "noop"),
        (200, "plain text OK", "order_id", "noop"),
        # 2xx with no success_field -> indeterminate (cannot disambiguate).
        (200, '{"order_id": 42}', None, "inconclusive"),
        # 401 is NOT in the default reject set -> indeterminate (auth, not order).
        (401, "", None, "inconclusive"),
        # Other statuses prove neither enforcement nor bypass.
        (404, "", None, "inconclusive"),
        (405, "", None, "inconclusive"),
        (302, "", None, "inconclusive"),
        (500, '{"order_id": 1}', "order_id", "inconclusive"),
        (0, "", None, "inconclusive"),
    ],
)
def test_step_sequence_verdict_classifies(status, body, field, expected):
    assert (
        _step_sequence_verdict(status, body, set(_REJECTION_STATUSES), field) == expected
    )


def test_step_sequence_verdict_honors_custom_reject_statuses():
    # An operator who knows 422 means "prerequisite missing" for this endpoint opts
    # it in -> the same 422 now counts as enforced.
    assert _step_sequence_verdict(422, "", {409, 425, 422}, None) == "enforced"


@pytest.mark.parametrize(
    "body,field,expected",
    [
        ('{"order_id": 42}', "order_id", True),
        ('{"order_id": 0}', "order_id", True),        # 0 is a real value, not empty
        ('{"order_id": null}', "order_id", False),
        ('{"order_id": ""}', "order_id", False),      # empty string is not a value
        ('{"data": {"order_id": 7}}', "data.order_id", True),
        ('{"data": {}}', "data.order_id", False),
        ('[{"order_id": 1}]', "order_id", True),      # PostgREST list representation
        ('{"error": "order_id required"}', "order_id", False),  # name mentioned, no key
        ("not json at all", "order_id", False),
        ('{"order_id": 42}', "", False),              # empty field path never matches
    ],
)
def test_success_field_present(body, field, expected):
    assert _success_field_present(body, field) is expected


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
