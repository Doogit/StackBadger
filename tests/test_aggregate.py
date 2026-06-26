"""Tests for standalone evidence promotion in reports.aggregate."""

from __future__ import annotations

import json
import sys
from pathlib import Path


_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

import pytest

from reports.aggregate import (
    _CATEGORY_PREFIXES,
    _PROVIDER_CATEGORIES,
    _PROVIDER_LAYER_MAP,
    _TEST_NAME_CATEGORY_OVERRIDES,
    _TEST_NAME_SEVERITY_OVERRIDES,
    _coverage_matrix,
    _endpoint_categories,
    _extract_severity_from_message,
    _is_standalone_finding_payload,
    _remediation_for_category,
    _root_cause_for_category,
    _test_stem_from_nodeid,
    _why_it_matters_for_category,
    TEST_CATEGORY_MAP,
    TEST_SEVERITY_MAP,
    build_evidence_findings,
    build_pytest_findings,
    failed_test_names,
    load_evidence,
    render_html,
)


def _replay_payload() -> dict:
    return {
        "finding": "lemonsqueezy_no_replay_protection",
        "severity": "MEDIUM",
        "category": "webhook_replay",
        "title": "LemonSqueezy webhook lacks replay protection",
        "description": "Captured valid requests can be replayed.",
        "remediation": "Deduplicate by event ID.",
        "note": "Architectural limitation.",
        "webhook_path": "/api/webhooks/lemonsqueezy",
        "generated_at": "2026-05-19T07:39:17Z",
    }


def test_load_evidence_separates_standalone_findings(tmp_path):
    payload = _replay_payload()
    (tmp_path / "ls_replay_protection_informational_20260519T073917Z.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    evidence_map, standalone_findings = load_evidence(tmp_path)

    assert evidence_map == {}
    assert standalone_findings == [payload]


def test_build_evidence_findings_promotes_replay_artifact():
    findings = build_evidence_findings(
        [_replay_payload()],
        {"/api/webhooks/lemonsqueezy": "netlify/functions/lemonsqueezy-webhook.js"},
        {},
        set(),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "MEDIUM"
    assert finding["category"] == "webhook_replay"
    assert finding["endpoint"] == "/api/webhooks/lemonsqueezy"
    assert finding["affected_files"] == ["netlify/functions/lemonsqueezy-webhook.js"]
    assert "Architectural limitation." in finding["description"]


def test_build_evidence_findings_skips_duplicate_failed_pytest_probe():
    findings = build_evidence_findings(
        [_replay_payload()],
        {},
        {},
        {"test_replay_protection_informational"},
    )

    assert findings == []


def test_build_evidence_findings_promotes_when_other_tests_failed():
    # The probe test passed (its name is absent), but unrelated tests failed.
    # The standalone finding must still be promoted.
    findings = build_evidence_findings(
        [_replay_payload()],
        {},
        {},
        {"test_some_unrelated_probe"},
    )

    assert len(findings) == 1
    assert findings[0]["category"] == "webhook_replay"


def test_is_standalone_finding_payload_accepts_empty_description():
    payload = _replay_payload()
    payload["description"] = ""

    assert _is_standalone_finding_payload(payload) is True


def test_is_standalone_finding_payload_rejects_node_bound_evidence():
    node_bound = {
        "request": {"method": "POST", "headers": {}},
        "response": {"status": 200},
        "timestamp": "2026-05-19T07:39:17Z",
    }

    assert _is_standalone_finding_payload(node_bound) is False


def test_failed_test_names_strips_parametrize_suffix():
    pytest_data = {
        "tests": [
            {"nodeid": "tests/test_x.py::test_replay_protection_informational[case0]", "outcome": "failed"},
            {"nodeid": "tests/test_x.py::test_plain", "outcome": "error"},
            {"nodeid": "tests/test_x.py::test_passing[case1]", "outcome": "passed"},
        ]
    }

    names = failed_test_names(pytest_data)

    assert names == {"test_replay_protection_informational", "test_plain"}


def test_failed_test_names_suffix_strip_enables_dedup():
    # A parametrized probe failure must still suppress the standalone copy.
    pytest_data = {
        "tests": [
            {
                "nodeid": "tests/test_x.py::test_replay_protection_informational[ipv4]",
                "outcome": "failed",
            }
        ]
    }

    findings = build_evidence_findings(
        [_replay_payload()], {}, {}, failed_test_names(pytest_data)
    )

    assert findings == []


# ---------------------------------------------------------------------------
# U10 — provider-layer reporting
# ---------------------------------------------------------------------------

_EXPECTED_PROVIDER_CATEGORIES = {
    "firebase_auth", "firestore_rules", "firebase_storage",
    "supabase_auth", "nextauth", "s3_storage",
    "webhook_paddle", "webhook_lemonsqueezy",
}


def _finding(category: str, **over) -> dict:
    """Minimal but template-complete finding dict for render tests."""
    finding = {
        "id": f"{category}-001",
        "title": f"{category} sample finding",
        "severity": "HIGH",
        "category": category,
        "source": "pytest",
        "endpoint": "",
        "method": "POST",
        "description": "desc",
        "solution": "",
        "reference": "",
        "evidence": {"request": {}, "response": {}},
        "affected_files": [],
        "root_cause": "",
        "why_it_matters": "",
        "remediation_plan": "",
        "test_to_verify": "",
        "related_findings": [],
        "scope_estimate": "S",
        "false_positive": False,
        "known_exception_reason": None,
    }
    finding.update(over)
    return finding


@pytest.mark.parametrize(
    "node_id,expected",
    [
        ("tests/test_s3_storage.py::TestBucket::test_listing", "test_s3_storage"),
        ("tests/test_firebase_auth_adapter.py::test_mfa", "test_firebase_auth_adapter"),
        ("tests/test_webhook_paddle.py::test_forged", "test_webhook_paddle"),
        # Boundary guard: "test_" embedded mid-filename must not match.
        ("tests/not_a_test_file.py::setup", ""),
        ("tests/helper.py::go", ""),
    ],
)
def test_test_stem_from_nodeid(node_id, expected):
    assert _test_stem_from_nodeid(node_id) == expected


def test_provider_categories_match_expected_set():
    assert _PROVIDER_CATEGORIES == _EXPECTED_PROVIDER_CATEGORIES


def test_provider_categories_are_subset_of_test_category_map():
    assert _PROVIDER_CATEGORIES <= set(TEST_CATEGORY_MAP.values())


def test_provider_layer_map_keys_match_provider_categories():
    # Guards against drift between the layer map and the authoritative set.
    assert set(_PROVIDER_LAYER_MAP) == _PROVIDER_CATEGORIES


def test_endpoint_categories_exclude_providers_and_dedup():
    cats = _endpoint_categories()
    assert not (_PROVIDER_CATEGORIES & set(cats))
    assert len(cats) == len(set(cats))  # no duplicate columns


@pytest.mark.parametrize("category", sorted(_EXPECTED_PROVIDER_CATEGORIES))
def test_provider_content_dicts_have_specific_entries(category):
    generic_remediation = "Review the flagged code path and apply secure coding best practices."
    assert _remediation_for_category(category, "HIGH", {}) != generic_remediation
    assert _root_cause_for_category(category) != "Unclassified vulnerability."
    assert _why_it_matters_for_category(category) != "This vulnerability may impact application security."


# Phase-1 ASVS probe modules MUST be fully wired into the ledger or their HIGH
# findings silently downgrade to MEDIUM/api_surface and the run.sh exit-1 gate
# breaks. Guard the full wiring (stem->severity, stem->category, category->prefix,
# and non-generic content) so a typo or a dropped map entry fails offline.
@pytest.mark.parametrize(
    "stem,category,severity,prefix",
    [
        ("test_session", "session", "HIGH", "SESS"),
        ("test_data_protection", "data_protection", "MEDIUM", "DATAP"),
        ("test_oauth_flow", "oauth", "HIGH", "OAUTH"),
    ],
)
def test_phase1_modules_fully_wired_into_ledger(stem, category, severity, prefix):
    assert TEST_SEVERITY_MAP.get(stem) == severity
    assert TEST_CATEGORY_MAP.get(stem) == category
    assert _CATEGORY_PREFIXES.get(category) == prefix
    # Content dicts must return module-specific (non-generic) text.
    assert _remediation_for_category(category, severity, {}) != (
        "Review the flagged code path and apply secure coding best practices."
    )
    assert _root_cause_for_category(category) != "Unclassified vulnerability."
    assert _why_it_matters_for_category(category) != (
        "This vulnerability may impact application security."
    )


# Phase-2 ASVS coverage-ceiling modules carry the same ledger DoD as Phase 1:
# every new module must be fully wired or its HIGH findings silently downgrade
# to MEDIUM/api_surface and the run.sh exit-1 gate breaks.
@pytest.mark.parametrize(
    "stem,category,severity,prefix",
    [
        ("test_mass_assignment", "mass_assignment", "HIGH", "MASS"),
        # §P2-G business-logic: file-stem MEDIUM (per-user quota gap, CWE-799); the
        # step-sequence bypass self-escalates HIGH inline (CWE-841), covered by the
        # e2e escalation test below.
        ("test_business_logic", "business_logic", "MEDIUM", "BIZLOG"),
    ],
)
def test_phase2_modules_fully_wired_into_ledger(stem, category, severity, prefix):
    assert TEST_SEVERITY_MAP.get(stem) == severity
    assert TEST_CATEGORY_MAP.get(stem) == category
    assert _CATEGORY_PREFIXES.get(category) == prefix
    # Content dicts must return module-specific (non-generic) text.
    assert _remediation_for_category(category, severity, {}) != (
        "Review the flagged code path and apply secure coding best practices."
    )
    assert _root_cause_for_category(category) != "Unclassified vulnerability."
    assert _why_it_matters_for_category(category) != (
        "This vulnerability may impact application security."
    )


# Phase-2 §P2-B/§P2-E probes EXTEND existing modules (test_api_surface.py,
# test_cors_headers.py) rather than adding a new file stem, so they attach their
# category and severity through the per-test-NAME override maps. The stem-based
# guards above cannot see them. Guard the function-level wiring directly: without
# the category override the finding files under api_surface/cors_headers; without
# the prefix the id falls back to FIND-; without the severity override a HIGH CSRF
# finding silently downgrades and breaks the run.sh exit-1 gate.
@pytest.mark.parametrize(
    "test_func,category,severity,prefix",
    [
        ("test_trace_method_is_rejected", "method_hardening", "MEDIUM", "METH"),
        ("test_state_change_requires_anti_csrf_token", "csrf", "HIGH", "CSRF"),
        ("test_csp_frame_ancestors_restricts_framing", "frame_ancestors", "MEDIUM", "FRAME"),
        # §P2-C file-handling probes (extend test_file_upload.py).
        ("test_upload_zip_bomb_rejected", "file_dos", "MEDIUM", "FDOS"),
        ("test_served_upload_sets_content_disposition", "file_serve", "MEDIUM", "FSERVE"),
        # §P2-D auth-delta probes (extend test_auth_flows.py).
        ("test_registration_rejects_weak_password", "password_policy", "MEDIUM", "PWPOL"),
        ("test_signin_response_is_enumeration_safe", "user_enumeration", "MEDIUM", "ENUM"),
        # §P2-F Paddle stale-timestamp replay (extends test_webhook_paddle.py); routes
        # to webhook_replay/MEDIUM, overriding the paddle stem's HIGH/webhook_paddle.
        ("test_replay_stale_timestamp_rejected", "webhook_replay", "MEDIUM", "WREPLAY"),
    ],
)
def test_phase2_per_test_override_modules_wired_into_ledger(
    test_func, category, severity, prefix
):
    assert _TEST_NAME_CATEGORY_OVERRIDES.get(test_func) == category
    assert _TEST_NAME_SEVERITY_OVERRIDES.get(test_func) == severity
    assert _CATEGORY_PREFIXES.get(category) == prefix
    # Content dicts must return module-specific (non-generic) text.
    assert _remediation_for_category(category, severity, {}) != (
        "Review the flagged code path and apply secure coding best practices."
    )
    assert _root_cause_for_category(category) != "Unclassified vulnerability."
    assert _why_it_matters_for_category(category) != (
        "This vulnerability may impact application security."
    )


# §P2-F payments maps the existing Stripe/Paddle/LemonSqueezy + payment-gate probes
# into the ASVS/CWE ledger. These modules already carry file-stem ledger entries; guard
# them with the same DoD as the Phase-1/2 new modules so a dropped severity/category/
# prefix or a generic content fallback fails offline (a downgraded HIGH webhook/payment
# finding would break the run.sh exit-1 gate).
@pytest.mark.parametrize(
    "stem,category,severity,prefix",
    [
        ("test_payment_gate", "payment_gate", "HIGH", "PAY"),
        ("test_webhook_spoofing", "webhook_spoofing", "HIGH", "HOOK"),
        ("test_webhook_paddle", "webhook_paddle", "HIGH", "PADL"),
        ("test_webhook_lemonsqueezy", "webhook_lemonsqueezy", "MEDIUM", "LMSQ"),
    ],
)
def test_phase2f_payment_modules_wired_into_ledger(stem, category, severity, prefix):
    assert TEST_SEVERITY_MAP.get(stem) == severity
    assert TEST_CATEGORY_MAP.get(stem) == category
    assert _CATEGORY_PREFIXES.get(category) == prefix
    # Content dicts must return module-specific (non-generic) text.
    assert _remediation_for_category(category, severity, {}) != (
        "Review the flagged code path and apply secure coding best practices."
    )
    assert _root_cause_for_category(category) != "Unclassified vulnerability."
    assert _why_it_matters_for_category(category) != (
        "This vulnerability may impact application security."
    )


def test_paddle_replay_override_resolves_through_class_qualified_nodeid():
    """The §P2-F Paddle replay probe is a class method, so its nodeid carries a
    `TestPaddleWebhookSignature::` prefix and no [param] suffix. Drive the real
    aggregator pipeline (not just the static override maps) to prove the per-test
    override still resolves through the class-qualified nodeid. Without correct
    class-prefix stripping the finding would fall back to the paddle stem
    (webhook_paddle/HIGH/PADL-###), flipping a MEDIUM-only run.sh from exit 2 to
    exit 1. The parametrized static-map guard above cannot catch a regression in
    that lookup; this end-to-end test does.
    """
    # Deliberately omit any inline severity keyword from the longrepr so the MEDIUM
    # resolves through _TEST_NAME_SEVERITY_OVERRIDES, not _extract_severity_from_message.
    # This guards both the category AND the severity override resolving through the
    # class-qualified, non-parametrized nodeid. (The inline-"MEDIUM:" path the probe
    # actually emits is covered by test_inline_high_escalation_from_frame_ancestors_pytest_fail.)
    pytest_data = {
        "tests": [
            {
                "nodeid": (
                    "tests/test_webhook_paddle.py::TestPaddleWebhookSignature::"
                    "test_replay_stale_timestamp_rejected"
                ),
                "outcome": "failed",
                "call": {"longrepr": "Failed: Paddle webhook accepted a stale-timestamp event ..."},
            }
        ]
    }

    findings = build_pytest_findings(pytest_data, {}, {}, {})

    assert len(findings) == 1
    assert findings[0]["category"] == "webhook_replay"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["id"].startswith("WREPLAY-")


def test_stripe_forged_replay_node_stays_webhook_spoofing():
    """The Stripe forged-replay probe sends a FORGED signature (the harness has no
    Stripe webhook secret), so a failure is a signature bypass, not a replay gap. It
    deliberately stays in webhook_spoofing/HIGH rather than routing to
    webhook_replay/MEDIUM like the valid-signature Paddle/LemonSqueezy replay probes:
    routing it to webhook_replay would mislabel and downgrade a real signature bypass.
    Lock that classification in so it is not "corrected" to webhook_replay by mistake.
    """
    pytest_data = {
        "tests": [
            {
                "nodeid": (
                    "tests/test_webhook_spoofing.py::"
                    "test_stripe_webhook_forged_replay_rejected[POST:/webhook]"
                ),
                "outcome": "failed",
                "call": {"longrepr": "Failed: webhook returned 200 for a forged stale signature ..."},
            }
        ]
    }

    findings = build_pytest_findings(pytest_data, {}, {}, {})

    assert len(findings) == 1
    assert findings[0]["category"] == "webhook_spoofing"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["id"].startswith("HOOK-")


def test_inline_high_escalation_from_frame_ancestors_pytest_fail():
    """The frame-ancestors probe self-escalates to HIGH via an inline 'HIGH:' in
    its pytest.fail() message when the page is framable by any origin. The MEDIUM
    floor in _TEST_NAME_SEVERITY_OVERRIDES would otherwise cap it, so guard that
    the aggregator lifts the longrepr to HIGH. Without this the run.sh exit-1 gate
    would not fire on a fully-clickjackable page.
    """
    # pytest.fail("HIGH: ...") yields a longrepr prefixed with "Failed: ".
    high_longrepr = (
        "Failed: HIGH: CSP frame-ancestors does not restrict framing (CSP: "
        "'(absent)') and X-Frame-Options is absent/invalid ('')."
    )
    assert _extract_severity_from_message(high_longrepr) == "HIGH"
    # The MEDIUM-floor message (legacy X-Frame-Options present, no inline keyword)
    # carries no severity keyword, so it falls through to the override map (MEDIUM).
    medium_longrepr = (
        "Failed: CSP frame-ancestors does not restrict framing (CSP: "
        "'(absent)'); the app relies on legacy X-Frame-Options ('DENY')."
    )
    assert _extract_severity_from_message(medium_longrepr) is None
    # The §P2-F Paddle replay probe emits an inline "MEDIUM:" on its reprocessing
    # path. It agrees with the override-map MEDIUM today, but guard the extractor's
    # MEDIUM branch so a future inline keyword change is caught rather than silent.
    paddle_replay_longrepr = (
        "Failed: MEDIUM: Paddle webhook reprocessed a validly-signed event with a "
        "stale timestamp ..."
    )
    assert _extract_severity_from_message(paddle_replay_longrepr) == "MEDIUM"


def test_business_logic_step_sequence_escalates_to_high():
    """The §P2-G step-sequence probe lives in test_business_logic.py (file-stem
    MEDIUM) but self-escalates to HIGH via an inline 'HIGH:' in its pytest.fail()
    message when a gated step is accepted out of order (CWE-841). Drive the real
    aggregator pipeline to prove the longrepr lifts the finding above the MEDIUM
    default; without this a true step-sequence bypass would report MEDIUM and not
    fire the run.sh exit-1 gate.
    """
    pytest_data = {
        "tests": [
            {
                "nodeid": (
                    "tests/test_business_logic.py::"
                    "test_gated_steps_reject_out_of_order_requests"
                ),
                "outcome": "failed",
                "call": {
                    "longrepr": (
                        "Failed: HIGH: gated step(s) accepted out of order — the flow "
                        "does not enforce step sequence ..."
                    )
                },
            }
        ]
    }

    findings = build_pytest_findings(pytest_data, {}, {}, {})

    assert len(findings) == 1
    assert findings[0]["category"] == "business_logic"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["id"].startswith("BIZLOG-")


def test_business_logic_quota_node_stays_medium():
    """The §P2-G per-user-quota probe (same module) emits no inline severity
    keyword, so an absent-quota failure must resolve to the file-stem MEDIUM and
    the business_logic category — not silently fall back to api_surface. A MEDIUM
    quota finding must keep a MEDIUM-only run at exit 2, never flip it to exit 1.
    """
    pytest_data = {
        "tests": [
            {
                "nodeid": (
                    "tests/test_business_logic.py::"
                    "test_authenticated_endpoint_enforces_per_user_quota"
                ),
                "outcome": "failed",
                "call": {"longrepr": "Failed: per-user quota appears absent: 60 ..."},
            }
        ]
    }

    findings = build_pytest_findings(pytest_data, {}, {}, {})

    assert len(findings) == 1
    assert findings[0]["category"] == "business_logic"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["id"].startswith("BIZLOG-")


def test_pytest_finding_override_resolves_through_parametrize_suffix():
    """A parametrized probe (e.g. the per-endpoint TRACE matrix) must still resolve
    its per-test-name category/severity override; the [param] suffix is stripped
    before the override-map lookup. Without this a parametrized HIGH/MEDIUM probe
    would silently fall back to the file stem (api_surface) and miscategorise.
    """
    pytest_data = {
        "tests": [
            {
                "nodeid": (
                    "tests/test_api_surface.py::TestTraceMethod::"
                    "test_trace_method_is_rejected[<root>]"
                ),
                "outcome": "failed",
                "call": {"longrepr": "Failed: TRACE https://x/ returned 200 ..."},
            }
        ]
    }

    findings = build_pytest_findings(pytest_data, {}, {}, {})

    assert len(findings) == 1
    assert findings[0]["category"] == "method_hardening"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["id"].startswith("METH-")


def test_coverage_matrix_excludes_provider_categories():
    profile = {"endpoints": {"core": [{"path": "/api/login"}]}}
    findings = [
        _finding("auth_bypass", endpoint="/api/login"),
        _finding("s3_storage"),
    ]

    rows = _coverage_matrix(findings, profile)

    assert len(rows) == 1
    cols = rows[0]["categories"]
    assert "s3_storage" not in cols
    assert cols["auth_bypass"] is True


def test_render_html_routes_provider_finding_to_provider_section(tmp_path):
    profile = {
        "target": {"base_url": "https://example.com"},
        "endpoints": {"core": [{"path": "/api/login"}]},
    }
    findings = [
        _finding("auth_bypass", endpoint="/api/login", title="Endpoint auth bypass"),
        # firestore_rules → layer "database" (a distinctive, single-source value
        # now supplied by _PROVIDER_LAYER_MAP rather than the template).
        _finding("firestore_rules", title="Firestore rules too permissive"),
    ]

    out = render_html(findings, profile, tmp_path, generated_at="2026-06-09T00:00:00Z")
    html = out.read_text(encoding="utf-8")

    assert "Provider Layer Findings" in html
    assert "Firestore rules too permissive" in html
    assert "test_firestore_rules.py" in html
    # Layer column resolved from _PROVIDER_LAYER_MAP, not reconstructed in-template.
    assert "<td>database</td>" in html
