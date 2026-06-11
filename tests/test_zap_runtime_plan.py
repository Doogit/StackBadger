"""Characterization tests for the extracted ZAP runtime-plan generator (U6 / R6).

Targets the pure functions in ``zap/build_runtime_plan.py`` only — no Docker,
no bash, no network, no profile loading. Locks the requestor-injection contract
from the heredoc that previously lived inline in ``run.sh`` (L631-732):

  - one requestor request per declared endpoint,
  - the per-category header decision matrix,
  - literal ``${...}`` ZAP substitution tokens (never resolved),
  - no real secret/hostname leakage even when the profile carries real values.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

# Bootstrap the repo root so ``from zap.build_runtime_plan import ...`` resolves
# regardless of pytest's invocation cwd.
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from zap.build_runtime_plan import (  # noqa: E402
    RequestorJobNotFound,
    build_requestor_requests,
    inject_into_plan,
)

NIL_UUID = "00000000-0000-0000-0000-000000000000"

BEARER_HEADERS = [
    "Content-Type: application/json",
    "Authorization: Bearer ${JWT_TOKEN}",
    "Cookie: ${SESSION_COOKIE}",
]
ANON_HEADERS = ["Content-Type: application/json", "apikey: ${SUPABASE_ANON_KEY}"]
UPLOAD_HEADERS = ["Content-Type: text/csv", "apikey: ${SUPABASE_ANON_KEY}"]


# ---------------------------------------------------------------------------
# Profile-dict builders (the shape returned by profile.raw())
# ---------------------------------------------------------------------------

def _full_profile():
    """One endpoint per category exercising every header branch."""
    return {
        "target": {"api_prefix": "/.netlify/functions"},
        "endpoints": {
            "authenticated": [{"path": "/get-records", "method": "POST", "probe_body": {"id": "{{uuid}}"}}],
            "payment": [{"path": "/create-checkout-session", "method": "POST", "probe_body": {}}],
            "internal": [{"path": "/admin-sync", "method": "POST"}],
            "anonymous": [{"path": "/public-config", "method": "GET", "probe_body": {"ref": "{{base_url}}/x"}}],
            "webhook": [
                {"path": "/webhook-clerk", "method": "POST", "signature": "svix"},
                {"path": "/webhook-stripe", "method": "POST", "signature": "stripe"},
            ],
        },
        "uploads": {"endpoint": "/upload-csv"},
    }


def _find(requests, url_suffix):
    """Return the single request whose url ends with ``url_suffix``."""
    matches = [r for r in requests if r["url"].endswith(url_suffix)]
    assert len(matches) == 1, f"expected exactly one request for {url_suffix!r}, got {len(matches)}"
    return matches[0]


# ---------------------------------------------------------------------------
# Happy path — one request per endpoint, correct header set per matrix
# ---------------------------------------------------------------------------

def test_one_request_per_endpoint_with_correct_headers():
    requests = build_requestor_requests(_full_profile())

    # 1 authenticated + 1 payment + 1 internal + 1 anonymous + 2 webhook + 1 upload
    assert len(requests) == 7

    # BEARER for authenticated / payment / internal.
    for suffix in ("/get-records", "/create-checkout-session", "/admin-sync"):
        assert _find(requests, suffix)["headers"] == BEARER_HEADERS

    # ANON for anonymous.
    assert _find(requests, "/public-config")["headers"] == ANON_HEADERS

    # svix / stripe webhook signature headers.
    svix = _find(requests, "/webhook-clerk")["headers"]
    assert "svix-id: zap-probe" in svix
    assert "svix-timestamp: 0" in svix
    assert "svix-signature: v1,probe" in svix
    assert not any(h.startswith("stripe-signature") for h in svix)

    stripe = _find(requests, "/webhook-stripe")["headers"]
    assert "stripe-signature: t=0,v1=probe" in stripe
    assert not any(h.startswith("svix-") for h in stripe)

    # uploads endpoint → anon CSV POST.
    upload = _find(requests, "/upload-csv")
    assert upload["headers"] == UPLOAD_HEADERS
    assert upload["data"] == "col1,col2,col3\nval0,val1,val2"
    assert upload["method"] == "POST"


def test_webhook_other_or_absent_signature_gets_plain_content_type():
    """Decision-matrix row 3: webhook with no/unknown signature → Content-Type only.

    Neither svix nor stripe signature headers may be emitted for an unrecognised
    (or absent) ``signature`` value.
    """
    profile = {
        "target": {"api_prefix": "/.netlify/functions"},
        "endpoints": {
            "webhook": [
                {"path": "/webhook-none", "method": "POST"},                 # no signature key
                {"path": "/webhook-paddle", "method": "POST", "signature": "paddle"},  # unknown
            ]
        },
    }
    requests = build_requestor_requests(profile)
    for suffix in ("/webhook-none", "/webhook-paddle"):
        headers = _find(requests, suffix)["headers"]
        assert headers == ["Content-Type: application/json"]
        assert not any(h.startswith("svix-") for h in headers)
        assert not any(h.startswith("stripe-signature") for h in headers)


def test_request_shape_and_probe_body_resolution():
    requests = build_requestor_requests(_full_profile())

    authed = _find(requests, "/get-records")
    assert authed["httpVersion"] == "HTTP/1.1"
    assert authed["method"] == "POST"
    # {{uuid}} resolved to the nil UUID inside the JSON body.
    assert authed["data"] == f'{{"id": "{NIL_UUID}"}}'

    # {{base_url}} resolves to the base token (kept literal), not a real host.
    anon = _find(requests, "/public-config")
    assert anon["data"] == '{"ref": "${TARGET_BASE_URL}/x"}'
    assert anon["method"] == "GET"

    # url_for joins base token + prefix + path literally.
    assert authed["url"] == "${TARGET_BASE_URL}/.netlify/functions/get-records"


# ---------------------------------------------------------------------------
# Edge cases — empty / single-category profiles
# ---------------------------------------------------------------------------

def test_empty_categories_yield_no_requests():
    requests = build_requestor_requests({"target": {}, "endpoints": {}})
    assert requests == []


def test_only_authenticated_yields_exactly_those():
    profile = {
        "target": {"api_prefix": "/.netlify/functions"},
        "endpoints": {
            "authenticated": [
                {"path": "/a", "method": "POST"},
                {"path": "/b", "method": "GET"},
            ]
        },
    }
    requests = build_requestor_requests(profile)
    assert len(requests) == 2
    assert {r["url"] for r in requests} == {
        "${TARGET_BASE_URL}/.netlify/functions/a",
        "${TARGET_BASE_URL}/.netlify/functions/b",
    }
    for r in requests:
        assert r["headers"] == BEARER_HEADERS


def test_default_prefix_when_target_absent():
    profile = {"endpoints": {"authenticated": [{"path": "/x"}]}}
    requests = build_requestor_requests(profile)
    assert requests[0]["url"] == "${TARGET_BASE_URL}/.netlify/functions/x"
    # default method is POST.
    assert requests[0]["method"] == "POST"


# ---------------------------------------------------------------------------
# Literals — ${...} tokens stay unsubstituted everywhere
# ---------------------------------------------------------------------------

def test_all_tokens_remain_literal():
    requests = build_requestor_requests(_full_profile())
    blob = yaml.safe_dump(requests)

    for token in ("${TARGET_BASE_URL}", "${JWT_TOKEN}", "${SESSION_COOKIE}", "${SUPABASE_ANON_KEY}"):
        assert token in blob, f"{token} missing from generated plan"

    # Prove no resolved value crept in: every url still carries the literal base
    # token, and no Bearer/Cookie header was filled with a concrete credential.
    for r in requests:
        assert r["url"].startswith("${TARGET_BASE_URL}")
    bearer = _find(requests, "/get-records")["headers"]
    assert "Cookie: ${SESSION_COOKIE}" in bearer
    # No accidental resolution: any Authorization header still carries the token.
    assert all("Bearer ${JWT_TOKEN}" in h or not h.startswith("Authorization") for h in bearer)


# ---------------------------------------------------------------------------
# R6 leak guard — real key / real host must NOT appear in serialized output
# ---------------------------------------------------------------------------

def test_real_anon_key_and_host_never_leak():
    """R6: a profile carrying real credentials must never serialize them.

    This guards two distinct leak paths:
      1. The generator must source NO secret from the profile — it emits only
         the literal ``${SUPABASE_ANON_KEY}`` token. Feeding a real key proves a
         future "enrichment" refactor that started reading ``supabase.anon_key``
         would be caught.
      2. The ``resolve()`` path DOES read profile-sourced ``probe_body`` values.
         A ``{{base_url}}`` placeholder must resolve to the literal
         ``${TARGET_BASE_URL}`` token, NOT to the profile's real ``base_url``.
         The probe_body below routes the real host through ``resolve()`` so the
         host-leak assertion has teeth: were ``resolve()`` to substitute the real
         base_url, ``real_host`` would appear in the serialized output.
    """
    real_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKEFAKE.sig"
    real_host = "https://realapp.example-not.com"
    profile = {
        "target": {"api_prefix": "/.netlify/functions", "base_url": real_host},
        "supabase": {"anon_key": real_key},
        "endpoints": {
            # probe_body forces real_host through resolve() via {{base_url}}.
            "anonymous": [
                {
                    "path": "/public-config",
                    "method": "GET",
                    "probe_body": {"callback": "{{base_url}}/cb", "id": "{{uuid}}"},
                }
            ],
        },
        "uploads": {"endpoint": "/upload-csv"},
    }
    requests = build_requestor_requests(profile)
    serialized = yaml.safe_dump(requests)

    # (a) The real key value appears NOWHERE — the generator only emits the token.
    assert real_key not in serialized
    # (b) The real host must not leak — resolve() turns {{base_url}} into the
    # literal token, never the profile's base_url. (Has teeth: the probe_body
    # routes real_host through resolve().)
    assert real_host not in serialized
    assert "realapp.example-not.com" not in serialized
    # The resolved {{base_url}} became the literal token, proving the substitution
    # ran but stayed literal.
    anon = _find(requests, "/public-config")
    assert anon["data"] == '{"callback": "${TARGET_BASE_URL}/cb", "id": "%s"}' % NIL_UUID

    # (c) ${SUPABASE_ANON_KEY} appears exactly once per anon-category endpoint.
    # Two anon-keyed endpoints here (anonymous + uploads), each emits the token
    # exactly once in its header list.
    anon_endpoints = 2  # /public-config (anonymous) + /upload-csv (uploads)
    assert serialized.count("${SUPABASE_ANON_KEY}") == anon_endpoints
    # The literal token is present (contract: token emitted, real value absent).
    assert "${SUPABASE_ANON_KEY}" in serialized


# ---------------------------------------------------------------------------
# inject_into_plan — requestor job injection + missing-job exception
# ---------------------------------------------------------------------------

def test_inject_into_plan_sets_requestor_requests():
    plan = {
        "jobs": [
            {"type": "spider"},
            {"type": "requestor", "requests": []},
            {"type": "activeScan"},
        ]
    }
    reqs = build_requestor_requests(_full_profile())
    returned = inject_into_plan(plan, reqs)

    # mutate-and-return: same object, requestor job populated, order preserved.
    assert returned is plan
    assert plan["jobs"][1]["requests"] == reqs
    assert [j["type"] for j in plan["jobs"]] == ["spider", "requestor", "activeScan"]


def test_inject_into_plan_raises_when_no_requestor_job():
    plan = {"jobs": [{"type": "spider"}, {"type": "activeScan"}]}
    try:
        inject_into_plan(plan, [])
    except RequestorJobNotFound:
        pass
    else:
        raise AssertionError("expected RequestorJobNotFound when no requestor job is present")
