"""Build the runtime ZAP automation plan from the active pentest profile.

This module is the source of truth for ZAP requestor-injection. It was lifted
verbatim from the inline ``run.sh`` ``PYZAP`` heredoc so the logic is importable
and unit-testable (see ``tests/test_zap_runtime_plan.py`` and decision D7 of
``docs/plans/2026-06-10-001-refactor-test-quality-debt-and-coverage-plan.md``).

The committed ``zap/automation-plan.yaml`` ships an empty requestor list. We
inject one request per endpoint the frozen profile declares:

  - ``authenticated`` / ``payment`` / ``internal`` use the Bearer header set,
  - ``anonymous`` and the upload endpoint use the anon-key set,
  - ``webhook`` endpoints get signature-shaped probe headers.

``${TARGET_BASE_URL}`` / ``${JWT_TOKEN}`` / ``${SESSION_COOKIE}`` /
``${SUPABASE_ANON_KEY}`` are kept LITERAL so ZAP performs the env substitution
at scan time. The ``build_requestor_requests`` URL builder deliberately does NOT
route through ``helpers.netlify_url`` (which would resolve/rstrip the token and
break the literal-placeholder contract).

Pure functions (``build_requestor_requests`` / ``inject_into_plan``) own no IO;
the ``__main__`` block owns all filesystem and profile-loading IO and mirrors the
heredoc exactly (including non-zero exit on a missing requestor job so the
``run.sh`` static-skeleton fallback still fires).
"""

from __future__ import annotations

import json
import re

from exclusions import effective_exclude_paths, is_excluded_path

NIL_UUID = "00000000-0000-0000-0000-000000000000"


def zap_exclude_regexes(profile_data, *, base_token="${TARGET_BASE_URL}"):
    """Build ZAP context excludePaths regexes from the profile's exclude_paths.

    The requestor seam (build_requestor_requests) only stops ZAP from being
    *seeded* with an excluded endpoint — but the spider crawls public links and
    activeScan attacks whatever lands in the context, so a linked /logout (or a
    token-rotation path) would still be probed and could destroy the
    authenticated session mid-scan. These regexes add those paths to the
    context excludePaths so the spider and active scanner skip them too.

    ``${TARGET_BASE_URL}`` is kept LITERAL (ZAP substitutes it at scan time),
    mirroring the static-asset exclusions already in the plan. Each pattern is
    a full-URL match: ``<base>.*<path>`` with an optional ``[/?]...`` tail so a
    sub-path or query is covered but a segment-boundary sibling
    (``/reset-password-help`` vs ``/reset-password``) is not over-excluded.
    """
    patterns = []
    for path in effective_exclude_paths((profile_data or {}).get("exclude_paths")):
        patterns.append(f"{base_token}.*{re.escape(path)}(?:[/?].*)?")
    return patterns


class RequestorJobNotFound(Exception):
    """Raised when the automation plan has no ``requestor`` job to inject into."""


def build_requestor_requests(profile_data, *, base_token="${TARGET_BASE_URL}"):
    """Build the ZAP requestor request list from a profile dict.

    ``profile_data`` is the plain dict returned by ``profile.raw()``. Returns a
    list of request dicts (one per declared endpoint). Pure: no filesystem, no
    network, no profile loading.

    ``base_token`` is substituted everywhere the heredoc used the literal
    ``BASE`` token; it stays a literal string so ZAP resolves it at scan time.
    """
    data = profile_data
    base = base_token  # ZAP env-substitution token, kept literal
    prefix = ((data.get('target') or {}).get('api_prefix') or '/.netlify/functions').rstrip('/')
    endpoints = data.get('endpoints') or {}
    # Default-on probe exclusions (shared filter — same rules as the pytest
    # enumeration seam and discover.py, so no seam leaks an excluded path).
    exclude_paths = effective_exclude_paths(data.get('exclude_paths'))

    def excluded(path):
        return is_excluded_path(str(path), exclude_paths)

    def resolve(v):
        if isinstance(v, str):
            return v.replace('{{uuid}}', NIL_UUID).replace('{{base_url}}', base)
        return v

    def body_for(ep):
        pb = ep.get('probe_body') or {}
        if not isinstance(pb, dict):
            return ''
        return json.dumps({k: resolve(v) for k, v in pb.items()})

    def url_for(path):
        return f"{base}{prefix}/{str(path).lstrip('/')}"

    bearer = [
        "Content-Type: application/json",
        "Authorization: Bearer ${JWT_TOKEN}",
        "Cookie: ${SESSION_COOKIE}",
    ]
    anon = ["Content-Type: application/json", "apikey: ${SUPABASE_ANON_KEY}"]

    def webhook_headers(sig):
        sig = (sig or '').lower()
        if sig == 'svix':
            return [
                "Content-Type: application/json",
                "svix-id: zap-probe",
                "svix-timestamp: 0",
                "svix-signature: v1,probe",
            ]
        if sig == 'stripe':
            return ["Content-Type: application/json", "stripe-signature: t=0,v1=probe"]
        return ["Content-Type: application/json"]

    def req(path, method, headers, data_):
        return {
            'url': url_for(path),
            'method': method,
            'httpVersion': 'HTTP/1.1',
            'headers': list(headers),
            'data': data_,
        }

    requests = []
    for cat in ('authenticated', 'payment', 'internal'):
        for ep in (endpoints.get(cat) or []):
            if isinstance(ep, dict) and ep.get('path') and not excluded(ep['path']):
                requests.append(req(ep['path'], ep.get('method', 'POST'), bearer, body_for(ep)))
    for ep in (endpoints.get('anonymous') or []):
        if isinstance(ep, dict) and ep.get('path') and not excluded(ep['path']):
            requests.append(req(ep['path'], ep.get('method', 'POST'), anon, body_for(ep)))
    for ep in (endpoints.get('webhook') or []):
        if isinstance(ep, dict) and ep.get('path') and not excluded(ep['path']):
            requests.append(
                req(ep['path'], ep.get('method', 'POST'), webhook_headers(ep.get('signature')), body_for(ep))
            )
    # Upload endpoint (file-upload abuse surface) — seeded as an anon CSV POST.
    uploads = data.get('uploads') or {}
    if isinstance(uploads, dict) and uploads.get('endpoint') and not excluded(uploads['endpoint']):
        requests.append(
            req(
                uploads['endpoint'],
                'POST',
                ["Content-Type: text/csv", "apikey: ${SUPABASE_ANON_KEY}"],
                'col1,col2,col3\nval0,val1,val2',
            )
        )
    return requests


def inject_exclude_paths(plan_dict, exclude_regexes):
    """Append ``exclude_regexes`` to every context's ``excludePaths`` in place.

    Idempotent: a regex already present is not duplicated (so re-running the
    builder on an already-injected plan is a no-op). Returns ``plan_dict``.
    """
    if not exclude_regexes:
        return plan_dict
    for context in ((plan_dict.get('env') or {}).get('contexts') or []):
        existing = context.setdefault('excludePaths', [])
        for rx in exclude_regexes:
            if rx not in existing:
                existing.append(rx)
    return plan_dict


def inject_into_plan(plan_dict, requests, exclude_regexes=None):
    """Inject ``requests`` into the ``requestor`` job of ``plan_dict``.

    Also appends ``exclude_regexes`` to every context's ``excludePaths`` so the
    spider and active scanner honor the same exclusions as the requestor seam.

    Mutates and returns ``plan_dict``. Raises ``RequestorJobNotFound`` when no
    ``requestor`` job exists (mirrors the heredoc's ``sys.exit`` at run.sh:728).
    """
    inject_exclude_paths(plan_dict, exclude_regexes or [])
    for job in plan_dict.get('jobs', []):
        if job.get('type') == 'requestor':
            job['requests'] = requests
            return plan_dict
    raise RequestorJobNotFound("requestor job not found in zap/automation-plan.yaml")


if __name__ == "__main__":
    import os
    import sys

    import yaml

    sys.path.insert(0, '.')
    from profile import load_profile

    profile = load_profile(os.environ['PENTEST_PROFILE'])
    data = profile.raw()
    requests = build_requestor_requests(data)
    exclude_regexes = zap_exclude_regexes(data)

    with open('zap/automation-plan.yaml') as f:
        plan = yaml.safe_load(f)
    try:
        inject_into_plan(plan, requests, exclude_regexes)
    except RequestorJobNotFound as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    with open('zap/automation-plan.runtime.yaml', 'w') as f:
        yaml.safe_dump(plan, f, default_flow_style=False, sort_keys=False)
    print(f"[zap] injected {len(requests)} profile endpoint(s) into the runtime plan", file=sys.stderr)
