"""File upload abuse tests targeting the profile's declared upload endpoint.

The upload endpoint is read from ``profile.uploads.endpoint``; tests skip when
the active profile declares no upload endpoint.

Test categories:
- Wrong file type (exe, html, svg) with text/csv content-type
- Malformed/broken encoding CSV
- Oversized upload (>25 MB)
- Path traversal in multipart filename
- Double extension filenames (csv.html, csv%00.exe)
- Null bytes in filename
- Content-type spoofing
- Decompression bomb rejection (ASVS 5.2.3, CWE-409; §P2-C)
- Content-Disposition on served uploads (ASVS 5.4.1, CWE-434; §P2-C)

§P2-C scope note: server-side AV/malware scanning (ASVS 5.4.3) is NOT a
probe here. Whether the server scans an uploaded file for malware is not
reliably observable from outside: a clean response to an EICAR-style upload
could mean the scanner ran and passed, that no scanner exists, or that the
file was queued for async scanning. There is no black-box signal that
distinguishes those cases, so 5.4.3 is a documented Not-Applicable for this
harness rather than a flaky probe.
"""

from __future__ import annotations

import gzip
import io
import os
import subprocess
import sys as _sys
import types
from pathlib import Path, Path as _Path

import httpx
import pytest

# ---------------------------------------------------------------------------
# Collection-time profile loading
# ---------------------------------------------------------------------------

_PKG_ROOT = _Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PKG_ROOT))

from profile import load_profile, resolve_profile_path  # noqa: E402
# Probes that reach a storage/serve endpoint or send a heavy/mutating payload
# reuse the shared sender and sanitized-evidence shim, mirroring the §P2-B
# probes in test_api_surface.py.
from helpers import FakeResponse, send_request  # noqa: E402


def _collection_profile():
    """Load profile at collection time."""
    try:
        return load_profile(resolve_profile_path(_PKG_ROOT))
    except Exception:
        return None


_PROFILE = _collection_profile()

# ---------------------------------------------------------------------------
# Fixture path
# ---------------------------------------------------------------------------

_FIXTURES = _Path(__file__).resolve().parent.parent / "fixtures"

# Synthetic large-body size if oversized fixture is unavailable (26 MB).
# Must exceed Netlify's 6 MB function request body limit to reliably trigger
# 413 rejection. Using 5 MB previously caused false positives since it fell
# below the limit and healthy endpoints returned 2xx.
_SYNTHETIC_LARGE_BYTES = 26 * 1024 * 1024


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _endpoint_url(profile) -> str:
    from conftest import upload_path

    base = (profile.target.base_url or "").rstrip("/")
    prefix = (profile.target.api_prefix or "/.netlify/functions").rstrip("/")
    return f"{base}{prefix}{upload_path(profile)}"


def _send_upload(
    url: str,
    filename: str,
    content: bytes,
    content_type: str = "text/csv",
    timeout: float = 30.0,
) -> httpx.Response:
    """POST a file to url via multipart/form-data."""
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        files = {"file": (filename, io.BytesIO(content), content_type)}
        return client.post(url, files=files)


def _assert_rejection(resp: httpx.Response, context: str) -> None:
    """Assert the server rejected the upload (4xx) and did not crash (not 500)."""
    assert resp.status_code != 500, (
        f"{context}: returned 500 (unhandled server error)"
    )
    assert resp.status_code in range(400, 500), (
        f"{context}: returned {resp.status_code}; expected 4xx rejection, not acceptance or crash"
    )


def _assert_not_500(resp: httpx.Response, context: str) -> None:
    """Assert the server did not crash regardless of acceptance/rejection."""
    assert resp.status_code != 500, (
        f"{context}: returned 500 (unhandled server error)"
    )


def _minimal_csv() -> bytes:
    """Return a minimal valid CSV as bytes.

    Column headers are loaded from profile.uploads.column_headers when available.
    The data row uses generic synthetic values that match the column count.
    """
    headers: list[str] = (
        list(_PROFILE.uploads.column_headers)
        if _PROFILE and _PROFILE.uploads and _PROFILE.uploads.column_headers
        else ["col1", "col2", "col3"]
    )
    header_line = ",".join(headers)
    # Build a data row with the same number of columns using placeholder values.
    data_row = ",".join(f"val{i}" for i in range(len(headers)))
    return f"{header_line}\n{data_row}\n".encode("utf-8")


# ---------------------------------------------------------------------------
# Wrong file type — .exe with text/csv content-type
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
def test_upload_exe_file_csv_content_type(profile, evidence):
    """Upload of a .exe file (even with text/csv content-type) must be rejected (4xx)."""
    url = _endpoint_url(profile)
    # Use minimal CSV bytes but an .exe filename — server must validate the extension.
    content = _minimal_csv()
    resp = _send_upload(url, filename="malware.exe", content=content, content_type="text/csv")
    context = "upload malware.exe (text/csv)"
    _assert_not_500(resp, context)
    # The endpoint should reject by extension; accept 200 only if the upload was
    # truly ignored and no processing occurred (which we cannot verify externally).
    if resp.status_code < 400:
        evidence.capture(resp, "upload_exe_accepted_unexpected")
    _assert_rejection(resp, context)


# ---------------------------------------------------------------------------
# Wrong file type — .html
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
def test_upload_html_file(profile, evidence):
    """Upload of a .html file must be rejected (4xx) — XSS vector via download."""
    url = _endpoint_url(profile)
    content = b"<html><body><script>alert(1)</script></body></html>"
    resp = _send_upload(url, filename="payload.html", content=content, content_type="text/html")
    context = "upload payload.html"
    _assert_not_500(resp, context)
    if resp.status_code < 400:
        evidence.capture(resp, "upload_html_accepted_unexpected")
    _assert_rejection(resp, context)


# ---------------------------------------------------------------------------
# Wrong file type — .svg (potential XSS vector)
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
def test_upload_svg_file(profile, evidence):
    """Upload of a .svg file must be rejected (4xx) — SVG can contain embedded scripts."""
    url = _endpoint_url(profile)
    content = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b'<script>alert(document.cookie)</script>'
        b'</svg>'
    )
    resp = _send_upload(url, filename="xss.svg", content=content, content_type="image/svg+xml")
    context = "upload xss.svg"
    _assert_not_500(resp, context)
    if resp.status_code < 400:
        evidence.capture(resp, "upload_svg_accepted_unexpected")
    _assert_rejection(resp, context)


# ---------------------------------------------------------------------------
# Malformed CSV — broken encoding / format
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
def test_upload_malformed_csv(profile, evidence):
    """Upload of the malformed fixture must return 400 or graceful error, never 500."""
    url = _endpoint_url(profile)
    fixture_path = _FIXTURES / "records_malformed.csv"
    if not fixture_path.exists():
        pytest.skip(f"Fixture not found: {fixture_path}")
    content = fixture_path.read_bytes()
    resp = _send_upload(url, filename="records_malformed.csv", content=content)
    context = "upload records_malformed.csv"
    _assert_not_500(resp, context)
    # Malformed input should produce a 400 (validation error), not a 200 (silent accept).
    if resp.status_code == 200:
        evidence.capture(resp, "malformed_csv_accepted_as_valid")
    assert resp.status_code in range(200, 500), (
        f"{context}: returned {resp.status_code}; expected 2xx (graceful) or 4xx (rejection)"
    )


# ---------------------------------------------------------------------------
# Oversized upload — >25 MB
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
def test_upload_oversized_file(profile, evidence):
    """Upload of a file >25 MB must be rejected (413 or 4xx), never 500."""
    url = _endpoint_url(profile)

    # Prefer the pre-generated fixture if it exists.
    oversized_path = _FIXTURES / "records_oversized.csv"
    if oversized_path.exists() and oversized_path.stat().st_size >= 10 * 1024 * 1024:
        content = oversized_path.read_bytes()
    else:
        # Generate a synthetic large payload (valid CSV header + repeated rows).
        # Reuse _minimal_csv() header logic for portability.
        col_headers: list[str] = (
            list(_PROFILE.uploads.column_headers)
            if _PROFILE and _PROFILE.uploads and _PROFILE.uploads.column_headers
            else ["col1", "col2", "col3"]
        )
        header = (",".join(col_headers) + "\n").encode("utf-8")
        row = (",".join(f"val{i}" for i in range(len(col_headers))) + "\n").encode("utf-8")
        chunks = [header]
        total = len(header)
        while total < _SYNTHETIC_LARGE_BYTES:
            chunks.append(row)
            total += len(row)
        content = b"".join(chunks)

    resp = _send_upload(
        url,
        filename="records_oversized.csv",
        content=content,
        content_type="text/csv",
        timeout=60.0,
    )
    context = f"upload oversized ({len(content):,} bytes)"
    _assert_not_500(resp, context)
    if resp.status_code == 200:
        evidence.capture(resp, "oversized_upload_accepted_unexpected")
    # Netlify has a default 6 MB body limit on Functions; expect 413 or 400.
    assert resp.status_code in (400, 413, 422, 431, 503), (
        f"{context}: returned {resp.status_code}; expected 413 or 4xx rejection for oversized upload"
    )


# ---------------------------------------------------------------------------
# Path traversal in multipart filename
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename", [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc/passwd",
    "valid_name_../../etc/shadow",
], ids=lambda f: f.replace("/", "_").replace("\\", "_")[:40])
@pytest.mark.write_probe
def test_upload_path_traversal_filename(filename, profile, evidence):
    """Path traversal in multipart filename must not cause a server error or file write."""
    url = _endpoint_url(profile)
    content = _minimal_csv()
    resp = _send_upload(url, filename=filename, content=content)
    context = f"upload filename={filename!r}"
    _assert_not_500(resp, context)
    # We cannot verify whether the server wrote to an unintended path from the outside.
    # What we can assert is the server did not crash.
    if resp.status_code not in (200, 400, 401, 403, 413, 422):
        evidence.capture(resp, f"path_traversal_status_{resp.status_code}")


# ---------------------------------------------------------------------------
# Double extension filenames
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename,content_type", [
    ("data.csv.html", "text/csv"),
    ("data.csv.exe", "text/csv"),
    ("report.csv.php", "text/csv"),
    ("upload.CSV.HTML", "text/csv"),
], ids=lambda x: x if isinstance(x, str) else "")
@pytest.mark.write_probe
def test_upload_double_extension_filename(filename, content_type, profile, evidence):
    """Double-extension filenames must be rejected or at least not cause a 500."""
    url = _endpoint_url(profile)
    content = _minimal_csv()
    resp = _send_upload(url, filename=filename, content=content, content_type=content_type)
    context = f"upload filename={filename!r}"
    _assert_not_500(resp, context)
    if resp.status_code == 200:
        evidence.capture(resp, f"double_ext_accepted_{filename}")
    # Double extensions should be rejected; document if accepted.
    assert resp.status_code in range(200, 500), (
        f"{context}: returned {resp.status_code}; expected 2xx or 4xx"
    )


# ---------------------------------------------------------------------------
# Null byte in filename
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename", [
    "data.csv\x00.exe",
    "upload\x00.html",
    "file\x00/../etc/passwd",
], ids=lambda f: repr(f)[:30])
@pytest.mark.write_probe
def test_upload_null_byte_in_filename(filename, profile, evidence):
    """Null bytes in multipart filename must not cause a server error or extension confusion."""
    url = _endpoint_url(profile)
    content = _minimal_csv()
    try:
        resp = _send_upload(url, filename=filename, content=content)
        context = f"upload filename with null byte"
        _assert_not_500(resp, context)
        if resp.status_code == 200:
            evidence.capture(resp, "null_byte_filename_accepted")
        assert resp.status_code in range(200, 500), (
            f"{context}: returned {resp.status_code}; expected 2xx or 4xx"
        )
    except (httpx.LocalProtocolError, ValueError):
        # Some HTTP clients refuse null bytes in headers/filenames at the protocol
        # level — this is correct behaviour and the test passes.
        pass


# ---------------------------------------------------------------------------
# Content-type spoofing — send binary content with text/csv header
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
def test_upload_binary_content_with_csv_content_type(profile, evidence):
    """Binary content sent with text/csv content-type must not cause a 500."""
    url = _endpoint_url(profile)
    # Simulate a binary file (e.g. PNG magic bytes) labelled as CSV.
    content = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b"\x00" * 100
    resp = _send_upload(url, filename="not_a_csv.csv", content=content, content_type="text/csv")
    context = "upload binary content with text/csv content-type"
    _assert_not_500(resp, context)
    if resp.status_code not in (200, 400, 401, 403, 415, 422):
        evidence.capture(resp, f"binary_content_csv_mime_status_{resp.status_code}")


# ---------------------------------------------------------------------------
# Valid CSV — baseline (smoke test to confirm endpoint is reachable)
# ---------------------------------------------------------------------------

@pytest.mark.write_probe
def test_upload_valid_csv_baseline(profile, evidence):
    """Upload the valid baseline fixture to confirm the upload endpoint is reachable.

    This test does not assert business-logic correctness — it only verifies the
    endpoint responds without a 500. A 200 or 4xx (e.g. auth requirement) are
    both acceptable.
    """
    url = _endpoint_url(profile)
    fixture_path = _FIXTURES / "records.csv"
    if not fixture_path.exists():
        pytest.skip(f"Fixture not found: {fixture_path}")
    content = fixture_path.read_bytes()
    resp = _send_upload(url, filename="records.csv", content=content)
    context = "upload records.csv (baseline)"
    _assert_not_500(resp, context)
    if resp.status_code not in (200, 400, 401, 403, 422):
        evidence.capture(resp, f"valid_csv_baseline_status_{resp.status_code}")


# ---------------------------------------------------------------------------
# Auth-gating probes (read-only — no valid auth = no server-side state)
# ---------------------------------------------------------------------------

def test_upload_requires_auth(profile, evidence):
    """POST to upload endpoint with NO auth must return 401.

    This proves the endpoint requires authentication without creating any
    server-side state. No valid auth = no file processing occurs.
    """
    url = _endpoint_url(profile)
    # Send a minimal multipart POST without any Authorization header.
    content = _minimal_csv()
    with httpx.Client(timeout=30.0, follow_redirects=False) as client:
        files = {"file": ("test.csv", io.BytesIO(content), "text/csv")}
        resp = client.post(url, files=files)

    evidence.capture(resp, label="upload_requires_auth")
    assert resp.status_code in (401, 403), (
        f"Upload endpoint returned {resp.status_code} without auth; "
        "expected 401 or 403. The endpoint may accept unauthenticated uploads."
    )


def test_upload_rejects_expired_token(profile, evidence):
    """POST to upload endpoint with an invalid/expired JWT must return 401/403.

    Sends a syntactically valid but expired JWT to verify the endpoint
    validates token integrity, not just presence.
    """
    url = _endpoint_url(profile)
    content = _minimal_csv()
    # Syntactically valid JWT with an expired exp claim (epoch 0).
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJmYWtlLXVzZXIiLCJleHAiOjB9."
        "invalid-signature"
    )
    with httpx.Client(timeout=30.0, follow_redirects=False) as client:
        files = {"file": ("test.csv", io.BytesIO(content), "text/csv")}
        resp = client.post(
            url,
            files=files,
            headers={"Authorization": f"Bearer {fake_jwt}"},
        )

    evidence.capture(resp, label="upload_rejects_expired_token")
    assert resp.status_code in (401, 403), (
        f"Upload endpoint returned {resp.status_code} with expired JWT; "
        "expected 401 or 403. Token validation may be insufficient."
    )


# ---------------------------------------------------------------------------
# §P2-C: Decompression bomb / resource exhaustion (ASVS 5.2.3, CWE-409)
# ---------------------------------------------------------------------------

# Target uncompressed size of the decompression bomb (~1 GiB). A repeated
# single-byte run compresses to a few KB of gzip, so the request body stays
# tiny while the server-side expansion is what the probe is testing. The cap
# bounds generation: the gzip stream is produced by streaming this many bytes
# through GzipFile in fixed-size chunks, so the full uncompressed payload is
# never held in the test's memory.
_BOMB_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
_BOMB_CHUNK = 1024 * 1024  # 1 MiB write granularity feeding the gzip stream.


def _make_gzip_bomb(uncompressed_bytes: int = _BOMB_UNCOMPRESSED_BYTES) -> bytes:
    """Return a small gzip stream that decompresses to *uncompressed_bytes*.

    The payload is a single repeated byte ("A") fed to GzipFile one chunk at a
    time, so the highly compressible run yields a few-KB gzip body without the
    test ever materializing the full uncompressed buffer. The SERVER is what
    would expand it on decompression; the client side stays bounded.
    """
    buf = io.BytesIO()
    chunk = b"A" * _BOMB_CHUNK
    remaining = uncompressed_bytes
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        while remaining > 0:
            n = min(_BOMB_CHUNK, remaining)
            gz.write(chunk if n == _BOMB_CHUNK else chunk[:n])
            remaining -= n
    return buf.getvalue()


def _zip_bomb_status_outcome(status: int) -> str:
    """Classify the upload endpoint's response to a decompression bomb (pure).

    Black-box, a CSV-import endpoint's status code does not uniquely reveal how it
    handled the compressed payload, so only the unambiguous signals are acted on:
      - "exhausted": 500. The handler crashed, the signature of an unbounded
        expansion that ran out of memory or CPU. This is the finding.
      - "capped": 413. An explicit payload-too-large on a tiny compressed body is
        the decompressed-size cap doing its job. This is the pass.
      - "auth_gate": 401 or 403. The body handler was never reached, so the size
        control is not observable without credentials.
      - "inconclusive": anything else. A 2xx may mean the endpoint stored the
        compressed bytes opaquely (object storage) without decompressing, and a
        non-413 4xx may be a CSV-format rejection rather than a size cap, so
        neither is a sound verdict.
    """
    if status == 500:
        return "exhausted"
    if status == 413:
        return "capped"
    if status in (401, 403):
        return "auth_gate"
    return "inconclusive"


@pytest.mark.write_probe
@pytest.mark.asvs_extended
@pytest.mark.asvs("5.2.3")
@pytest.mark.cwe("409")
def test_upload_zip_bomb_rejected(profile, evidence):
    """Upload a tiny gzip that decompresses to ~1 GiB; the server must not crash.

    Vector: a multipart upload of ``records.csv.gz`` (a gzip whose declared
    content decompresses huge) to the profile's upload endpoint. This mirrors
    how the CSV-import surface is exercised elsewhere in this module rather than
    relying on a ``Content-Encoding: gzip`` transfer header that an intermediary
    or the framework might transparently strip or re-handle, which would test
    the proxy and not the application.

    Outcome is decided by :func:`_zip_bomb_status_outcome` plus the transport
    result, acting only on unambiguous signals. A 500 or a post-connect hang
    (read timeout / dropped connection on a few-KB body) is the resource-
    exhaustion finding (ASVS 5.2.3, CWE-409). A 413 is the decompressed-size cap
    doing its job (pass). A 401/403 is an auth gate, so the size control is not
    observable without credentials (skip). Any other status is inconclusive: a
    2xx may be opaque object-storage that never decompressed, and a non-413 4xx
    may be a CSV-format rejection rather than a size cap (skip). A connect-phase
    failure means the bomb was never delivered, so the probe skips rather than
    flagging an unreachable target. The request carries a short timeout so a
    server that tries to expand the payload synchronously surfaces as a timeout
    rather than blocking the suite.
    """
    url = _endpoint_url(profile)
    bomb = _make_gzip_bomb()
    context = (
        f"upload gzip bomb ({len(bomb):,} compressed bytes -> "
        f"~{_BOMB_UNCOMPRESSED_BYTES // (1024 * 1024)} MiB uncompressed)"
    )

    try:
        resp = _send_upload(
            url,
            filename="records.csv.gz",
            content=bomb,
            content_type="application/gzip",
            timeout=20.0,
        )
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        # Connect-phase failure: the target was unreachable before the body was
        # sent, so the bomb was never delivered and decompression handling is
        # not observable. Skip like every other live probe does on a connect
        # failure (do not flag an unreachable/firewalled/misconfigured target).
        pytest.skip(
            f"{context}: target unreachable at connect time "
            f"({type(exc).__name__}: {exc}); the bomb was never delivered, so "
            "the server's decompression handling is not observable."
        )
    except httpx.TransportError as exc:
        # Post-connect transport failure (read timeout, protocol error, dropped
        # connection) on a few-KB request body: the server began expanding the
        # bomb (or fell over) after accepting the connection. Capture a
        # sanitized synthetic record (no request/response body to persist) and
        # fail as the exhaustion finding.
        evidence.capture(
            FakeResponse(
                0, url,
                f"[body omitted] decompression bomb caused "
                f"{type(exc).__name__} after connect (no bounded response). "
                f"{context}.",
                "POST",
            ),
            label="zip_bomb_no_bounded_response",
        )
        pytest.fail(
            f"{context}: the connection was established but the request hung or "
            f"dropped ({type(exc).__name__}). A few-KB compressed body should "
            "never exhaust the server; enforce a decompressed-size cap and "
            "reject oversized expansion (ASVS 5.2.3, CWE-409)."
        )

    outcome = _zip_bomb_status_outcome(resp.status_code)

    if outcome == "capped":
        return  # 413: the decompressed-size cap rejected the bomb cleanly.

    if outcome == "auth_gate":
        pytest.skip(
            f"{context}: upload endpoint returned {resp.status_code} (auth "
            "gate) before the decompressed-size control is observable. Provide "
            "credentials (run with an authenticated profile) to reach the body "
            "handler and exercise the 5.2.3 size cap."
        )

    if outcome == "inconclusive":
        pytest.skip(
            f"{context}: returned {resp.status_code}, which does not uniquely "
            "indicate decompression handling. A 2xx may mean the endpoint "
            "stored the compressed bytes opaquely (object storage) without "
            "decompressing, and a non-413 4xx may be a CSV-format rejection "
            "rather than a size cap, so the control is not observable from this "
            "response. Confirm server-side whether the upload is decompressed "
            "and whether a decompressed-size cap is enforced (ASVS 5.2.3)."
        )

    # outcome == "exhausted": a 500 means the handler crashed expanding the bomb
    # instead of capping it. Capture sanitized evidence (no echoed bomb bytes)
    # and fail.
    evidence.capture(
        FakeResponse(
            resp.status_code, url,
            f"[body omitted] decompression bomb returned "
            f"{resp.status_code} (handler crashed expanding the payload). "
            f"{context}.",
            "POST",
        ),
        label="zip_bomb_exhausted_handler",
    )
    pytest.fail(
        f"{context}: returned 500 (the handler crashed expanding the bomb "
        "instead of enforcing a decompressed-size cap and rejecting it). A "
        "few-KB compressed body must not be able to exhaust the server's "
        "memory or CPU (ASVS 5.2.3, CWE-409)."
    )


# ---------------------------------------------------------------------------
# §P2-C: Content-Disposition on served uploads (ASVS 5.4.1, CWE-434)
# ---------------------------------------------------------------------------

# Content types that, if rendered inline by the browser, can execute as the
# serving origin (stored XSS on download). For these a served user upload MUST
# carry Content-Disposition: attachment so the browser downloads rather than
# renders it. Lowercased; compared by prefix so a charset parameter
# (e.g. "text/html; charset=utf-8") still matches.
_RENDERABLE_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "application/xml",
    "text/xml",
)


def _content_disposition_is_safe(
    content_disposition: str | None, content_type: str | None
) -> bool:
    """Return True when the served upload's disposition forces a download.

    Pure classifier (offline-unit-tested). It answers ONLY the disposition
    question: a ``Content-Disposition`` whose first directive is ``attachment``
    makes the browser download the body instead of rendering it inline in the
    serving origin's context. A missing header, an ``inline`` disposition, or
    any other directive (e.g. ``form-data``) is unsafe.

    The nosniff requirement is a separate axis checked by the caller against the
    response's ``X-Content-Type-Options`` header; the probe ANDs that with this
    helper. ``content_type`` is accepted for a stable signature (the caller also
    classifies renderability via :func:`_is_renderable_content_type`) but does
    not change the disposition verdict, so the helper stays unit-testable in
    isolation.
    """
    disp = (content_disposition or "").strip().lower()
    if not disp:
        return False
    # The first directive is the disposition type (attachment / inline / form-data).
    disp_type = disp.split(";", 1)[0].strip()
    return disp_type == "attachment"


def _is_renderable_content_type(content_type: str | None) -> bool:
    """Return True when *content_type* can render as active content in a browser."""
    ct = (content_type or "").strip().lower()
    return any(ct.startswith(rt) for rt in _RENDERABLE_CONTENT_TYPES)


def _served_upload_url(profile) -> str | None:
    """Return a served-file URL to GET, or None when none is derivable.

    Read defensively from the profile: prefer an explicit
    ``uploads.served_sample_url`` if the active profile declares one (the
    _AttrDict returns None for an absent key, so this never raises and no new
    REQUIRED schema is introduced). Returns None when the field is unset, which
    is the common case for the shipped example profiles; the caller then skips
    with a provider-specific reason. Dispatching on ``stack.storage`` is left to
    the caller so the skip message can name the active provider.
    """
    uploads = getattr(profile, "uploads", None)
    served = getattr(uploads, "served_sample_url", None) if uploads else None
    if isinstance(served, str) and served.strip():
        return served.strip()
    return None


@pytest.mark.asvs_extended
@pytest.mark.asvs("5.4.1")
@pytest.mark.cwe("434")
def test_served_upload_sets_content_disposition(profile, evidence):
    """A served user upload must download (attachment + nosniff), not render inline.

    Black-box limitation: confirming serve-time hardening needs a KNOWN served
    object URL (a stored file the harness can GET). StackBadger does not upload
    a stored sample as part of this read-only probe, so the URL must come from
    the profile (``uploads.served_sample_url``). When no served URL is derivable
    for the active ``stack.storage`` provider the probe skips with a reason
    naming the provider and the field that would enable it, rather than passing
    without testing.

    When a URL is derivable, GET it and require the response to be served
    defensively: ``Content-Disposition: attachment`` (not inline/absent) AND
    ``X-Content-Type-Options: nosniff`` for a renderable type, so a stored
    HTML/SVG is downloaded rather than executed in the serving origin's context
    (stored XSS on serve; ASVS 5.4.1, CWE-434).
    """
    storage = (profile.stack and profile.stack.storage) or "(unset)"
    url = _served_upload_url(profile)
    if not url:
        pytest.skip(
            f"No served-file URL derivable for stack.storage '{storage}'. "
            "Serve-time Content-Disposition (ASVS 5.4.1) needs a known stored "
            "object to GET; declare uploads.served_sample_url (a public/served "
            "URL of a user-uploaded file) in the profile to enable this probe."
        )

    try:
        resp = send_request("GET", url, timeout=15.0, follow_redirects=True)
    except httpx.TransportError as exc:
        pytest.skip(
            f"Served upload {url} unreachable for stack.storage '{storage}' "
            f"({type(exc).__name__}: {exc}); serve-time hardening cannot be "
            "checked."
        )

    if resp.status_code // 100 != 2:
        pytest.skip(
            f"Served upload {url} returned {resp.status_code}, not 2xx, so the "
            "stored object is not retrievable; point uploads.served_sample_url "
            "at a currently-served file to exercise ASVS 5.4.1."
        )

    content_disposition = resp.headers.get("Content-Disposition")
    content_type = resp.headers.get("Content-Type")
    nosniff = (resp.headers.get("X-Content-Type-Options", "").strip().lower() == "nosniff")
    disposition_safe = _content_disposition_is_safe(content_disposition, content_type)
    renderable = _is_renderable_content_type(content_type)

    # Defensive serving = attachment disposition AND (nosniff when renderable).
    served_safely = disposition_safe and (nosniff or not renderable)

    if not served_safely:
        # Header-only synthetic evidence: a served upload body could be
        # attacker-controlled stored content, so do not persist it; capture the
        # headers that decide the verdict via a sanitized FakeResponse.
        evidence.capture(
            FakeResponse(
                resp.status_code, url,
                f"[body omitted] served upload headers: "
                f"Content-Disposition={content_disposition!r}, "
                f"Content-Type={content_type!r}, nosniff={nosniff}.",
                "GET",
            ),
            label="served_upload_not_attachment",
        )

    assert served_safely, (
        f"Served upload {url} is not delivered defensively: "
        f"Content-Disposition={content_disposition!r} (need 'attachment'), "
        f"Content-Type={content_type!r}, X-Content-Type-Options nosniff="
        f"{nosniff}. A stored HTML/SVG served inline executes in the serving "
        "origin's context (stored XSS on download); serve user uploads with "
        "Content-Disposition: attachment and X-Content-Type-Options: nosniff "
        "(ASVS 5.4.1, CWE-434)."
    )


# ---------------------------------------------------------------------------
# Offline unit tests: pure helpers (no profile, no network)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status,expected", [
    (500, "exhausted"),
    (413, "capped"),
    (401, "auth_gate"),
    (403, "auth_gate"),
    (200, "inconclusive"),
    (201, "inconclusive"),
    (204, "inconclusive"),
    (400, "inconclusive"),
    (422, "inconclusive"),
    (431, "inconclusive"),
    (503, "inconclusive"),
    (429, "inconclusive"),
    (404, "inconclusive"),
])
def test_zip_bomb_status_outcome(status, expected):
    assert _zip_bomb_status_outcome(status) == expected


def test_make_gzip_bomb_is_small_and_expands_huge():
    """The generated gzip stays tiny but decompresses to the declared target.

    Uses a small target so the assertion runs fast and bounded; the production
    constant is ~1 GiB. Confirms (a) the compressed body is far smaller than the
    uncompressed payload, and (b) decompressing yields exactly the target size,
    so the bomb really does expand.
    """
    target = 8 * 1024 * 1024  # 8 MiB uncompressed.
    bomb = _make_gzip_bomb(target)
    assert len(bomb) < target // 100, (
        "gzip bomb did not compress: a repeated-byte run should be far smaller "
        f"than its uncompressed size (got {len(bomb)} bytes for {target})"
    )
    assert len(gzip.decompress(bomb)) == target


@pytest.mark.parametrize(
    "content_disposition,content_type,expected",
    [
        # Attachment is safe regardless of type.
        ("attachment", "text/html", True),
        ("attachment; filename=\"x.html\"", "text/html", True),
        ("ATTACHMENT", "image/svg+xml", True),  # case-insensitive directive.
        ("  attachment ; filename=a.svg ", "image/svg+xml", True),  # whitespace.
        # content_type-independence: the same disposition yields the same verdict
        # for a renderable (text/html) and an inert (text/csv) type. The paired
        # rows below, plus the explicit invariant assertion in the test body,
        # make the documented independence verifiable.
        ("attachment", "text/csv", True),   # renderable counterpart: ("attachment", "text/html").
        ("inline", "text/csv", False),      # renderable counterpart: ("inline", "text/html").
        # Inline renders in-origin -> unsafe.
        ("inline", "text/html", False),
        ("inline; filename=\"x.html\"", "image/svg+xml", False),
        # Missing disposition -> unsafe (browser may render).
        (None, "text/html", False),
        ("", "text/html", False),
        ("   ", "image/svg+xml", False),
        # A non-attachment directive (form-data) is not a download.
        ("form-data; name=file", "text/html", False),
    ],
)
def test_content_disposition_is_safe(content_disposition, content_type, expected):
    assert (
        _content_disposition_is_safe(content_disposition, content_type) is expected
    )


@pytest.mark.parametrize("disposition", ["attachment", "inline", None, "form-data"])
def test_content_disposition_is_content_type_independent(disposition):
    """The disposition verdict must not depend on the content type.

    Holds the disposition fixed and asserts an identical verdict for a renderable
    (text/html) and an inert (text/csv) content type, making the documented
    content_type-independence of :func:`_content_disposition_is_safe` explicit.
    """
    renderable = _content_disposition_is_safe(disposition, "text/html")
    inert = _content_disposition_is_safe(disposition, "text/csv")
    assert renderable is inert


@pytest.mark.parametrize(
    "content_type,expected",
    [
        ("text/html", True),
        ("text/html; charset=utf-8", True),
        ("application/xhtml+xml", True),
        ("image/svg+xml", True),
        ("application/xml", True),
        ("text/xml", True),
        ("IMAGE/SVG+XML", True),  # case-insensitive.
        # Non-renderable / inert content types.
        ("text/csv", False),
        ("application/octet-stream", False),
        ("image/png", False),
        ("application/json", False),
        (None, False),
        ("", False),
    ],
)
def test_is_renderable_content_type(content_type, expected):
    assert _is_renderable_content_type(content_type) is expected


@pytest.mark.parametrize(
    "served,expected",
    [
        # A non-empty string is returned trimmed.
        ("https://cdn.example.com/uploads/x.csv", "https://cdn.example.com/uploads/x.csv"),
        ("  https://cdn.example.com/uploads/x.csv  ", "https://cdn.example.com/uploads/x.csv"),
        # Absent / empty / whitespace-only -> None.
        (None, None),
        ("", None),
        ("   ", None),
        ("\t\n", None),
    ],
)
def test_served_upload_url(served, expected):
    """``_served_upload_url`` reads uploads.served_sample_url defensively (pure).

    Uses a minimal duck-typed fake profile (no profile fixture, no network) so
    the helper is exercised in isolation.
    """
    fake = types.SimpleNamespace(
        uploads=types.SimpleNamespace(served_sample_url=served)
    )
    assert _served_upload_url(fake) == expected


def test_served_upload_url_handles_missing_uploads():
    """A profile whose ``uploads`` is None returns None (no AttributeError)."""
    fake = types.SimpleNamespace(uploads=None)
    assert _served_upload_url(fake) is None
