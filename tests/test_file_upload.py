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
"""

from __future__ import annotations

import io
import os
import subprocess
import sys as _sys
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
