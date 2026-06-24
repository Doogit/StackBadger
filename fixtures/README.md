# StackBadger/fixtures

Test fixture files for StackBadger, the portable API security harness. Each fixture targets a specific
failure mode in the file-upload and input-sanitisation paths. The CSVs use generic, stack-neutral
column names so they exercise the upload parser without naming any application's domain.

## Files

### records.csv
Minimal well-formed CSV with 5 synthetic data rows across 3 record ids.
Used as the baseline "golden path" input for upload tests. All record ids pass the
11-char format (`TST` prefix + 7-digit sequence + numeric check digit).

### records_injection.csv
Formula-injection payloads placed in the `record_id` and `item_code`
columns. Tests that the parser rejects or sanitises CSV formula injection before the data
reaches any spreadsheet export or downstream rendering context. Payloads used:

| Payload | Column |
|---------|--------|
| `=cmd\|' /C calc'!A0` | record_id, item_code |
| `+cmd\|' /C calc'!A0` | record_id |
| `-cmd\|' /C calc'!A0` | record_id |
| `@SUM(1+1)*cmd\|' /C calc'!A0` | item_code |
| `=HYPERLINK("http://evil.com")` | item_code |

### records_malformed.csv
Binary file with multiple deliberate defects in one payload:
- UTF-16 LE BOM (`\xff\xfe`) prepended
- Truncated header row (missing the trailing `origin_code` column)
- Rows with trailing commas
- Rows with extra (unexpected) columns
- An empty row in the middle of data

Tests that the parser surfaces a clear error rather than silently accepting malformed input.

### xxe_classic.xml
Classic XXE payload: a `<!DOCTYPE>` with an external general entity
(`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) referenced from an element value.
Sent to endpoints that accept XML. A safe parser must NOT resolve the entity —
the test asserts no `/etc/passwd`-style file content is reflected in the
response. Used by `test_xxe_external_entity` in `tests/test_injection.py`
(ASVS V1.5.1, CWE-611).

### xxe_oob.xml
Out-of-band / parameter-entity XXE variant. Declares parameter entities that, on
a vulnerable parser, would fetch a remote DTD and exfiltrate a local file over an
outbound channel. The `SYSTEM` host is the reserved-documentation domain
`oob.example.com`, so the static fixture initiates no live fetch when stored or
read offline. The test asserts the entity is not resolved and no file content is
reflected. Used by `test_xxe_external_entity` (ASVS V1.5.1, CWE-611).

### ssrf_targets.txt
Reviewable, line-delimited list of SSRF target URLs — cloud instance-metadata
(`169.254.169.254`, `metadata.google.internal`), loopback, RFC 1918 private
ranges, the `file://` scheme, and alternate-encoding allowlist bypasses. The
probe submits each URL to a profile-derived endpoint/RPC that accepts a URL and
asserts the server does not dereference it. The harness only SENDS these strings
as request data; it never connects to them itself. Comment (`#`) and blank lines
are skipped by the loader. Used by `test_ssrf_internal_targets` (ASVS V1.3.6 /
V15.3.2, CWE-918) — which additionally stays gated behind the `SSRF_PROBE_ACK=1`
acknowledgment until SECURITY.md gains SSRF / internal-network probing language.

### generate_oversized.py
Python script (not a static fixture) that generates `records_oversized.csv` at ~25 MB.
Run once locally before size-limit tests:

```
python fixtures/generate_oversized.py
```

The generated file is gitignored (too large to commit). The script writes the generic
headers and synthetic row pairs until the target byte count is reached, then prints the
actual file size.

### records_oversized.csv (generated, not committed)
Output of `generate_oversized.py`. Tests that the upload endpoint enforces its documented
file-size limit and returns an appropriate error before attempting to parse.

## Usage

Tests in `tests/` reference these fixtures by relative path from the
repo root, e.g.:

```python
FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures"
valid_csv   = FIXTURES / "records.csv"
inject_csv  = FIXTURES / "records_injection.csv"
malformed   = FIXTURES / "records_malformed.csv"
```
