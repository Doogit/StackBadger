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
