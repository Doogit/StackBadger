"""Byte-level integrity guard for fixtures/records_malformed.csv.

This fixture deliberately embeds malformed-CSV defects so that parser and
ingestion code can be exercised against real-world garbage. If a future
regeneration of the fixture silently drops one of these defects, the affected
test below fails loudly and names exactly which defect went missing.

OFFLINE and dependency-free: no profile fixture, no network, no live target.
Reads only raw bytes from disk via pathlib.
"""

import pathlib

FIXTURE_PATH = (
    pathlib.Path(__file__).parent.parent / "fixtures" / "records_malformed.csv"
)


def _read_bytes() -> bytes:
    assert FIXTURE_PATH.exists(), f"fixture missing: {FIXTURE_PATH}"
    return FIXTURE_PATH.read_bytes()


def _decoded_lines(content: bytes) -> list[str]:
    """Strip the 2-byte UTF-16 LE BOM and decode the ASCII body, split on \\n.

    The body after the BOM is ASCII; latin-1 decodes any byte without error.
    """
    body = content[2:].decode("latin-1")
    return body.split("\n")


def test_defect_1_utf16_le_bom():
    """Defect 1: file begins with a UTF-16 LE byte-order mark (\\xff\\xfe)."""
    content = _read_bytes()
    assert content[:2] == b"\xff\xfe", (
        "expected UTF-16 LE BOM (b'\\xff\\xfe') at start of fixture; "
        f"got {content[:2]!r} -- BOM defect was dropped"
    )


def test_defect_2_blank_mid_data_row():
    """Defect 2: a blank row sits in the middle of the data (b'\\n\\n')."""
    content = _read_bytes()
    assert b"\n\n" in content, (
        "expected a blank mid-data row (b'\\n\\n') in fixture; "
        "blank-row defect was dropped"
    )

    # Cross-check at the decoded-line level: at least one empty line exists.
    lines = _decoded_lines(content)
    assert any(line == "" for line in lines), (
        "expected at least one empty line after decode/split; "
        "blank-row defect was dropped"
    )


def test_defect_3_trailing_comma_row():
    """Defect 3: a data row carries a *pure* trailing comma (not an extra-column row).

    Isolated from defect 4: the extra-column rows (``...,XX,EXTRA,``) also end in
    a comma, so a bare ``endswith(',')`` check would still pass even if the
    dedicated trailing-comma row were dropped. The trailing-comma defect row is
    the one that holds exactly the header's field set plus a single trailing
    empty field (``header_count + 1`` fields, last one empty) — assert that shape
    specifically so dropping it fails this test independent of defects 4/5.
    """
    content = _read_bytes()
    lines = _decoded_lines(content)
    header, *rest = lines
    header_count = len(header.split(","))
    data_rows = [line for line in rest if line != ""]

    def is_pure_trailing_comma(row: str) -> bool:
        fields = row.split(",")
        return row.endswith(",") and len(fields) == header_count + 1 and fields[-1] == ""

    assert any(is_pure_trailing_comma(row) for row in data_rows), (
        f"expected a data row with exactly {header_count + 1} fields ending in a "
        "trailing empty field (the dedicated trailing-comma defect, distinct from "
        "the wider extra-column rows); trailing-comma defect was dropped"
    )


def test_defect_4_extra_columns_vs_header():
    """Defect 4: at least one data row has MORE fields than the header.

    Header lists 10 comma-separated columns. This also encodes the truncated
    header / missing trailing origin_code defect: data rows out-widen it.
    """
    content = _read_bytes()
    lines = _decoded_lines(content)
    header, *rest = lines

    header_count = len(header.split(","))
    data_rows = [line for line in rest if line != ""]
    assert data_rows, "expected at least one non-empty data row in fixture"
    max_data_count = max(len(row.split(",")) for row in data_rows)

    assert header_count == 10, (
        f"expected header to list 10 columns; got {header_count} -- "
        "header shape changed; review fixture defects"
    )
    assert header_count < max_data_count, (
        f"expected at least one data row wider than the {header_count}-column "
        f"header, but widest data row has {max_data_count} fields; "
        "extra-columns defect was dropped"
    )


def test_defect_5_extra_column_marker_present():
    """Defect 5: the explicit ``EXTRA_COLUMN`` marker token is present.

    Pinned to the exact committed token (not an ``EXTRA`` substring OR). The
    README and fixture commit to ``EXTRA_COLUMN`` as the deliberate marker; an
    OR over the shorter ``EXTRA`` substring would be satisfied by the
    ``XX,EXTRA,`` row alone, so it could not detect the marker row being
    regenerated away while a different extra-column row survived.
    """
    content = _read_bytes()
    assert b"EXTRA_COLUMN" in content, (
        "expected the explicit extra-column marker b'EXTRA_COLUMN' in fixture; "
        "extra-column marker defect was dropped"
    )
