#!/usr/bin/env python3
"""Generate a ~25MB CSV fixture for file-size limit testing."""

import os
import pathlib

TARGET_BYTES = 25 * 1024 * 1024  # 25 MB
OUTPUT_PATH = pathlib.Path(__file__).parent / "records_oversized.csv"

HEADER = (
    "record_id,record_date,line_number,item_ordinal,item_code,"
    "line_value_amount,line_fee_amount,record_type,lifecycle_status,"
    "lifecycle_date,origin_code\n"
)

# Two rows per synthetic record (base line + surcharge line)
ROW_TEMPLATE_A = (
    "{record},03/01/2025,1,1,ITEM-1001,12500.00,0.00,01,"
    "open,04/15/2025,XX\n"
)
ROW_TEMPLATE_B = (
    "{record},03/01/2025,1,2,ITEM-2001,0.00,3125.00,01,"
    "open,04/15/2025,XX\n"
)


def make_record_id(n: int) -> str:
    """Return a synthetic 11-char record id: TST + 7-digit sequence + check digit."""
    seq = f"{n:07d}"
    # Simple check digit: sum of numeric positions mod 10
    digits = [int(c) if c.isdigit() else ord(c) - ord('A') + 1 for c in f"TST{seq}"]
    check = sum(digits) % 10
    return f"TST{seq}{check}"


def main() -> None:
    written = 0
    row_count = 0

    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as fh:
        fh.write(HEADER)
        written += len(HEADER.encode("utf-8"))

        n = 1
        while written < TARGET_BYTES:
            record = make_record_id(n)
            row_a = ROW_TEMPLATE_A.format(record=record)
            row_b = ROW_TEMPLATE_B.format(record=record)
            fh.write(row_a)
            fh.write(row_b)
            written += len(row_a.encode("utf-8")) + len(row_b.encode("utf-8"))
            row_count += 2
            n += 1

    actual = OUTPUT_PATH.stat().st_size
    print(f"Wrote {row_count} data rows to {OUTPUT_PATH}")
    print(f"File size: {actual:,} bytes ({actual / (1024*1024):.2f} MB)")


if __name__ == "__main__":
    main()
