#!/usr/bin/env python3
"""Build SweepR's embedded IEEE OUI vendor database.

Reads the three IEEE public registries (MA-L, MA-M, MA-S) and emits one compact,
sorted, de-duplicated TSV that `src-tauri/src/enricher.rs` embeds with `include_str!`
and loads into a `HashMap` for O(1) MAC-to-vendor lookup.

Each output line is `<ASSIGNMENT-HEX>\t<VENDOR>`:

  * MA-L assignments are 6 hex digits (OUI / 24-bit prefix),
  * MA-M assignments are 7 hex digits (28-bit prefix),
  * MA-S assignments are 9 hex digits (36-bit prefix).

The Rust side looks a MAC up most-specific-first (9, then 7, then 6 hex digits),
so a MA-M / MA-S sub-assignment wins over the MA-L block it sits inside.

Usage:
    python3 -I scripts/build_oui_db.py <csv-dir> <out.tsv>

<csv-dir> must contain oui.csv (MA-L), mam.csv (MA-M) and oui36.csv (MA-S); only
oui.csv is required, the others are folded in when present. Download them from:
    https://standards-oui.ieee.org/oui/oui.csv
    https://standards-oui.ieee.org/oui28/mam.csv
    https://standards-oui.ieee.org/oui36/oui36.csv
"""

import csv
import os
import sys

# Keep the embedded file small and the vendor column terminal-safe.
MAX_VENDOR_LEN = 48

# Unicode bidi / zero-width format characters (mirrors models::sanitize_text).
_BIDI = set(
    [chr(c) for c in range(0x200B, 0x2010)]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
    + [chr(0xFEFF)]
)


def clean(name: str) -> str:
    """Collapse whitespace, drop control/bidi characters, trim and cap length."""
    out = []
    for ch in name:
        if ch in ("\t", "\n", "\r", "\v", "\f"):
            out.append(" ")
        elif ch in _BIDI or (ord(ch) < 0x20) or ord(ch) == 0x7F or (0x80 <= ord(ch) <= 0x9F):
            continue
        else:
            out.append(ch)
    text = " ".join("".join(out).split())
    if len(text) > MAX_VENDOR_LEN:
        text = text[:MAX_VENDOR_LEN].rstrip()
    return text


def load(path: str, hex_len: int, into: dict) -> int:
    added = 0
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if header is None:
            return 0
        for row in reader:
            if len(row) < 3:
                continue
            assignment = row[1].strip().upper()
            vendor = clean(row[2])
            # Keep only well-formed hex assignments of the expected width.
            if len(assignment) != hex_len or not all(c in "0123456789ABCDEF" for c in assignment):
                continue
            if not vendor:
                continue
            # First registry wins for a given key; registries do not overlap by key.
            if assignment not in into:
                into[assignment] = vendor
                added += 1
    return added


def main(argv) -> int:
    if len(argv) != 3:
        sys.stderr.write(
            "usage: python3 -I scripts/build_oui_db.py <csv-dir> <out.tsv>\n"
        )
        return 2
    csv_dir, out_path = argv[1], argv[2]
    entries: dict = {}

    ma_l = os.path.join(csv_dir, "oui.csv")
    if not os.path.isfile(ma_l):
        sys.stderr.write(f"error: required MA-L registry not found: {ma_l}\n")
        return 1
    n_l = load(ma_l, 6, entries)

    n_m = 0
    mam = os.path.join(csv_dir, "mam.csv")
    if os.path.isfile(mam):
        n_m = load(mam, 7, entries)

    n_s = 0
    ma_s = os.path.join(csv_dir, "oui36.csv")
    if os.path.isfile(ma_s):
        n_s = load(ma_s, 9, entries)

    # Sorted by key so the Rust side can rely on a stable file and humans can diff it.
    lines = [f"{k}\t{v}\n" for k, v in sorted(entries.items())]
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)
    os.replace(tmp, out_path)

    size = os.path.getsize(out_path)
    sys.stderr.write(
        f"wrote {len(lines)} entries "
        f"(MA-L {n_l}, MA-M {n_m}, MA-S {n_s}) "
        f"to {out_path} ({size} bytes)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
