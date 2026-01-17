from __future__ import annotations

import csv
import argparse
from typing import List


def read_summary(path: str) -> List[dict]:
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        return list(r)


def main():
    ap = argparse.ArgumentParser(description="Merge summary CSVs for final table.")
    ap.add_argument(
        "--in",
        dest="inputs",
        nargs="+",
        required=True,
        help="Input summary CSV files (e.g., summary_gq_sec128.csv ...)",
    )
    ap.add_argument(
        "--out",
        dest="out",
        required=True,
        help="Output merged CSV file",
    )
    args = ap.parse_args()

    rows = []
    for p in args.inputs:
        rows.extend(read_summary(p))

    # Sort for readability: scheme -> op
    rows.sort(key=lambda x: (x["scheme"], x["op"]))

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"Wrote merged summary to {args.out}")


if __name__ == "__main__":
    main()
