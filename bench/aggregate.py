from __future__ import annotations

import argparse
import csv
import glob
import math
import os
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class Row:
    scheme: str
    bits: int
    lam: int
    op: str
    warmup: int
    rep: int
    elapsed_ns: int
    icert_len_bytes: int
    pk_len_bytes: int
    sk_len_bytes: int


def _read_rows(paths: List[str]) -> List[Row]:
    rows: List[Row] = []
    for p in paths:
        with open(p, "r", newline="") as f:
            r = csv.DictReader(f)
            required = {
                "scheme",
                "bits",
                "lam",
                "op",
                "warmup",
                "rep",
                "elapsed_ns",
                "icert_len_bytes",
                "pk_len_bytes",
                "sk_len_bytes",
            }
            if not required.issubset(set(r.fieldnames or [])):
                missing = required - set(r.fieldnames or [])
                raise ValueError(f"{p}: missing columns {sorted(missing)}")

            for d in r:
                rows.append(
                    Row(
                        scheme=str(d["scheme"]),
                        bits=int(d["bits"]),
                        lam=int(d["lam"]),
                        op=str(d["op"]),
                        warmup=int(d["warmup"]),
                        rep=int(d["rep"]),
                        elapsed_ns=int(d["elapsed_ns"]),
                        icert_len_bytes=int(d["icert_len_bytes"]),
                        pk_len_bytes=int(d["pk_len_bytes"]),
                        sk_len_bytes=int(d["sk_len_bytes"]),
                    )
                )
    return rows


def _percentile(sorted_vals: List[int], q: float) -> int:
    """
    Nearest-rank percentile (q in [0,1]).
    For paper tables this is stable, simple, and reviewer-friendly.
    """
    if not sorted_vals:
        raise ValueError("empty values")
    if q <= 0:
        return sorted_vals[0]
    if q >= 1:
        return sorted_vals[-1]
    k = math.ceil(q * len(sorted_vals)) - 1
    k = max(0, min(k, len(sorted_vals) - 1))
    return sorted_vals[k]


def _summarize(vals: List[int]) -> Dict[str, int]:
    vals_sorted = sorted(vals)
    n = len(vals_sorted)
    mean = int(round(sum(vals_sorted) / n))
    median = (
        vals_sorted[n // 2]
        if (n % 2 == 1)
        else int(round((vals_sorted[n // 2 - 1] + vals_sorted[n // 2]) / 2))
    )
    p95 = _percentile(vals_sorted, 0.95)
    p99 = _percentile(vals_sorted, 0.99)
    vmin = vals_sorted[0]
    vmax = vals_sorted[-1]
    return {
        "n": n,
        "mean_ns": mean,
        "median_ns": median,
        "p95_ns": p95,
        "p99_ns": p99,
        "min_ns": vmin,
        "max_ns": vmax,
    }


def _stable_len(vals: List[int]) -> int:
    """
    Choose a stable representative length from observed values.
    - If there are non-zero values (typical for iCert-related ops), use min(nonzero).
    - Else (e.g., Setup rows where iCert_len=0), return 0.
    """
    nonzero = [v for v in vals if v > 0]
    if nonzero:
        return min(nonzero)
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Aggregate raw benchmark CSVs into paper-ready summary.")
    ap.add_argument(
        "--in",
        dest="inputs",
        nargs="*",
        default=None,
        help="Input CSV files. If omitted, uses --glob.",
    )
    ap.add_argument(
        "--glob",
        dest="globpat",
        default="bench/outputs/*.csv",
        help="Glob pattern for input CSVs (default: bench/outputs/*.csv).",
    )
    ap.add_argument(
        "--out",
        dest="out",
        default="bench/outputs/summary.csv",
        help="Output summary CSV path.",
    )
    ap.add_argument(
        "--include-warmup",
        action="store_true",
        help="Include warmup rows (default: excluded).",
    )
    args = ap.parse_args()

    paths = args.inputs if args.inputs else sorted(glob.glob(args.globpat))
    if not paths:
        raise SystemExit(f"No input CSVs found (inputs={args.inputs}, glob={args.globpat}).")

    rows = _read_rows(paths)
    if not args.include_warmup:
        rows = [x for x in rows if x.warmup == 0]

    # Group by (scheme, bits, lam, op)
    groups: Dict[Tuple[str, int, int, str], List[Row]] = {}
    for x in rows:
        key = (x.scheme, x.bits, x.lam, x.op)
        groups.setdefault(key, []).append(x)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "scheme",
                "bits",
                "lam",
                "op",
                "n",
                "mean_ns",
                "median_ns",
                "p95_ns",
                "p99_ns",
                "min_ns",
                "max_ns",
                "icert_len_bytes",
                "pk_len_bytes",
                "sk_len_bytes",
            ],
        )
        w.writeheader()

        for (scheme, bits, lam, op), rs in sorted(groups.items()):
            vals = [r.elapsed_ns for r in rs]
            stats = _summarize(vals)

            icert_len = _stable_len([r.icert_len_bytes for r in rs])
            pk_len = _stable_len([r.pk_len_bytes for r in rs])
            sk_len = _stable_len([r.sk_len_bytes for r in rs])

            w.writerow(
                {
                    "scheme": scheme,
                    "bits": bits,
                    "lam": lam,
                    "op": op,
                    "n": stats["n"],
                    "mean_ns": stats["mean_ns"],
                    "median_ns": stats["median_ns"],
                    "p95_ns": stats["p95_ns"],
                    "p99_ns": stats["p99_ns"],
                    "min_ns": stats["min_ns"],
                    "max_ns": stats["max_ns"],
                    "icert_len_bytes": icert_len,
                    "pk_len_bytes": pk_len,
                    "sk_len_bytes": sk_len,
                }
            )

    print(f"Wrote: {args.out}")
    print(f"Inputs: {len(paths)} file(s); rows used: {len(rows)}; groups: {len(groups)}")


if __name__ == "__main__":
    main()
