from __future__ import annotations

import argparse
import csv
import os
import time
from dataclasses import dataclass
from typing import Callable

from gic.core import PKRecon, SKGen, Setup, iCertGen

from instantiations.gq import gen_rsa_modulus, make_gq_params
from instantiations.schnorr import make_schnorr_params
from instantiations.bls import make_bls_params


@dataclass(frozen=True)
class BenchConfig:
    scheme: str
    bits: int
    e_rsa: int
    lam: int
    warmup: int
    reps: int
    out: str
    identity: bytes


def _timed_ns(fn: Callable[[], object]) -> int:
    t0 = time.perf_counter_ns()
    fn()
    return time.perf_counter_ns() - t0


def _apply_security_profile(scheme: str, bits: int, lam: int, sec: int | None) -> tuple[int, int]:
    """
    A: security-level matched (classical) profiles.

    sec = 128:
      - GQ (RSA): RSA-3072, RO output 128
      - Schnorr (P-256): RO output 128 (curve fixed in instantiation)
      - BLS (BLS12-381 G1): RO output 128 (curve fixed in instantiation)
    """
    if sec is None:
        return bits, lam
    if sec != 128:
        raise ValueError(f"Unsupported --sec={sec}. Supported: 128.")

    if scheme == "gq":
        return 3072, 128
    if scheme in ("schnorr", "bls"):
        return bits, 128  # bits unused for schnorr/bls
    raise ValueError(f"Unsupported scheme={scheme}.")


def _write_row(
    w: csv.DictWriter,
    scheme: str,
    bits: int,
    lam: int,
    op: str,
    warmup: int,
    rep: int,
    elapsed_ns: int,
    icert_len: int,
) -> None:
    w.writerow(
        {
            "scheme": scheme,
            "bits": bits,
            "lam": lam,
            "op": op,
            "warmup": warmup,
            "rep": rep,
            "elapsed_ns": elapsed_ns,
            "icert_len_bytes": icert_len,
        }
    )


def _run_generic(cfg: BenchConfig, params, sample_H, scheme_name: str) -> None:
    os.makedirs(os.path.dirname(cfg.out), exist_ok=True)

    with open(cfg.out, "w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "scheme",
                "bits",
                "lam",
                "op",
                "warmup",
                "rep",
                "elapsed_ns",
                "icert_len_bytes",
            ],
        )
        w.writeheader()

        for i in range(cfg.warmup + cfg.reps):
            is_warmup = 1 if i < cfg.warmup else 0
            rep = i if is_warmup else i - cfg.warmup

            sk_C, pk_C = Setup(params, sample_H)

            holder = {}

            def _do_icertgen():
                (iCer, _), (_, view_U) = iCertGen(params, cfg.identity, sk_C, sample_H)
                holder["iCer"] = iCer
                holder["view_U"] = view_U

            t_icert = _timed_ns(_do_icertgen)
            iCer = holder["iCer"]
            view_U = holder["view_U"]

            _write_row(w, scheme_name, cfg.bits, cfg.lam, "iCertGen", is_warmup, rep, t_icert, len(iCer))

            holder2 = {}

            def _do_skgen():
                holder2["sk_U"] = SKGen(params, view_U, iCer)

            t_skgen = _timed_ns(_do_skgen)
            sk_U = holder2["sk_U"]

            _write_row(w, scheme_name, cfg.bits, cfg.lam, "SKGen", is_warmup, rep, t_skgen, len(iCer))

            def _do_pkrecon():
                PKRecon(params, iCer, pk_C)

            t_pkrecon = _timed_ns(_do_pkrecon)
            _write_row(w, scheme_name, cfg.bits, cfg.lam, "PKRecon", is_warmup, rep, t_pkrecon, len(iCer))

            if not is_warmup:
                pk_U = PKRecon(params, iCer, pk_C)
                assert pk_U is not None
                assert params.keygen(sk_U) == pk_U


def run_gq(cfg: BenchConfig) -> None:
    N = gen_rsa_modulus(bits=cfg.bits)
    params, sample_H = make_gq_params(N=N, e_rsa=cfg.e_rsa, lam=cfg.lam)
    _run_generic(cfg, params, sample_H, "gq")


def run_schnorr(cfg: BenchConfig) -> None:
    params, sample_H = make_schnorr_params(lam=cfg.lam)
    _run_generic(cfg, params, sample_H, "schnorr")


def run_bls(cfg: BenchConfig) -> None:
    params, sample_H = make_bls_params(lam=cfg.lam)
    _run_generic(cfg, params, sample_H, "bls")


def main() -> None:
    ap = argparse.ArgumentParser(description="GIC benchmark harness (GQ / Schnorr / BLS).")

    ap.add_argument("--scheme", choices=["gq", "schnorr", "bls"], default="gq", help="Benchmark scheme")
    ap.add_argument("--sec", type=int, default=None, help="Target classical security level (supported: 128)")

    ap.add_argument("--bits", type=int, default=2048, help="RSA modulus bits (GQ only)")
    ap.add_argument("--e", type=int, default=65537, help="RSA public exponent (GQ only)")
    ap.add_argument("--lam", type=int, default=128, help="RO output length")

    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--reps", type=int, default=200)
    ap.add_argument("--out", type=str, default="bench/outputs/out.csv")
    ap.add_argument("--id", type=str, default="alice")
    args = ap.parse_args()

    bits, lam = _apply_security_profile(args.scheme, args.bits, args.lam, args.sec)

    cfg = BenchConfig(
        scheme=args.scheme,
        bits=bits,
        e_rsa=args.e,
        lam=lam,
        warmup=args.warmup,
        reps=args.reps,
        out=args.out,
        identity=args.id.encode(),
    )

    if cfg.scheme == "gq":
        run_gq(cfg)
    elif cfg.scheme == "schnorr":
        run_schnorr(cfg)
    else:
        run_bls(cfg)


if __name__ == "__main__":
    main()
