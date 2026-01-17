# src/instantiations/bls/inst.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

import secrets

from gic.core import Params
from gic.ro import ro_default

# py_ecc for BLS12-381 G1 group ops + point compression (no pairing).
# Install: pip install py-ecc
try:
    from py_ecc.optimized_bls12_381 import (
        G1,
        Z1,
        add,
        neg,
        multiply,
        curve_order,
        is_on_curve,
        b,
        normalize,
        is_inf,
    )
    from py_ecc.bls.point_compression import compress_G1, decompress_G1
except Exception as e:  # pragma: no cover
    raise ImportError(
        "BLS12-381 instantiation requires 'py-ecc'. Install via: pip install py-ecc"
    ) from e


# ----------------------------
# Point representation note (important!)
# - py_ecc optimized curve arithmetic expects Jacobian points (x, y, z).
# - normalize(P) returns affine (x, y).
# We canonicalize for equality (affine), but must convert back to Jacobian
# before calling add/neg/multiply to avoid IndexError.
# ----------------------------

def _to_jacobian(P):
    """Convert affine (x,y) to Jacobian (x,y,1). Keep Jacobian as-is."""
    if P is None:
        return None
    if is_inf(P):
        return Z1
    # Jacobian already
    if isinstance(P, tuple) and len(P) == 3:
        return P
    # Affine -> Jacobian
    if isinstance(P, tuple) and len(P) == 2:
        x, y = P
        try:
            one = x.one()  # field element 1
        except Exception:
            # Fallback if x is plain int-like (shouldn't happen in py_ecc)
            one = 1
        return (x, y, one)
    return P


def _canon_g1(P):
    """Canonicalize for stable equality: affine for non-infinity, Z1 for infinity."""
    if P is None:
        return None
    try:
        if is_inf(P):
            return Z1
        return normalize(_to_jacobian(P))  # affine (x, y)
    except Exception:
        return P


# ----------------------------
# H: Z_q as an additive group (secret keys)
# Core expects: zero/one/add/neg and also mul/inv as aliases.
# ----------------------------

@dataclass(frozen=True)
class ZqOps:
    q: int

    def zero(self) -> int:
        return 0

    def one(self) -> int:
        return 0

    def add(self, a: int, b_: int) -> int:
        return (a + b_) % self.q

    def neg(self, a: int) -> int:
        return (-a) % self.q

    # aliases expected by core naming
    def mul(self, a: int, b_: int) -> int:
        return self.add(a, b_)

    def inv(self, a: int) -> int:
        return self.neg(a)


# ----------------------------
# E: BLS12-381 G1 as an additive group (public keys)
# Core expects: one/mul/inv.
# We canonicalize outputs (affine) for stable equality, but convert inputs
# back to Jacobian before calling py_ecc arithmetic.
# ----------------------------

@dataclass(frozen=True)
class G1Ops:
    def zero(self):
        return Z1

    def one(self):
        return Z1

    def add(self, A, B):
        return _canon_g1(add(_to_jacobian(A), _to_jacobian(B)))

    def neg(self, A):
        return _canon_g1(neg(_to_jacobian(A)))

    # aliases expected by core naming
    def mul(self, A, B):
        return _canon_g1(add(_to_jacobian(A), _to_jacobian(B)))

    def inv(self, A):
        return _canon_g1(neg(_to_jacobian(A)))


# ----------------------------
# Encode/Decode for iCer = Encode(R_U, id)
# - RU encoded as 48-byte compressed G1 point
# - iCer = b"R=" || RU48 || b"|id=" || id
# Decode returns (RU, id) or None on malformed input.
# ----------------------------

_RU_LEN = 48  # BLS12-381 G1 compressed size


def _int_to_fixed_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _int_from_fixed_bytes(bts: bytes) -> int:
    return int.from_bytes(bts, "big")


def _g1_to_bytes_compressed(P) -> bytes:
    # compress_G1 expects a Jacobian point in optimized form
    PJ = _to_jacobian(P)
    c = compress_G1(PJ)
    return _int_to_fixed_bytes(int(c), _RU_LEN)


def _g1_from_bytes_compressed(buf: bytes):
    if len(buf) != _RU_LEN:
        return None
    c = _int_from_fixed_bytes(buf)
    try:
        P = decompress_G1(c)  # typically returns Jacobian point
    except Exception:
        return None
    # Validate on-curve using Jacobian form
    try:
        if not is_on_curve(P, b):
            return None
    except Exception:
        return None
    # Return canonical affine (stable equality) while ops will convert back when needed
    return _canon_g1(P)


def make_encode_decode_bls_g1() -> tuple[
    Callable[[object, bytes], bytes],
    Callable[[bytes], Optional[Tuple[object, bytes]]],
]:
    def encode(RU, identity: bytes) -> bytes:
        return b"R=" + _g1_to_bytes_compressed(RU) + b"|id=" + identity

    def decode(iCer: bytes) -> Optional[Tuple[object, bytes]]:
        try:
            if not iCer.startswith(b"R="):
                return None
            rest = iCer[2:]
            if len(rest) < _RU_LEN + 4:  # RU + b"|id="
                return None
            RU_bytes = rest[:_RU_LEN]
            tail = rest[_RU_LEN:]
            if not tail.startswith(b"|id="):
                return None
            identity = tail[4:]
            RU = _g1_from_bytes_compressed(RU_bytes)
            if RU is None:
                return None
            return RU, identity
        except Exception:
            return None

    return encode, decode


# ----------------------------
# KeyGen(s) = s * G1 (no pairing)
# Canonicalize output to affine for stable equality.
# ----------------------------

def make_keygen_bls_g1(q: int) -> Callable[[int], object]:
    def keygen(s: int):
        s = int(s) % q
        if s == 0:
            raise ValueError("Secret key must be nonzero in Z_q")
        return _canon_g1(multiply(G1, s))  # multiply returns Jacobian; canon -> affine
    return keygen


# ----------------------------
# Sampler for secret keys in Z_q^*
# ----------------------------

def make_sampler_zq(q: int) -> Callable[[], int]:
    def sample() -> int:
        return secrets.randbelow(q - 1) + 1
    return sample


# ----------------------------
# Params factory (plug-in for core Figure 1)
# ----------------------------

def make_bls_params(lam: int = 128) -> tuple[Params[int, object], Callable[[], int]]:
    """
    Return (params, sample_H) for BLS12-381 G1 instantiation (no pairing).

    - H: Z_q additive group (secret keys)
    - E: G1 additive group (public keys)
    - KeyGen(s) = s * G1
    - Encode/Decode uses compressed G1 (48 bytes)
    """
    q = int(curve_order)
    H_ops = ZqOps(q=q)
    E_ops = G1Ops()
    encode, decode = make_encode_decode_bls_g1()
    keygen = make_keygen_bls_g1(q)

    params = Params(
        keygen=keygen,
        H_ops=H_ops,
        E_ops=E_ops,
        Encode=encode,
        Decode=decode,
        RO=lambda cer: ro_default(cer, lam=lam),
    )
    sample_H = make_sampler_zq(q)
    return params, sample_H
