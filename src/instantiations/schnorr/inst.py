# src/instantiations/schnorr/inst.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

import secrets

from gic.core import Params
from gic.ro import ro_default

# Pure-Python P-256 ops via `ecdsa`
try:
    from ecdsa.curves import NIST256p
    from ecdsa.ellipticcurve import INFINITY, Point
    from ecdsa.numbertheory import square_root_mod_prime
except Exception as e:  # pragma: no cover
    raise ImportError(
        "Schnorr instantiation requires the 'ecdsa' package. Install via: pip install ecdsa"
    ) from e


# ----------------------------
# H: Z_q as an additive group
# Core expects H_ops: zero/add/neg AND also mul/inv as aliases.
# Here: mul ≡ add, inv ≡ neg.
# ----------------------------

@dataclass(frozen=True)
class ZqOps:
    q: int

    def zero(self) -> int:
        return 0

    def one(self) -> int:
        # core's z_action_* uses ops.one() as identity
        return 0

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.q

    def neg(self, a: int) -> int:
        return (-a) % self.q

    # aliases expected by core naming
    def mul(self, a: int, b: int) -> int:
        return self.add(a, b)

    def inv(self, a: int) -> int:
        return self.neg(a)



# ----------------------------
# E: P-256 EC group as an additive group
# Core expects E_ops.mul/inv (group law), so we alias:
#   mul ≡ add, inv ≡ neg.
# ----------------------------

@dataclass(frozen=True)
class P256Ops:
    curve = NIST256p.curve
    gen = NIST256p.generator
    q = NIST256p.order
    p = NIST256p.curve.p()
    a = NIST256p.curve.a()
    b = NIST256p.curve.b()

    def zero(self):
        return INFINITY

    def one(self):
        # core's z_action_E uses ops.one() as identity
        return INFINITY

    def add(self, A, B):
        return A + B

    def neg(self, A):
        if A == INFINITY:
            return INFINITY
        return Point(self.curve, A.x(), (-A.y()) % self.p, A.order())

    # aliases expected by core naming
    def mul(self, A, B):
        return self.add(A, B)

    def inv(self, A):
        return self.neg(A)

    def scalar_mul(self, k: int, A):
        k = int(k)
        if A == INFINITY or k == 0:
            return INFINITY
        if k < 0:
            return self.scalar_mul(-k, self.neg(A))
        return k * A



# ----------------------------
# SEC1 compressed encoding for P-256 points (33 bytes)
# ----------------------------

def _int_to_fixed_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _int_from_fixed_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _point_to_bytes_compressed(P) -> bytes:
    if P == INFINITY:
        raise ValueError("cannot encode point at infinity")
    x = P.x()
    y = P.y()
    prefix = 0x03 if (y & 1) else 0x02
    return bytes([prefix]) + _int_to_fixed_bytes(x, 32)


def _point_from_bytes_compressed(buf: bytes) -> Optional[Point]:
    if len(buf) != 33:
        return None
    prefix = buf[0]
    if prefix not in (0x02, 0x03):
        return None
    x = _int_from_fixed_bytes(buf[1:])
    p = P256Ops.p
    a = P256Ops.a
    b = P256Ops.b
    if x >= p:
        return None

    rhs = (pow(x, 3, p) + (a * x) % p + b) % p
    try:
        y = square_root_mod_prime(rhs, p)
    except Exception:
        return None

    if (y & 1) != (prefix & 1):
        y = (-y) % p

    try:
        P = Point(P256Ops.curve, x, y, P256Ops.q)
    except Exception:
        return None

    if P == INFINITY:
        return None
    return P


# ----------------------------
# Encode/Decode for iCer = Encode(R_U, id)
# ----------------------------

def make_encode_decode_p256() -> tuple[
    Callable[[Point, bytes], bytes],
    Callable[[bytes], Optional[Tuple[Point, bytes]]],
]:
    RU_LEN = 33

    def encode(RU: Point, identity: bytes) -> bytes:
        return b"R=" + _point_to_bytes_compressed(RU) + b"|id=" + identity

    def decode(iCer: bytes) -> Optional[Tuple[Point, bytes]]:
        try:
            if not iCer.startswith(b"R="):
                return None
            rest = iCer[2:]
            if len(rest) < RU_LEN + 4:
                return None
            RU_bytes = rest[:RU_LEN]
            tail = rest[RU_LEN:]
            if not tail.startswith(b"|id="):
                return None
            identity = tail[4:]
            RU = _point_from_bytes_compressed(RU_bytes)
            if RU is None:
                return None
            return RU, identity
        except Exception:
            return None

    return encode, decode


# ----------------------------
# KeyGen(s) = s * G  (Schnorr-type)
# ----------------------------

def make_keygen_p256() -> Callable[[int], Point]:
    G = P256Ops.gen
    q = P256Ops.q

    def keygen(s: int) -> Point:
        s = int(s) % q
        if s == 0:
            raise ValueError("Secret key must be nonzero in Z_q")
        return s * G

    return keygen


def make_sampler_zq(q: int) -> Callable[[], int]:
    def sample() -> int:
        return secrets.randbelow(q - 1) + 1
    return sample


def make_schnorr_params(lam: int = 128) -> tuple[Params[int, Point], Callable[[], int]]:
    q = P256Ops.q
    H_ops = ZqOps(q=q)
    E_ops = P256Ops()
    encode, decode = make_encode_decode_p256()
    keygen = make_keygen_p256()

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
