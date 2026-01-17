from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple
from math import gcd as GCD
import secrets

from gic.core import Params
from gic.ro import ro_default


# ----------------------------
# Primes / RSA modulus generation (stdlib, for tests/bench)
# ----------------------------

def _is_probable_prime(n: int, rounds: int = 20) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _get_prime(bits: int) -> int:
    assert bits >= 2
    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1))  # ensure bit length
        p |= 1                  # ensure odd
        if _is_probable_prime(p):
            return p


def gen_rsa_modulus(bits: int = 2048) -> int:
    """Generate RSA modulus N = p*q."""
    p = _get_prime(bits // 2)
    q = _get_prime(bits // 2)
    while q == p:
        q = _get_prime(bits // 2)
    return p * q


# ----------------------------
# Group ops for Z_N^* (multiplicative)
#  - H = (Z_N^*, ·), identity 1
#  - E = (Z_N^*, ·), identity 1
#  - inv via modular inverse
# ----------------------------

@dataclass(frozen=True)
class ZStarOps:
    N: int

    def one(self) -> int:
        return 1

    # For H_ops naming in core.py:
    def zero(self) -> int:
        # In multiplicative notation, 0_H corresponds to 1
        return 1

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.N

    def inv(self, a: int) -> int:
        # a must be invertible mod N (i.e., gcd(a,N)=1)
        return pow(a, -1, self.N)

    # Alias for H-group add/neg (⊕ is multiplication)
    def add(self, a: int, b: int) -> int:
        return self.mul(a, b)

    def neg(self, a: int) -> int:
        # inverse element in multiplicative group
        return self.inv(a)


# ----------------------------
# Encode/Decode for iCer = Encode(R_U, id)
# ----------------------------

def _int_to_fixed_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _int_from_fixed_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def make_encode_decode_for_modulus(
    N: int,
) -> tuple[Callable[[int, bytes], bytes], Callable[[bytes], Optional[Tuple[int, bytes]]]]:
    k = (N.bit_length() + 7) // 8  # fixed byte-length for elements mod N

    def encode(RU: int, identity: bytes) -> bytes:
        return b"R=" + _int_to_fixed_bytes(RU % N, k) + b"|id=" + identity

    def decode(iCer: bytes) -> Optional[Tuple[int, bytes]]:
        try:
            if not iCer.startswith(b"R="):
                return None
            rest = iCer[2:]
            if len(rest) < k + 4:
                return None
            RU_bytes = rest[:k]
            tail = rest[k:]
            if not tail.startswith(b"|id="):
                return None
            identity = tail[4:]
            RU = _int_from_fixed_bytes(RU_bytes) % N
            # reject RU not in Z_N^* (must be invertible)
            if GCD(RU, N) != 1:
                return None
            return RU, identity
        except Exception:
            return None

    return encode, decode


# ----------------------------
# KeyGen(s) = s^{-e_RSA} mod N
# ----------------------------

def make_keygen_gq(N: int, e_rsa: int) -> Callable[[int], int]:
    def keygen(s: int) -> int:
        s = s % N
        if GCD(s, N) != 1:
            raise ValueError("Secret key not in Z_N^*")
        inv_s = pow(s, -1, N)
        return pow(inv_s, e_rsa, N)  # (s^{-1})^{e} = s^{-e} mod N
    return keygen


# ----------------------------
# Sampler for secret keys in Z_N^*
# ----------------------------

def make_sampler_zstar(N: int) -> Callable[[], int]:
    def sample() -> int:
        while True:
            x = secrets.randbelow(N - 2) + 2  # in [2, N-1]
            if GCD(x, N) == 1:
                return x
    return sample


# ----------------------------
# Params factory
# ----------------------------

def make_gq_params(
    N: int,
    e_rsa: int = 65537,
    lam: int = 128,
) -> tuple[Params[int, int], Callable[[], int]]:
    ops = ZStarOps(N=N)
    encode, decode = make_encode_decode_for_modulus(N)
    keygen = make_keygen_gq(N, e_rsa)

    params = Params(
        keygen=keygen,
        H_ops=ops,
        E_ops=ops,
        Encode=encode,
        Decode=decode,
        RO=lambda cer: ro_default(cer, lam=lam),
    )
    sample_H = make_sampler_zstar(N)
    return params, sample_H
