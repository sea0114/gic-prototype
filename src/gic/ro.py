from __future__ import annotations

from hashlib import sha256


def ro_default(iCer: bytes, lam: int = 128) -> int:
    """Deterministic stand-in for a random oracle: {0,1}* -> {1,...,2^lam}."""
    h = int.from_bytes(sha256(iCer).digest(), "big")
    return 1 + (h % (2**lam))
