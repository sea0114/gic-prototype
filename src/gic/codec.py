from __future__ import annotations

from typing import Optional, Tuple, TypeVar

E = TypeVar("E")


def encode_simple(R: E, identity: bytes) -> bytes:
    """Injective deterministic encoding for prototype use.

    We encode as: b"R=" + repr(R).encode() + b"|id=" + identity
    This is reversible only if repr(R) can be parsed. For the prototype,
    we'll instead supply instantiation-specific encode/decode when needed.

    For correctness tests we will use integer E, where parsing is easy.
    """
    return b"R=" + str(R).encode("utf-8") + b"|id=" + identity


def decode_simple_int(iCer: bytes) -> Optional[Tuple[int, bytes]]:
    """Decode for the simple integer-E case. Returns None as ⊥ on malformed input."""
    try:
        parts = iCer.split(b"|id=", 1)
        if len(parts) != 2:
            return None
        left, identity = parts
        if not left.startswith(b"R="):
            return None
        R = int(left[2:].decode("utf-8"))
        return R, identity
    except Exception:
        return None
