"""Paper-aligned interfaces for Generic Implicit Certificates (GIC)."""

from __future__ import annotations

from typing import Optional, Protocol, Tuple, TypeVar, Callable

H = TypeVar("H")  # element type of secret-key group 𝓗
E = TypeVar("E")  # element type of public-key group 𝓔


class KeyGen(Protocol[H, E]):
    """Deterministic public-key derivation KeyGen : 𝓗 -> 𝓔."""
    def __call__(self, sk: H) -> E: ...


class HGroupOps(Protocol[H]):
    """Secret-key group (𝓗, ⊕) operations."""
    def zero(self) -> H: ...
    def add(self, left: H, right: H) -> H: ...
    def neg(self, value: H) -> H: ...


class EGroupOps(Protocol[E]):
    """Public-key group (𝓔, ⊗) operations."""
    def one(self) -> E: ...
    def mul(self, left: E, right: E) -> E: ...
    def inv(self, value: E) -> E: ...


Encode = Callable[[E, bytes], bytes]
Decode = Callable[[bytes], Optional[Tuple[E, bytes]]]
