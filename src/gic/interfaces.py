"""Interface definitions for GIC components."""

from __future__ import annotations

from typing import Protocol, TypeVar

SecretKey = TypeVar("SecretKey")
PublicKey = TypeVar("PublicKey")
Encoded = TypeVar("Encoded")


class KeyGen(Protocol[SecretKey, PublicKey]):
    """Key generation interface: KeyGen(sk) -> pk."""

    def __call__(self, sk: SecretKey) -> PublicKey:
        ...


class SecretKeyGroupOps(Protocol[SecretKey]):
    """Secret-key group operations and scalar action."""

    def sk_add(self, left: SecretKey, right: SecretKey) -> SecretKey:
        ...

    def sk_neg(self, value: SecretKey) -> SecretKey:
        ...

    def sk_scalar_mul(self, scalar: int, value: SecretKey) -> SecretKey:
        ...


class PublicKeyGroupOps(Protocol[PublicKey]):
    """Public-key group operations and scalar action."""

    def pk_mul(self, left: PublicKey, right: PublicKey) -> PublicKey:
        ...

    def pk_inv(self, value: PublicKey) -> PublicKey:
        ...

    def pk_scalar_mul(self, scalar: int, value: PublicKey) -> PublicKey:
        ...


class Encode(Protocol[Encoded]):
    """Encoding interface: encode object into bytes."""

    def encode(self, value: Encoded) -> bytes:
        ...


class Decode(Protocol[Encoded]):
    """Decoding interface: decode bytes into object."""

    def decode(self, data: bytes) -> Encoded:
        ...
