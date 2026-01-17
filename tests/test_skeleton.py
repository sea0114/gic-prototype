from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from gic.core import Params, PKRecon, SKGen, Setup, iCertGen
from gic.codec import decode_simple_int, encode_simple
from gic.ro import ro_default

Q = 65537


@dataclass(frozen=True)
class HOps:
    def zero(self) -> int:
        return 0

    def add(self, left: int, right: int) -> int:
        return (left + right) % Q

    def neg(self, value: int) -> int:
        return (-value) % Q


@dataclass(frozen=True)
class EOps:
    # Here we realize (E, ⊗) as addition mod Q (still an abelian group).
    def one(self) -> int:
        return 0

    def mul(self, left: int, right: int) -> int:
        return (left + right) % Q

    def inv(self, value: int) -> int:
        return (-value) % Q


def keygen(sk: int) -> int:
    # Deterministic KeyGen : H -> E (toy)
    return sk % Q


def decode(iCer: bytes) -> Optional[Tuple[int, bytes]]:
    return decode_simple_int(iCer)


def sample_H() -> int:
    import secrets
    return secrets.randbelow(Q)


def test_correctness_definition_ic_syntax():
    params = Params(
        keygen=keygen,
        H_ops=HOps(),
        E_ops=EOps(),
        Encode=encode_simple,
        Decode=decode,
        RO=lambda cer: ro_default(cer, lam=16),
    )

    sk_C, pk_C = Setup(params, sample_H)

    identity = b"alice"
    (iCer, view_CA), (_iCer2, view_U) = iCertGen(params, identity, sk_C, sample_H)

    sk_U = SKGen(params, view_U, iCer)
    pk_U = PKRecon(params, iCer, pk_C)

    assert pk_U is not None
    assert keygen(sk_U) == pk_U


def test_pkrecon_rejects_malformed():
    params = Params(
        keygen=keygen,
        H_ops=HOps(),
        E_ops=EOps(),
        Encode=encode_simple,
        Decode=decode,
        RO=lambda cer: ro_default(cer, lam=16),
    )

    sk_C, pk_C = Setup(params, sample_H)

    malformed = b"not-an-icert"
    assert PKRecon(params, malformed, pk_C) is None
