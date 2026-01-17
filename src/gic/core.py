from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, Optional, Tuple, TypeVar

from .interfaces import Decode, EGroupOps, Encode, HGroupOps, KeyGen

H = TypeVar("H")
E = TypeVar("E")


def z_action_H(ops: HGroupOps[H], a: int, h: H) -> H:
    """Compute a ⊙_H h using group law ⊕ (double-and-add), supporting a<0."""
    if a == 0:
        return ops.zero()
    if a < 0:
        return z_action_H(ops, -a, ops.neg(h))

    res = ops.zero()
    base = h
    n = a
    while n > 0:
        if n & 1:
            res = ops.add(res, base)
        base = ops.add(base, base)
        n >>= 1
    return res


def z_action_E(ops: EGroupOps[E], a: int, X: E) -> E:
    """Compute a ⊙_E X using group law ⊗ (square-and-multiply), supporting a<0."""
    if a == 0:
        return ops.one()
    if a < 0:
        return z_action_E(ops, -a, ops.inv(X))

    res = ops.one()
    base = X
    n = a
    while n > 0:
        if n & 1:
            res = ops.mul(res, base)
        base = ops.mul(base, base)
        n >>= 1
    return res


@dataclass(frozen=True)
class Params(Generic[H, E]):
    keygen: KeyGen[H, E]
    H_ops: HGroupOps[H]
    E_ops: EGroupOps[E]
    Encode: Encode[E]
    Decode: Decode[E]
    RO: Callable[[bytes], int]  # H(iCer) -> e in D_λ ⊆ Z_{≥1}


@dataclass(frozen=True)
class ViewU(Generic[H]):
    k_U: H
    r: H


@dataclass(frozen=True)
class ViewCA(Generic[H]):
    k_C: H
    r: H


def Setup(params: Params[H, E], sample_H: Callable[[], H]) -> Tuple[H, E]:
    """Setup: sk_C ←$ H; pk_C := KeyGen(sk_C)."""
    sk_C = sample_H()
    pk_C = params.keygen(sk_C)
    return sk_C, pk_C


def iCertGen(
    params: Params[H, E],
    identity: bytes,
    sk_C: H,
    sample_H: Callable[[], H],
) -> Tuple[Tuple[bytes, ViewCA[H]], Tuple[bytes, ViewU[H]]]:
    """Issuance: implement Fig.1 exactly (collapsed into one function).

    User:
      k_U ←$ H; K_U := KeyGen(k_U); send (K_U, id)

    CA:
      k_C ←$ H; K_C := KeyGen(k_C)
      R_U := K_U ⊗ K_C
      iCer := Encode(R_U, id)
      e := RO(iCer)
      r := (e ⊙_H k_C) ⊕ sk_C
      send (iCer, r)

    Views:
      view_U := (k_U, r)
      view_CA := (k_C, r)
    """
    k_U = sample_H()
    K_U = params.keygen(k_U)

    k_C = sample_H()
    K_C = params.keygen(k_C)

    R_U = params.E_ops.mul(K_U, K_C)
    iCer = params.Encode(R_U, identity)

    e = params.RO(iCer)
    r = params.H_ops.add(z_action_H(params.H_ops, e, k_C), sk_C)

    return (iCer, ViewCA(k_C=k_C, r=r)), (iCer, ViewU(k_U=k_U, r=r))


def SKGen(params: Params[H, E], view_U: ViewU[H], iCer: bytes) -> H:
    """User-side reconstruction: sk_U := (e ⊙_H k_U) ⊕ r."""
    e = params.RO(iCer)
    return params.H_ops.add(z_action_H(params.H_ops, e, view_U.k_U), view_U.r)


def PKRecon(params: Params[H, E], iCer: bytes, pk_C: E) -> Optional[E]:
    """Verifier-side reconstruction: pk_U := (e ⊙_E R_U) ⊗ pk_C, or ⊥ if malformed."""
    decoded = params.Decode(iCer)
    if decoded is None:
        return None
    R_U, _id = decoded
    e = params.RO(iCer)
    return params.E_ops.mul(z_action_E(params.E_ops, e, R_U), pk_C)
