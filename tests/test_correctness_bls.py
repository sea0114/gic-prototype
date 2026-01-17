from __future__ import annotations

from gic.core import PKRecon, SKGen, Setup, iCertGen
from instantiations.bls import make_bls_params


def test_bls_correctness_end_to_end():
    params, sample_H = make_bls_params(lam=128)
    sk_C, pk_C = Setup(params, sample_H)

    identity = b"alice"
    (iCer, _), (_, view_U) = iCertGen(params, identity, sk_C, sample_H)

    sk_U = SKGen(params, view_U, iCer)
    pk_U = PKRecon(params, iCer, pk_C)

    assert pk_U is not None
    assert params.keygen(sk_U) == pk_U


def test_bls_pkrecon_rejects_malformed():
    params, sample_H = make_bls_params(lam=128)
    _sk_C, pk_C = Setup(params, sample_H)

    assert PKRecon(params, b"garbage", pk_C) is None
