from __future__ import annotations

from gic.core import PKRecon, SKGen, Setup, iCertGen
from instantiations.gq import gen_rsa_modulus, make_gq_params


def test_gq_correctness_end_to_end():
    # Keep modulus small for unit tests (fast). Benchmarks will use 2048+ bits.
    N = gen_rsa_modulus(bits=512)
    params, sample_H = make_gq_params(N=N, e_rsa=65537, lam=16)

    sk_C, pk_C = Setup(params, sample_H)

    identity = b"alice"
    (iCer, view_CA), (_iCer2, view_U) = iCertGen(params, identity, sk_C, sample_H)

    sk_U = SKGen(params, view_U, iCer)
    pk_U = PKRecon(params, iCer, pk_C)

    assert pk_U is not None
    assert params.keygen(sk_U) == pk_U


def test_gq_pkrecon_rejects_malformed():
    N = gen_rsa_modulus(bits=512)
    params, sample_H = make_gq_params(N=N, e_rsa=65537, lam=16)
    sk_C, pk_C = Setup(params, sample_H)

    assert PKRecon(params, b"garbage", pk_C) is None
