from gic.gic import PKRecon, SKGen, Setup, iCertGen


def test_imports():
    import gic  # noqa: F401

    assert Setup is not None
    assert iCertGen is not None
    assert SKGen is not None
    assert PKRecon is not None
