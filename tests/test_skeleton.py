import pytest

from gic.gic import PKRecon, SKGen, Setup, iCertGen


@pytest.mark.parametrize("func", [Setup, iCertGen, SKGen, PKRecon])
def test_skeleton_raises_not_implemented(func):
    with pytest.raises(NotImplementedError):
        func()
