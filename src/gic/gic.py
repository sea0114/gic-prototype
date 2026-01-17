"""Skeleton GIC construction entry points."""

from __future__ import annotations


def Setup(*_args, **_kwargs):
    """Setup the GIC scheme parameters."""
    raise NotImplementedError("Setup is not implemented yet.")


def iCertGen(*_args, **_kwargs):
    """Generate an implicit certificate."""
    raise NotImplementedError("iCertGen is not implemented yet.")


def SKGen(*_args, **_kwargs):
    """Derive a secret key from an implicit certificate."""
    raise NotImplementedError("SKGen is not implemented yet.")


def PKRecon(*_args, **_kwargs):
    """Reconstruct a public key from an implicit certificate."""
    raise NotImplementedError("PKRecon is not implemented yet.")
