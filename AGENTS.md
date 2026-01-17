# AGENTS.md — GIC prototype guidelines

## Goal
Build a functional prototype to validate correctness and relative cost profile of the generic implicit-certificate construction.
This is NOT a deployment-level optimized implementation.

## Scope rules
- Implement IC-specific glue logic by us: Setup / iCertGen / SKGen / PKRecon / Encode / Decode.
- Cryptographic primitives may rely on standard libraries, but do NOT reuse full ECQV implementations.
- The first instantiation should be GQ in pure Python using built-in modular arithmetic.

## Engineering rules
- Keep the code readable and reviewer-safe.
- No premature optimization, no platform-specific tuning.
- Ensure reproducibility via deterministic randomness when possible.

## Deliverables
1) Python src-layout under `src/`.
2) Pytest-based correctness tests.
3) Minimal benchmark scripts reporting time for Setup / iCertGen / SKGen / PKRecon.

## Naming alignment
All functions and naming must follow the paper.

- Setup
- iCertGen
- SKGen
- PKRecon
- Encode / Decode
- H(iCert) -> e
