# GIC Prototype

This repository provides a **reference prototype** of the *Generic Implicit Certificate (GIC)* framework proposed in the accompanying paper.

The implementation is designed to demonstrate the **generic issuance and reconstruction interface**, support multiple algebraic instantiations, and enable a **transparent and fair performance evaluation** across instantiations.

---

## Scope and Non-goals

**Scope**
- Illustrate the generic construction of implicit certificates.
- Validate the feasibility and cost profile of the construction.
- Provide a uniform benchmarking harness across different algebraic settings.

**Non-goals**
- This code is **not** a production-ready PKI system.
- It is **not** optimized for deployment or engineering efficiency.
- It does **not** implement full PKI workflows (e.g., revocation, lifecycle management).

The prototype is intended **solely for research and evaluation purposes**.

---

## Relation to the Paper

The repository structure mirrors the organization of the paper:

- **Generic construction and notation**: Sections II–III  
- **Security model and proofs**: Section IV-V  
- **Instantiation examples**: Section VI  
- **Performance evaluation**: Section VII  

The implementation follows exactly the issuance and reconstruction logic described in Fig. 1 of the paper.

---

## Supported Instantiations

The prototype supports the following representative instantiations under a unified interface:

- **GQ-type**: RSA-3072  
- **Schnorr-type**: NIST P-256  
- **BLS-type**: BLS12-381 \(G_1\) (no pairings)

All instantiations share the same generic construction and differ only in their underlying algebraic realization.

---

## Benchmarking

A unified benchmarking harness is included to measure the runtime of the three core procedures:

- Certificate issuance (`iCertGen`)
- User-side secret-key reconstruction (`SKGen`)
- Verifier-side public-key reconstruction (`PKRecon`)

Benchmarks are conducted under a common **128-bit classical security target** with a fixed measurement procedure, including warm-up and repeated trials.  
The goal is to compare **relative cost profiles**, not to provide deployment-optimized performance figures.

---

## Reproducibility

- All instantiations are implemented in the same language with consistent library choices.
- Measurements are averaged over repeated trials after warm-up.
- Reported results correspond directly to the performance tables in the paper.

---

## License

This code is provided for **academic and research use only**.
