# GIC Prototype

This repository provides a **reference prototype** of the *Generic Implicit Certificate (GIC)* framework proposed in the accompanying paper.

The prototype implements a **generic implicit-certificate construction derived from key-homomorphic key generation**, and is designed to:

- demonstrate the **generic issuance and reconstruction interface**
- support multiple algebraic instantiations
- enable a **transparent and fair performance evaluation** across instantiations

---

## Quick Start

```bash
git clone https://github.com/sea0114/gic-prototype
cd gic-prototype

# run benchmark
python bench/run_bench.py

# generate figures
python bench/plot_figs.py
```

Generated figures will be saved under:

```
bench/figures/
```

---

## Scope and Non-goals

### Scope

- Illustrate the generic construction of implicit certificates.
- Validate the feasibility and cost profile of the construction.
- Provide a uniform benchmarking harness across different algebraic settings.

### Non-goals

- This code is **not** a production-ready PKI system.
- It is **not** optimized for deployment or engineering efficiency.
- It does **not** implement full PKI workflows (e.g., revocation, lifecycle management).

The prototype is intended **solely for research and evaluation purposes**.

---

## Relation to the Paper

The repository structure mirrors the organization of the paper:

- **Generic construction and notation**: Sections III–IV  
- **Security model and proofs**: Section V–VI  
- **Instantiation examples**: Section VII  
- **Performance evaluation**: Section VIII  

The implementation follows exactly the issuance and reconstruction logic described in the paper (Fig. 2).  
The generated figures correspond directly to:

- **Fig. 3**: Cost breakdown (latency)
- **Fig. 4**: Size footprint

---

## Supported Instantiations

The prototype supports the following representative instantiations under a unified interface:

- **GQ-type**: RSA-3072  
- **Schnorr-type**: NIST P-256  
- **BLS-type**: BLS12-381 (G_1) (no pairings)

All instantiations share the same generic construction and differ only in their underlying algebraic realization.

---

## Benchmarking

A unified benchmarking harness is included to measure the runtime of the three core procedures:

- Certificate issuance (`iCertGen`)
- User-side secret-key reconstruction (`SKGen`)
- Verifier-side public-key reconstruction (`PKRecon`)

Benchmarks are conducted under a common **128-bit classical security target** with a fixed measurement procedure, including warm-up and repeated trials.

The goal is to compare **relative cost profiles under a fixed generic interface**, rather than optimized implementations of individual schemes.

---

## Reproducibility

All figures in the paper can be reproduced using the provided scripts.

### 1. Run benchmarking

```bash
python bench/run_bench.py
```

This generates:

```
bench/outputs/summary_all_sec128_v2.csv
```

### 2. Generate figures

```bash
python bench/plot_figs.py
```

This produces:

- `fig1_cost_breakdown.pdf`
- `fig2_tail_latency_p95.pdf`
- `fig3_size_footprint.pdf`
- `fig4_scale_out_model.pdf`

All outputs are saved in:

```
bench/figures/
```

---

## Implementation Notes

- All instantiations are implemented in a unified framework with consistent interfaces.
- The same measurement pipeline is applied across all schemes.
- Results are averaged over repeated trials after warm-up.
- Network effects and full PKI workflows are intentionally excluded.

---

## License

This code is provided for **academic and research use only**.