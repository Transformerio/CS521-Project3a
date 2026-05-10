# CS521-Project3a
This is Edward Li's and Saman Dehghan's CS521 project. We are doing Topic-3a.

# Cryptographic Accumulators: A Comparative Study
 
A benchmarking suite comparing four cryptographic accumulator constructions implemented in Python: **RSA**, **Merkle**, **BLS (KZG)**, and **Lattice (SIS)**.

---
 
## Overview
 
A cryptographic accumulator compresses a set of elements into a single compact value and supports succinct membership and non-membership proofs without revealing the full set. This project benchmarks four schemes across accumulation time, proof generation time, proof size, and verification time.
 
| Scheme  | Security Assumption | Post-Quantum | Trusted Setup |
|---------|--------------------:|:------------:|:-------------:|
| Merkle  | SHA-256 collision resistance | ✗ | No |
| RSA     | Strong RSA assumption | ✗ | Yes (N = pq) |
| BLS     | KZG / discrete log on BLS12-381 | ✗ | Yes (SRS) |
| Lattice | SIS / worst-case lattice (SIVP) | ✓ | No |
 
---

## Requirements
 
- Python 3.11+
- [py_ecc](https://github.com/ethereum/py_ecc) — BLS12-381 pairing operations
- NumPy — matrix operations for the lattice scheme
```bash
pip install py_ecc numpy
```
 
---
 
## Running the Benchmark
 
```bash
python benchmark.py
```

## Scheme Summaries
 
### Merkle
Sorted binary hash tree using SHA-256. Membership proofs are O(log n) sibling hashes. Non-membership uses adjacent leaf proofs in the sorted tree. Fastest scheme at every scale.
 
### RSA
Accumulator value `g^(e₁·e₂·…·eₖ) mod N`. Membership witness is a single modular integer. Non-membership uses Bézout coefficients via extended GCD. Proof size is constant but generation time scales poorly beyond n = 10⁴.
 
### BLS (KZG)
Polynomial commitment over BLS12-381. The characteristic polynomial `P(z) = ∏(z + xᵢ)` is committed at a secret point `s`. Membership verification requires 2 pairings; non-membership requires 3. Constant proof size but O(n²) scaling makes it impractical beyond n = 10⁴.
 
### Lattice (SIS)
Merkle tree whose compression function is the Ajtai/SIS hash `h_A(x) = A·x mod q`, where inputs are binary vectors to preserve the SIS hardness reduction. The only post-quantum secure scheme in this study. Produces the smallest proofs (48 bytes) and completes accumulation and proof generation faster than RSA and BLS.
 
---

## Repository Structure
 
```
.
├── benchmark.py      # Central benchmark runner
├── mtree.py          # Merkle accumulator (sorted tree, SHA-256)
├── bls.py            # BLS polynomial commitment accumulator (KZG / BLS12-381)
├── lattice.py        # Lattice-based accumulator (SIS / Merkle-SIS tree)
├── rsa.py            # RSA accumulator (Bézout non-membership proofs)
└── visualize/
    └── visualize.html  # Interactive in-browser visualizer (no server needed)
```
 
---

## Interactive Visualizer
 
`visualize/visualize.html` is a self-contained, single-file interactive explainer that runs entirely in the browser — no server, no dependencies, no build step.
 
**[Open visualize.html](https://github.com/Transformerio/CS521-Project3a/blob/main/visualize/visualize.html)** (download and open locally, or use GitHub's HTML preview)
 
### What it shows
 
The visualizer has four scheme tabs — **RSA**, **Lattice**, **Merkle**, and **Pairing (BLS/KZG)** — each with the same interactive structure.
