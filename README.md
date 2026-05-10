# CS521-Project3a
This is Edward Li's and Saman Dehghan's CS521 project. We are doing Topic-3a.

# Cryptographic Accumulators: A Comparative Study
 
A benchmarking suite comparing four cryptographic accumulator constructions implemented in Python: **RSA**, **Merkle**, **BLS (KZG)**, and **Lattice (SIS)**.

---
 
## Overview
 
A cryptographic accumulator compresses a set of elements into a single compact value and supports succinct membership and non-membership proofs without revealing the full set. This project benchmarks four schemes across accumulation time, proof generation time, proof size, and verification time at set sizes ranging from 10² to 10⁶.
 
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
 
The visualizer has four scheme tabs — **RSA**, **Lattice**, **Merkle**, and **Pairing (BLS/KZG)** — each with the same interactive structure:
 
- **Element set toggle**: Click any of the eight available elements (alice, bob, charlie, dave, eve, frank, grace, heidi) to add or remove them from the accumulator. All visualizations update instantly.
- **Public parameters panel**: Displays the scheme's setup values — the RSA modulus `N = p × q`, the lattice SIS parameters `(n, q, log q, m)`, or the bilinear group order.
- **Element mapping table**: Shows how each element maps to its internal representation — a prime representative for RSA, a SHA-256 leaf hash for Merkle, a SIS hash vector for Lattice, or a field element for BLS.
- **Accumulator display**: Shows the current accumulator value and the formula used to derive it.
- **Proof explorer**: Switch between membership and non-membership tabs, click any element, and see a full step-by-step breakdown of how the proof is constructed and verified, including intermediate values and a pass/fail badge.
### Scheme-specific features
 
**RSA**: Shows Bézout coefficients `(a, b)` for non-membership, the witness `w = g^(∏eᵢ) mod N` for membership, and the verification equation `w^e ≡ acc (mod N)`.
 
**Lattice**: Renders the full SIS Merkle tree as an SVG diagram. Clicking a membership element highlights the authentication path (teal) and sibling nodes (amber) through the tree. Non-membership shows the sorted bracketing neighbours and their auth paths.
 
**Merkle**: Same animated tree diagram as Lattice but using the SHA-256 compression function. The proof explorer shows each sibling hash in the O(log n) path from leaf to root.
 
**Pairing (BLS/KZG)**: Displays the structured reference string (SRS), the characteristic polynomial `χ_S(x) = ∏(x + eᵢ)` with formatted coefficients, and the pairing verification equations. Membership shows the KZG opening proof; non-membership shows the remainder-based proof with all three pairing terms.
 
> The visualizer uses small toy parameters (a ~17-bit RSA modulus, an 8-dimensional SIS lattice, a 17-bit prime-order field) to keep computations fast in JavaScript while staying faithful to the constructions' structure.
 
---


 
