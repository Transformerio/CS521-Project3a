"""
Lattice-Based Accumulator with Membership & Non-Membership Proofs
=================================================================

Architecture
------------
A Merkle tree whose compression function is the Ajtai / SIS hash:

    h_A(x) = A · x  mod q,      A ∈ Z_q^{n × m},   x ∈ {0,1}^m

Collision resistance reduces to the Short Integer Solution (SIS) problem,
which in turn reduces to worst-case lattice problems (SIVP / GapSVP) —
believed hard even for quantum computers.

To keep inputs binary (required for SIS hardness), every Z_q^n vector is
bit-decomposed before it enters the hash.  Concretely:

  * leaf hash   :  A_leaf · bits(SHA-256(element))  mod q   →  Z_q^n
  * internal    :  A · [bitdecomp(left) || bitdecomp(right)] mod q  →  Z_q^n

Membership proof   : standard Merkle authentication path.
Non-membership proof: the tree stores elements in *sorted* order; the proof
                      exhibits two adjacent leaves that bracket the target
                      and supplies auth paths for both.

Parameters (toy – for illustration, not production security):
    n     = 32        lattice dimension
    q     = 8191      prime modulus
    log_q = 13        bits per Z_q entry
"""

from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass, field
from typing import Optional

import numpy as np


# ──────────────────────────────────────────────────────────────────────────────
# Parameters
# ──────────────────────────────────────────────────────────────────────────────
N_DIM  = 32            # lattice dimension  (security parameter)
Q      = 8191          # prime modulus
LOG_Q  = 13            # ⌈log₂ q⌉
LEAF_BITS = 256        # SHA-256 digest length in bits

# Input dimension for internal pair hashing: two n-vectors, each decomposed
# into n * log_q bits  →  m = 2 · n · log_q
M_DIM = 2 * N_DIM * LOG_Q   # 2 · 32 · 13 = 832


# ──────────────────────────────────────────────────────────────────────────────
# SIS Hash
# ──────────────────────────────────────────────────────────────────────────────
class SISHash:
    """
    Ajtai / SIS hash function.

    Two public matrices:
        A_leaf ∈ Z_q^{n × 256}   – hashes a 256-bit SHA digest to Z_q^n
        A      ∈ Z_q^{n × m}     – compresses two Z_q^n nodes into one
    """

    def __init__(self, seed: int = 42):
        rng = np.random.RandomState(seed)
        self.A_leaf: np.ndarray = rng.randint(0, Q, size=(N_DIM, LEAF_BITS)).astype(np.int64)
        self.A: np.ndarray      = rng.randint(0, Q, size=(N_DIM, M_DIM)).astype(np.int64)

    # ── helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def _bit_decompose(v: np.ndarray) -> np.ndarray:
        """Decompose each entry of v ∈ Z_q^n into LOG_Q bits (LSB first)."""
        bits = np.zeros(len(v) * LOG_Q, dtype=np.int64)
        for i, val in enumerate(v):
            for b in range(LOG_Q):
                bits[i * LOG_Q + b] = (int(val) >> b) & 1
        return bits

    @staticmethod
    def _sha_bits(element: str) -> np.ndarray:
        """SHA-256(element) → 256-bit vector."""
        digest = hashlib.sha256(element.encode()).digest()
        return np.unpackbits(np.frombuffer(digest, dtype=np.uint8)).astype(np.int64)

    # ── public hash functions ─────────────────────────────────────────────
    def hash_leaf(self, element: str) -> np.ndarray:
        """Map an arbitrary string to Z_q^n."""
        bits = self._sha_bits(element)                    # {0,1}^256
        return (self.A_leaf @ bits) % Q                   # Z_q^n

    def hash_pair(self, left: np.ndarray, right: np.ndarray) -> np.ndarray:
        """Compress two Z_q^n vectors into one (internal Merkle node)."""
        x = np.concatenate([self._bit_decompose(left),
                            self._bit_decompose(right)])  # {0,1}^m
        return (self.A @ x) % Q                           # Z_q^n

    def hash_node_to_int(self, v: np.ndarray) -> int:
        """Deterministic integer digest of a Z_q^n vector (for display)."""
        return int(hashlib.sha256(v.tobytes()).hexdigest()[:16], 16)


# ──────────────────────────────────────────────────────────────────────────────
# Proof data-classes
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class MembershipProof:
    """Authentication path: list of (sibling_hash, is_right) pairs."""
    element: str
    path: list[tuple[np.ndarray, bool]]


@dataclass
class NonMembershipProof:
    """
    Sorted-tree non-membership proof.

    boundary = 'left'   : element < all leaves  → only right neighbour supplied
    boundary = 'right'  : element > all leaves  → only left  neighbour supplied
    boundary = 'between': two adjacent leaves bracket the element
    """
    element: str
    boundary: str                            # 'left' | 'right' | 'between'
    left_proof: Optional[MembershipProof]    # None when boundary == 'left'
    right_proof: Optional[MembershipProof]   # None when boundary == 'right'
    left_index: Optional[int] = None
    right_index: Optional[int] = None
    num_leaves: int = 0                      # public tree size


# ──────────────────────────────────────────────────────────────────────────────
# Lattice Accumulator (Sorted Merkle Tree with SIS Hash)
# ──────────────────────────────────────────────────────────────────────────────
class LatticeAccumulator:
    """
    Merkle-tree accumulator using the SIS hash function.

    Elements are stored in sorted order so that non-membership proofs can
    exhibit two adjacent leaves that bracket the missing element.
    """

    ZERO = np.zeros(N_DIM, dtype=np.int64)

    def __init__(self, seed: int = 42):
        self.hasher = SISHash(seed)
        self.elements: list[str] = []
        self._leaves: list[np.ndarray] = []
        self._layers: list[list[np.ndarray]] = []
        self.acc: np.ndarray = self.ZERO.copy()
        self.num_leaves: int = 0          # actual elements (before padding)
        self._tree_size: int = 0          # padded to next power-of-two

    # ── tree construction ─────────────────────────────────────────────────

    def _next_pow2(self, n: int) -> int:
        s = 1
        while s < n:
            s <<= 1
        return s

    def _build_tree(self) -> None:
        n = len(self._leaves)
        self.num_leaves = n
        if n == 0:
            self.acc = self.ZERO.copy()
            self._layers = []
            return

        # pad to power of two with zero vectors
        self._tree_size = self._next_pow2(n)
        layer0 = list(self._leaves) + [self.ZERO.copy()] * (self._tree_size - n)

        self._layers = [layer0]
        current = layer0
        while len(current) > 1:
            parents = []
            for i in range(0, len(current), 2):
                parents.append(self.hasher.hash_pair(current[i], current[i + 1]))
            self._layers.append(parents)
            current = parents

        self.acc = current[0]

    # ── public API ────────────────────────────────────────────────────────

    def accumulate(self, elements: list[str]) -> np.ndarray:
        """Accumulate a set of elements (rebuilds the tree)."""
        self.elements = sorted(set(elements))
        self._leaves = [self.hasher.hash_leaf(e) for e in self.elements]
        self._build_tree()
        return self.acc

    def add(self, element: str) -> np.ndarray:
        """Insert a single element (maintains sorted order, rebuilds tree)."""
        if element not in self.elements:
            bisect.insort(self.elements, element)
            self._leaves = [self.hasher.hash_leaf(e) for e in self.elements]
            self._build_tree()
        return self.acc

    # ── membership proof ──────────────────────────────────────────────────

    def prove_membership(self, element: str) -> MembershipProof:
        if element not in self.elements:
            raise ValueError(f"'{element}' is not in the accumulator")

        idx = self.elements.index(element)
        path: list[tuple[np.ndarray, bool]] = []

        cur = idx
        for layer in self._layers[:-1]:          # skip root layer
            sibling = cur ^ 1
            sib_hash = layer[sibling] if sibling < len(layer) else self.ZERO.copy()
            is_right = bool(cur & 1)             # True if current node is the right child
            path.append((sib_hash, is_right))
            cur >>= 1

        return MembershipProof(element=element, path=path)

    def verify_membership(self, proof: MembershipProof) -> bool:
        """Verify a membership proof against the current accumulator value."""
        current = self.hasher.hash_leaf(proof.element)

        for sibling, is_right in proof.path:
            if is_right:
                current = self.hasher.hash_pair(sibling, current)
            else:
                current = self.hasher.hash_pair(current, sibling)

        return np.array_equal(current, self.acc)

    # ── non-membership proof ──────────────────────────────────────────────

    def prove_non_membership(self, element: str) -> NonMembershipProof:
        if element in self.elements:
            raise ValueError(f"'{element}' IS in the accumulator")
        if not self.elements:
            return NonMembershipProof(
                element=element, boundary="empty",
                left_proof=None, right_proof=None,
                num_leaves=0,
            )

        pos = bisect.bisect_left(self.elements, element)

        if pos == 0:
            rp = self.prove_membership(self.elements[0])
            return NonMembershipProof(
                element=element, boundary="left",
                left_proof=None, right_proof=rp,
                right_index=0, num_leaves=self.num_leaves,
            )
        elif pos == len(self.elements):
            lp = self.prove_membership(self.elements[-1])
            return NonMembershipProof(
                element=element, boundary="right",
                left_proof=lp, right_proof=None,
                left_index=len(self.elements) - 1,
                num_leaves=self.num_leaves,
            )
        else:
            lp = self.prove_membership(self.elements[pos - 1])
            rp = self.prove_membership(self.elements[pos])
            return NonMembershipProof(
                element=element, boundary="between",
                left_proof=lp, right_proof=rp,
                left_index=pos - 1, right_index=pos,
                num_leaves=self.num_leaves,
            )

    def verify_non_membership(self, proof: NonMembershipProof) -> bool:
        """
        Verify non-membership:
          1. The boundary elements are valid members.
          2. They are adjacent in the sorted leaf list.
          3. The target element falls strictly between them in sort order.
        """
        el = proof.element

        if proof.boundary == "empty":
            # Accumulator is empty → nothing is a member.
            return np.array_equal(self.acc, self.ZERO)

        if proof.boundary == "left":
            if proof.right_proof is None:
                return False
            right_el = proof.right_proof.element
            # Target must sort before the first element
            if not (el < right_el):
                return False
            # First element must be at index 0
            if proof.right_index != 0:
                return False
            return self.verify_membership(proof.right_proof)

        if proof.boundary == "right":
            if proof.left_proof is None:
                return False
            left_el = proof.left_proof.element
            if not (left_el < el):
                return False
            if proof.left_index != proof.num_leaves - 1:
                return False
            return self.verify_membership(proof.left_proof)

        # 'between'
        if proof.left_proof is None or proof.right_proof is None:
            return False
        left_el = proof.left_proof.element
        right_el = proof.right_proof.element
        # Ordering check
        if not (left_el < el < right_el):
            return False
        # Adjacency check
        if proof.right_index != proof.left_index + 1:
            return False
        # Both must be valid members
        return (self.verify_membership(proof.left_proof)
                and self.verify_membership(proof.right_proof))


# ──────────────────────────────────────────────────────────────────────────────
# Demo
# ──────────────────────────────────────────────────────────────────────────────
def _fmt(v: np.ndarray) -> str:
    """Compact display of a Z_q^n vector."""
    return "[" + " ".join(str(x) for x in v[:6]) + " ...]"


def main():
    print("=" * 64)
    print("Lattice-Based (SIS) Accumulator Demo")
    print("=" * 64)
    print(f"Parameters:  n={N_DIM},  q={Q},  log_q={LOG_Q},  m={M_DIM}")
    print()

    acc = LatticeAccumulator(seed=0)

    elements = ["alice", "bob", "charlie", "dave", "eve"]
    acc.accumulate(elements)
    print(f"Accumulated {len(elements)} elements (sorted): {acc.elements}")
    print(f"Accumulator (root):  {_fmt(acc.acc)}")
    print(f"Tree leaves (padded): {acc._tree_size}    "
          f"Tree depth: {len(acc._layers) - 1}")
    print()

    # ── Membership proofs ─────────────────────────────────────────────────
    print("-" * 48)
    print("Membership Proofs")
    print("-" * 48)
    for el in elements:
        proof = acc.prove_membership(el)
        valid = acc.verify_membership(proof)
        print(f"  {el:>10}  |  path len {len(proof.path)}  |  valid = {valid}")

    # ── Non-membership proofs ─────────────────────────────────────────────
    print()
    print("-" * 48)
    print("Non-Membership Proofs")
    print("-" * 48)
    outsiders = ["aaa", "carol", "frank", "zara"]
    for el in outsiders:
        proof = acc.prove_non_membership(el)
        valid = acc.verify_non_membership(proof)
        left  = proof.left_proof.element  if proof.left_proof  else "—"
        right = proof.right_proof.element if proof.right_proof else "—"
        print(f"  {el:>10}  |  boundary={proof.boundary:>7}  "
              f"|  neighbours=({left}, {right})  |  valid = {valid}")

    # ── Negative tests ────────────────────────────────────────────────────
    print()
    print("-" * 48)
    print("Negative Tests")
    print("-" * 48)

    # 1. Tamper with a membership proof (corrupt a sibling hash)
    proof = acc.prove_membership("alice")
    proof.path[0] = (np.ones(N_DIM, dtype=np.int64), proof.path[0][1])
    valid = acc.verify_membership(proof)
    print(f"  Tampered membership proof for 'alice'   ->  valid = {valid}  (expected False)")

    # 2. Try to pass off a non-member with a forged proof
    forged = acc.prove_non_membership("carol")
    # Swap the boundary type to trick the verifier
    forged.boundary = "left"
    forged.left_proof = None
    valid = acc.verify_non_membership(forged)
    print(f"  Forged non-membership for 'carol'       ->  valid = {valid}  (expected False)")

    # ── SIS hash collision resistance note ────────────────────────────────
    print()
    print("-" * 48)
    print("Security Note")
    print("-" * 48)
    print("  Collision resistance of the Merkle tree rests on the SIS")
    print("  assumption: finding short x₁ ≠ x₂ with A·x₁ ≡ A·x₂ (mod q)")
    print("  is as hard as worst-case SIVP on n-dimensional lattices.")
    print("  This is believed to hold even against quantum adversaries.")


# if __name__ == "__main__":
#     main()
