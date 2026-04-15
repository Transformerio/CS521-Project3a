"""
Pairing-Based (BLS-style) Accumulator
======================================

Construction
------------
Given bilinear groups (G₁, G₂, G_T) with pairing e: G₁ × G₂ → G_T:

  Setup (trusted):
      secret trapdoor  s ∈ Z_p
      public params    (g₁, g₁ˢ, g₁^{s²}, …, g₁^{sⁿ})  and  (g₂, g₂ˢ)

  Accumulate set S = {e₁, …, eₖ}:
      characteristic polynomial  χ_S(x) = ∏ᵢ (x + eᵢ)
      accumulator  acc = g₁^{χ_S(s)}

  Membership proof for eᵢ ∈ S:
      witness poly  wᵢ(x) = χ_S(x) / (x + eᵢ)
      witness       Wᵢ = g₁^{wᵢ(s)}
      verify:       e(Wᵢ, g₂^{s + eᵢ}) = e(acc, g₂)

  Non-membership proof for y ∉ S:
      poly division  χ_S(x) = q(x)·(x + y) + r,  r = χ_S(−y) ≠ 0
      proof          (Q = g₁^{q(s)},  r)
      verify:        e(Q, g₂^{s+y}) · e(g₁, g₂)^r = e(acc, g₂)

Implementation note
-------------------
We simulate the bilinear group algebraically: group elements are stored as
their discrete-log exponents relative to fixed generators, and the pairing
is exponent multiplication modulo the group order.  This is NOT
cryptographically secure (DLog is trivial), but the *protocol* is identical
to a real BN254 / BLS12-381 deployment, making the code a faithful
educational reference.

To upgrade to real curves, swap the BilinearGroup backend for py_ecc or
arkworks bindings — the accumulator logic above it stays unchanged.
"""

from __future__ import annotations

import random
import hashlib
from dataclasses import dataclass


# ──────────────────────────────────────────────────────────────────────────────
# Simulated bilinear group
# ──────────────────────────────────────────────────────────────────────────────

def _generate_prime(bits: int = 256) -> int:
    """Generate a random prime ≈ `bits` bits (Miller-Rabin)."""
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n

def _is_prime(n: int, k: int = 20) -> bool:
    if n < 2:   return False
    if n < 4:   return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


class G1:
    """Element of group G₁  (stored as exponent mod order)."""
    __slots__ = ('exp', 'order')

    def __init__(self, exp: int, order: int):
        self.exp = exp % order
        self.order = order

    # additive group notation: add = point addition, mul = scalar mult
    def __add__(self, other: G1) -> G1:
        return G1(self.exp + other.exp, self.order)

    def __mul__(self, scalar: int) -> G1:
        return G1(self.exp * scalar, self.order)

    def __rmul__(self, scalar: int) -> G1:
        return self.__mul__(scalar)

    def __neg__(self) -> G1:
        return G1(-self.exp, self.order)

    def __eq__(self, other) -> bool:
        return isinstance(other, G1) and self.exp % self.order == other.exp % self.order

    def __repr__(self) -> str:
        return f"G1({self.exp % self.order})"


class G2:
    """Element of group G₂  (stored as exponent mod order)."""
    __slots__ = ('exp', 'order')

    def __init__(self, exp: int, order: int):
        self.exp = exp % order
        self.order = order

    def __add__(self, other: G2) -> G2:
        return G2(self.exp + other.exp, self.order)

    def __mul__(self, scalar: int) -> G2:
        return G2(self.exp * scalar, self.order)

    def __rmul__(self, scalar: int) -> G2:
        return self.__mul__(scalar)

    def __neg__(self) -> G2:
        return G2(-self.exp, self.order)

    def __eq__(self, other) -> bool:
        return isinstance(other, G2) and self.exp % self.order == other.exp % self.order

    def __repr__(self) -> str:
        return f"G2({self.exp % self.order})"


class GT:
    """Element of target group G_T  (stored as exponent mod order)."""
    __slots__ = ('exp', 'order')

    def __init__(self, exp: int, order: int):
        self.exp = exp % order
        self.order = order

    def __mul__(self, other: GT) -> GT:
        """Multiplicative group operation in G_T."""
        return GT(self.exp + other.exp, self.order)

    def __eq__(self, other) -> bool:
        return isinstance(other, GT) and self.exp % self.order == other.exp % self.order

    def __repr__(self) -> str:
        return f"GT({self.exp % self.order})"


class BilinearGroup:
    """
    Simulated Type-III bilinear group (G₁, G₂, G_T, e).

    e(g₁^a, g₂^b) = g_T^{ab}   — the bilinearity property holds exactly.
    """

    def __init__(self, order: int | None = None):
        self.order = order or _generate_prime(128)
        self.g1 = G1(1, self.order)   # generator of G₁
        self.g2 = G2(1, self.order)   # generator of G₂

    def pair(self, p: G1, q: G2) -> GT:
        """Compute the bilinear pairing  e(P, Q) → G_T."""
        return GT(p.exp * q.exp, self.order)

    def g1_exp(self, scalar: int) -> G1:
        """g₁ ^ scalar."""
        return G1(scalar, self.order)

    def g2_exp(self, scalar: int) -> G2:
        """g₂ ^ scalar."""
        return G2(scalar, self.order)


# ──────────────────────────────────────────────────────────────────────────────
# Polynomial arithmetic over Z_p
# ─────────────────────────────────────────────────────────────────────────────

class Poly:
    """Polynomial over Z_p,  coeffs[i] = coefficient of x^i."""

    def __init__(self, coeffs: list[int], p: int):
        self.p = p
        self.coeffs = [c % p for c in coeffs]
        self._strip()

    def _strip(self):
        while len(self.coeffs) > 1 and self.coeffs[-1] == 0:
            self.coeffs.pop()

    @property
    def degree(self) -> int:
        return len(self.coeffs) - 1

    def eval(self, x: int) -> int:
        """Evaluate polynomial at x (Horner's method)."""
        result = 0
        for c in reversed(self.coeffs):
            result = (result * x + c) % self.p
        return result

    def __mul__(self, other: Poly) -> Poly:
        n = len(self.coeffs) + len(other.coeffs) - 1
        out = [0] * n
        for i, a in enumerate(self.coeffs):
            for j, b in enumerate(other.coeffs):
                out[i + j] = (out[i + j] + a * b) % self.p
        return Poly(out, self.p)

    def divmod(self, divisor: Poly) -> tuple[Poly, Poly]:
        """Polynomial division: self = quotient * divisor + remainder."""
        p = self.p
        num = list(self.coeffs)
        den = divisor.coeffs
        if len(den) == 0 or (len(den) == 1 and den[0] == 0):
            raise ZeroDivisionError
        deg_diff = len(num) - len(den)
        if deg_diff < 0:
            return Poly([0], p), Poly(num, p)

        quot = [0] * (deg_diff + 1)
        den_lead_inv = pow(den[-1], -1, p)

        for i in range(deg_diff, -1, -1):
            coeff = (num[i + len(den) - 1] * den_lead_inv) % p
            quot[i] = coeff
            for j in range(len(den)):
                num[i + j] = (num[i + j] - coeff * den[j]) % p

        return Poly(quot, p), Poly(num[:len(den) - 1], p)

    def __repr__(self) -> str:
        terms = []
        for i, c in enumerate(self.coeffs):
            if c == 0:
                continue
            if i == 0:
                terms.append(str(c))
            elif i == 1:
                terms.append(f"{c}x")
            else:
                terms.append(f"{c}x^{i}")
        return " + ".join(terms) if terms else "0"


# ──────────────────────────────────────────────────────────────────────────────
# Trusted setup (SRS / structured reference string)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SRS:
    """Structured Reference String (powers of s in G₁ and G₂)."""
    g1_powers: list[G1]   # [g₁, g₁ˢ, g₁^{s²}, …, g₁^{sⁿ}]
    g2_s: G2              # g₂ˢ
    g2: G2                # g₂
    g1: G1                # g₁
    max_degree: int


def trusted_setup(bg: BilinearGroup, max_elements: int) -> tuple[SRS, int]:
    """
    Generate the SRS.  Returns (srs, trapdoor_s).

    In production the trapdoor is destroyed after the ceremony.
    We keep it here only for testing.
    """
    s = random.randrange(1, bg.order)
    g1_powers = [bg.g1_exp(pow(s, i, bg.order)) for i in range(max_elements + 1)]
    g2_s = bg.g2_exp(s)
    return SRS(
        g1_powers=g1_powers,
        g2_s=g2_s,
        g2=bg.g2,
        g1=bg.g1,
        max_degree=max_elements,
    ), s


# ──────────────────────────────────────────────────────────────────────────────
# Commit a polynomial using the SRS  (KZG-style)
# ──────────────────────────────────────────────────────────────────────────────

def poly_commit(poly: Poly, srs: SRS) -> G1:
    """Compute [f(s)]₁ = ∑ᵢ cᵢ · [sⁱ]₁  using the SRS."""
    if poly.degree > srs.max_degree:
        raise ValueError("Polynomial degree exceeds SRS size")
    result = G1(0, srs.g1.order)
    for i, c in enumerate(poly.coeffs):
        result = result + srs.g1_powers[i] * c
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Element mapping
# ──────────────────────────────────────────────────────────────────────────────

def hash_to_field(element: str, order: int) -> int:
    """Map an element to a non-zero field element in Z_p*."""
    h = hashlib.sha256(element.encode()).digest()
    val = int.from_bytes(h, 'big') % (order - 1) + 1
    return val


# ──────────────────────────────────────────────────────────────────────────────
# Pairing-based accumulator
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MembershipProof:
    element: str
    field_elem: int
    witness: G1           # g₁^{wᵢ(s)}


@dataclass
class NonMembershipProof:
    element: str
    field_elem: int
    quotient: G1          # g₁^{q(s)}
    remainder: int        # r = χ_S(−y)


class PairingAccumulator:
    """
    Pairing-based (BLS-style) accumulator.

    Accumulator value:   acc = g₁^{χ_S(s)}
    where χ_S(x) = ∏ᵢ (x + eᵢ)  is the characteristic polynomial of set S.
    """

    def __init__(self, max_elements: int = 64):
        self.bg = BilinearGroup()
        self.order = self.bg.order
        self.srs, self._trapdoor = trusted_setup(self.bg, max_elements)

        self.elements: list[str] = []
        self.field_elems: dict[str, int] = {}
        self.acc: G1 = self.srs.g1          # empty accumulator = g₁ (product of zero factors = 1)
        self._char_poly: Poly | None = None

    # ── helpers ───────────────────────────────────────────────────────────

    def _elem(self, element: str) -> int:
        if element not in self.field_elems:
            self.field_elems[element] = hash_to_field(element, self.order)
        return self.field_elems[element]

    def _build_char_poly(self) -> Poly:
        """Build χ_S(x) = ∏ᵢ (x + eᵢ)."""
        p = self.order
        poly = Poly([1], p)   # start with constant 1
        for e in self.elements:
            ei = self._elem(e)
            factor = Poly([ei, 1], p)   # (x + eᵢ)  → coefficients [eᵢ, 1]
            poly = poly * factor
        return poly

    # ── accumulation ──────────────────────────────────────────────────────

    def accumulate(self, elements: list[str]) -> G1:
        """Accumulate a set of elements (rebuilds from scratch)."""
        self.elements = list(set(elements))
        for e in self.elements:
            self._elem(e)
        self._char_poly = self._build_char_poly()
        self.acc = poly_commit(self._char_poly, self.srs)
        return self.acc

    def add(self, element: str) -> G1:
        """Add a single element."""
        if element not in self.elements:
            self.elements.append(element)
            self._elem(element)
            self._char_poly = self._build_char_poly()
            self.acc = poly_commit(self._char_poly, self.srs)
        return self.acc

    # ── membership proof ──────────────────────────────────────────────────

    def prove_membership(self, element: str) -> MembershipProof:
        """
        Membership proof: witness Wᵢ = g₁^{wᵢ(s)}
        where wᵢ(x) = χ_S(x) / (x + eᵢ)
        """
        if element not in self.elements:
            raise ValueError(f"'{element}' is not in the accumulator")

        ei = self._elem(element)
        divisor = Poly([ei, 1], self.order)       # (x + eᵢ)
        quotient, remainder = self._char_poly.divmod(divisor)

        assert remainder.eval(0) == 0, "Division should be exact for a member"

        witness = poly_commit(quotient, self.srs)
        return MembershipProof(element=element, field_elem=ei, witness=witness)

    def verify_membership(self, proof: MembershipProof) -> bool:
        """
        Verify:  e(Wᵢ, g₂^{s + eᵢ}) = e(acc, g₂)

        i.e.  e(Wᵢ,  [s]₂ + eᵢ·[1]₂)  =  e(acc, [1]₂)
        """
        ei = proof.field_elem

        # g₂^{s + eᵢ}  =  g₂ˢ + eᵢ · g₂
        g2_s_plus_ei = self.srs.g2_s + self.srs.g2 * ei

        lhs = self.bg.pair(proof.witness, g2_s_plus_ei)
        rhs = self.bg.pair(self.acc, self.srs.g2)

        return lhs == rhs

    # ── non-membership proof ──────────────────────────────────────────────

    def prove_non_membership(self, element: str) -> NonMembershipProof:
        """
        Non-membership proof via polynomial division with remainder.

        χ_S(x) = q(x) · (x + y) + r,   where r = χ_S(−y) ≠ 0

        Proof = (Q = g₁^{q(s)},  r)
        """
        if element in self.elements:
            raise ValueError(f"'{element}' IS in the accumulator")

        y = self._elem(element)
        divisor = Poly([y, 1], self.order)         # (x + y)
        quotient, remainder = self._char_poly.divmod(divisor)

        r = remainder.eval(0)   # remainder is a constant
        assert r != 0, "Remainder should be non-zero for a non-member"

        Q = poly_commit(quotient, self.srs)
        return NonMembershipProof(element=element, field_elem=y, quotient=Q, remainder=r)

    def verify_non_membership(self, proof: NonMembershipProof) -> bool:
        """
        Verify:  e(Q, g₂^{s+y}) · e(g₁^r, g₂) = e(acc, g₂)

        Expanding:
            e(g₁,g₂)^{q(s)·(s+y)}  ·  e(g₁,g₂)^r
          = e(g₁,g₂)^{q(s)(s+y) + r}
          = e(g₁,g₂)^{χ_S(s)}
          = e(acc, g₂)
        """
        y = proof.field_elem
        r = proof.remainder

        # g₂^{s + y}
        g2_s_plus_y = self.srs.g2_s + self.srs.g2 * y

        # g₁^r
        g1_r = self.srs.g1 * r

        # LHS = e(Q, g₂^{s+y}) · e(g₁^r, g₂)
        lhs_1 = self.bg.pair(proof.quotient, g2_s_plus_y)
        lhs_2 = self.bg.pair(g1_r, self.srs.g2)
        lhs = lhs_1 * lhs_2

        # RHS = e(acc, g₂)
        rhs = self.bg.pair(self.acc, self.srs.g2)

        return lhs == rhs


# ──────────────────────────────────────────────────────────────────────────────
# Demo
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 64)
    print("Pairing-Based (BLS) Accumulator Demo")
    print("=" * 64)

    acc = PairingAccumulator(max_elements=32)
    print(f"\nBilinear group order:  {acc.order}")
    print(f"SRS max degree:        {acc.srs.max_degree}")
    print()

    # ── Accumulate elements ────────────────────────────────────────────
    elements = ["alice", "bob", "charlie", "dave"]
    acc.accumulate(elements)
    print(f"Accumulated: {elements}")
    print(f"Accumulator (acc):  {acc.acc}")
    print()

    # ── Show field element mappings ────────────────────────────────────
    print("-" * 48)
    print("Element → Field element mapping")
    print("-" * 48)
    for e in elements + ["eve", "mallory"]:
        fe = acc._elem(e)
        tag = "  ← in set" if e in elements else ""
        print(f"  {e:>10}  →  {fe}{tag}")
    print()

    # ── Show characteristic polynomial ─────────────────────────────────
    print("-" * 48)
    print("Characteristic polynomial")
    print("-" * 48)
    print(f"  χ_S(x) = ∏ (x + eᵢ)")
    print(f"  degree = {acc._char_poly.degree}")
    print()

    # ── Membership proofs ─────────────────────────────────────────────
    print("-" * 48)
    print("Membership Proofs")
    print("-" * 48)
    for el in elements:
        proof = acc.prove_membership(el)
        valid = acc.verify_membership(proof)
        print(f"  {el:>10}  |  witness = {proof.witness}  |  valid = {valid}")

    # ── Non-membership proofs ──────────────────────────────────────────
    print()
    print("-" * 48)
    print("Non-Membership Proofs")
    print("-" * 48)
    outsiders = ["eve", "mallory", "frank"]
    for el in outsiders:
        proof = acc.prove_non_membership(el)
        valid = acc.verify_non_membership(proof)
        print(f"  {el:>10}  |  Q = {proof.quotient}  r = {proof.remainder}  |  valid = {valid}")

    # ── Negative tests ─────────────────────────────────────────────────
    print()
    print("-" * 48)
    print("Negative Tests")
    print("-" * 48)

    # 1. Tampered membership witness
    proof = acc.prove_membership("alice")
    tampered = MembershipProof(
        element="alice",
        field_elem=proof.field_elem,
        witness=proof.witness + acc.srs.g1   # corrupt the witness
    )
    valid = acc.verify_membership(tampered)
    print(f"  Tampered witness for 'alice'         →  valid = {valid}  (expected False)")

    # 2. Try to fake a membership proof for a non-member
    eve_fe = acc._elem("eve")
    fake_witness = acc.srs.g1 * random.randrange(1, acc.order)
    fake_proof = MembershipProof(element="eve", field_elem=eve_fe, witness=fake_witness)
    valid = acc.verify_membership(fake_proof)
    print(f"  Fake membership proof for 'eve'      →  valid = {valid}  (expected False)")

    # 3. Tampered non-membership remainder
    proof_nm = acc.prove_non_membership("eve")
    tampered_nm = NonMembershipProof(
        element="eve",
        field_elem=proof_nm.field_elem,
        quotient=proof_nm.quotient,
        remainder=proof_nm.remainder + 1  # corrupt remainder
    )
    valid = acc.verify_non_membership(tampered_nm)
    print(f"  Tampered non-membership for 'eve'    →  valid = {valid}  (expected False)")

    # ── Verification equation walkthrough ──────────────────────────────
    print()
    print("-" * 48)
    print("Verification Equations")
    print("-" * 48)
    print()
    print("  MEMBERSHIP:   e(Wᵢ, g₂^{s+eᵢ}) = e(acc, g₂)")
    print("     Wᵢ = g₁^{χ_S(s)/(s+eᵢ)}")
    print("     ⇒ e(g₁,g₂)^{χ_S(s)/(s+eᵢ) · (s+eᵢ)} = e(g₁,g₂)^{χ_S(s)}  ✓")
    print()
    print("  NON-MEMBERSHIP:  e(Q, g₂^{s+y}) · e(g₁^r, g₂) = e(acc, g₂)")
    print("     χ_S(x) = q(x)·(x+y) + r,   r ≠ 0")
    print("     ⇒ e(g₁,g₂)^{q(s)(s+y) + r} = e(g₁,g₂)^{χ_S(s)}  ✓")
    print()
    print("  Security rests on the q-SDH assumption in bilinear groups.")


if __name__ == "__main__":
    main()
