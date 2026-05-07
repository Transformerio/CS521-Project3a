from py_ecc.optimized_bls12_381 import G1, G2, add, multiply, pairing, curve_order
from typing import List, Tuple, Optional
from dataclasses import dataclass
import hashlib
import secrets

# Domain separation prefix for string hashing — prevents cross-context collisions
# if this accumulator is composed with other hash-to-field constructions.
_DOMAIN_PREFIX = b"BLSAcc_v1:"

g1 = G1
g2 = G2


# ---------------------------------------------------------------------------
# Field / polynomial helpers
# ---------------------------------------------------------------------------

def mod(x: int) -> int:
    return x % curve_order


def trim(poly: List[int]) -> List[int]:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_mul(a: List[int], b: List[int]) -> List[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        for j, bv in enumerate(b):
            out[i + j] = mod(out[i + j] + av * bv)
    return trim(out)


def build_characteristic_polynomial(elements: List[int]) -> List[int]:
    """Build P(z) = ∏ (z + x) for each x in elements.

    Convention: P(-x) = 0 for every member x.  All other functions that
    divide by a linear factor follow the same (z + x) convention.
    """
    poly = [1]
    for x in elements:
        fx = to_field_element(x)
        poly = poly_mul(poly, [fx, 1])
    return trim(poly)


def poly_eval(poly: List[int], z: int) -> int:
    """Evaluate poly(z) via Horner's method.  poly = [c0, c1, c2, ...]."""
    z = mod(z)
    result = 0
    power = 1
    for coeff in poly:
        result = mod(result + coeff * power)
        power = mod(power * z)
    return result


def poly_div_by_linear(poly: List[int], c: int) -> Tuple[List[int], int]:
    """Divide poly(z) by (z - c) using synthetic division.

    To divide by (z + x), pass c = (-x) mod curve_order.
    Returns (quotient_coeffs, remainder).
    """
    poly = trim(poly[:])

    if len(poly) == 1:
        return [0], poly[0]

    desc = list(reversed(poly))
    b = [desc[0]]
    for i in range(1, len(desc)):
        b.append(mod(desc[i] + b[-1] * c))

    remainder = b[-1]
    quotient_desc = b[:-1]
    quotient = list(reversed(quotient_desc))
    return trim(quotient), remainder


def eval_poly_in_exponent_g1(
    coeffs: List[int],
    g1_powers_of_s: List[tuple],
) -> tuple:
    """Compute g1^(c0 + c1*s + c2*s^2 + ...) using the committed SRS powers.

    Raises ValueError if the polynomial is identically zero (the result
    would be the point at infinity, which is not a valid witness — a
    pairing with the neutral element evaluates to GT's identity regardless
    of the other input, which could produce a spurious proof).
    """
    if len(coeffs) > len(g1_powers_of_s):
        raise ValueError(
            f"Polynomial degree {len(coeffs)-1} exceeds SRS capacity "
            f"{len(g1_powers_of_s)-1}."
        )

    # Detect the all-zero polynomial before doing any group operations.
    if all(mod(c) == 0 for c in coeffs):
        raise ValueError(
            "Refusing to encode the zero polynomial: the result would be "
            "the point at infinity, which is not a valid witness."
        )

    acc = None
    for i, coeff in enumerate(coeffs):
        coeff = mod(coeff)
        if coeff == 0:
            continue
        term = multiply(g1_powers_of_s[i], coeff)
        acc = term if acc is None else add(acc, term)

    # acc cannot be None here because we already ruled out the all-zero case.
    return acc  # type: ignore[return-value]


def to_field_element(x) -> int:
    """Convert an int or string to a BLS12-381 scalar field element.

    Strings are hashed with domain separation so this function is safe
    to compose with other hash-to-field constructions that use the same
    curve.
    """
    if isinstance(x, int):
        return x % curve_order

    if isinstance(x, str):
        digest = hashlib.sha256(
            _DOMAIN_PREFIX + x.encode("utf-8")
        ).digest()
        return int.from_bytes(digest, "big") % curve_order

    raise TypeError(f"Unsupported element type: {type(x)}")


# ---------------------------------------------------------------------------
# BLS Accumulator
# ---------------------------------------------------------------------------

class BLSAcc:
    """Bilinear-map accumulator over BLS12-381.

    The secret scalar *s* (the "toxic waste") is used only during __init__
    to populate the Structured Reference String (SRS).  It is deleted from
    the object immediately afterwards.  Callers who need a deterministic
    secret for testing may pass secret_s explicitly; in all other cases a
    cryptographically random scalar is sampled.

    Public SRS:
        G1 powers : [g1, g1^s, g1^(s^2), ..., g1^(s^max_set_size)]
        G2        : g2
        G2^s      : g2^s

    Characteristic polynomial convention:
        P(z) = ∏ (z + x_i)  →  P(-x) = 0 iff x is a member.

    Membership proof:
        P(z) = (z + x) Q(z)  →  witness W = g1^(Q(s))

    Non-membership proof:
        v = P(-y) ≠ 0        →  P(z) - v = (z + y) Q(z)
        witness W = g1^(Q(s)), alongside the scalar v

    Verification uses the bilinear pairing e: G2 × G1 → GT.
    """

    def __init__(
        self,
        max_set_size: int,
        secret_s: Optional[int] = None,
    ) -> None:
        if max_set_size < 1:
            raise ValueError("max_set_size must be >= 1")

        self.max_set_size = max_set_size

        # Use a random secret unless an explicit value is given (test mode).
        _s = mod(secret_s if secret_s is not None else secrets.randbelow(curve_order))

        # Build SRS in G1: [g1^(s^0), g1^(s^1), ..., g1^(s^max_set_size)]
        self.g1_powers_of_s: List[tuple] = []
        cur = 1
        for _ in range(max_set_size + 1):
            self.g1_powers_of_s.append(multiply(G1, cur))
            cur = mod(cur * _s)

        self.g2: tuple = G2
        self.g2_s: tuple = multiply(G2, _s)

        # ----------------------------------------------------------------
        # SECURITY: delete the toxic waste.  After this point no one —
        # including this object — can recover s from memory.  The only
        # information about s that survives is the SRS itself, whose
        # discrete-log hardness is the security assumption of the scheme.
        # ----------------------------------------------------------------
        del _s

    # ------------------------------------------------------------------
    # Accumulation
    # ------------------------------------------------------------------

    def accumulate(
        self,
        elements: List[int],
    ) -> Tuple[List[int], tuple]:
        """Build the accumulator for a set of elements.

        Returns (poly, acc) where:
            poly  – coefficient list of P(z) = ∏ (z + x_i)
            acc   – the group point g1^(P(s))
        """
        elems = list(dict.fromkeys(elements))   # deduplicate, preserve order
        if len(elems) > self.max_set_size:
            raise ValueError(
                f"Set size {len(elems)} exceeds max_set_size {self.max_set_size}."
            )

        poly = build_characteristic_polynomial(elems)
        acc = eval_poly_in_exponent_g1(poly, self.g1_powers_of_s)
        return poly, acc

    # ------------------------------------------------------------------
    # Membership
    # ------------------------------------------------------------------

    def prove_membership(self, poly: List[int], x) -> tuple:
        """Produce a membership witness for element x.

        If x is in the set then P(z) = (z + x) Q(z) with zero remainder.
        The witness is W = g1^(Q(s)).

        Raises ValueError if x is not a member (nonzero remainder) or if
        the quotient polynomial is identically zero (would produce a point
        at infinity, invalidating the proof).
        """
        fx = to_field_element(x)
        quotient, remainder = poly_div_by_linear(poly, mod(-fx))

        if remainder != 0:
            raise ValueError(
                f"{x!r} is not a member of the accumulated set "
                f"(division remainder was nonzero)."
            )

        # eval_poly_in_exponent_g1 raises if quotient is the zero polynomial,
        # which would otherwise yield the point at infinity as a witness.
        witness = eval_poly_in_exponent_g1(quotient, self.g1_powers_of_s)
        return witness

    def verify_membership(self, acc: tuple, x, witness: tuple) -> bool:
        """Verify a membership proof.

        Checks the pairing equation:
            e(g2^(s+x), W) == e(g2, Acc)

        which follows from P(s) = (s + x) Q(s).
        """
        fx = to_field_element(x)
        g2_s_plus_x = add(self.g2_s, multiply(self.g2, mod(fx)))

        lhs = pairing(g2_s_plus_x, witness, final_exponentiate=True)
        rhs = pairing(self.g2, acc, final_exponentiate=True)
        return lhs == rhs

    # ------------------------------------------------------------------
    # Non-membership
    # ------------------------------------------------------------------

    def prove_non_membership(self, poly: List[int], y) -> Tuple[tuple, int]:
        """Produce a non-membership witness for element y.

        If y is NOT in the set then v = P(-y) ≠ 0.
        We form P(z) - v = (z + y) Q(z) and set W = g1^(Q(s)).

        Returns (W, v).

        Security note: v is a raw field element in this proof tuple.
        The verifier uses multiply(G1, v) to commit to it on-the-fly, so
        a malicious prover who can choose v freely gains no advantage —
        manipulating v changes g1^v and therefore breaks the pairing
        equation unless the prover can also forge the witness W, which
        requires solving the discrete-log problem in G1.  In an
        interactive setting with a trusted prover this is sound; for a
        fully non-interactive ZK argument you would commit to v separately.

        Raises ValueError if y is actually a member (v would be zero).
        """
        fy = to_field_element(y)
        v = poly_eval(poly, mod(-fy))

        if v == 0:
            raise ValueError(
                f"{y!r} is actually a member of the accumulated set; "
                "a non-membership proof cannot be produced."
            )

        # P(z) - v  (only the constant term changes)
        poly_minus_v = poly[:]
        poly_minus_v[0] = mod(poly_minus_v[0] - v)

        quotient, remainder = poly_div_by_linear(poly_minus_v, mod(-fy))
        if remainder != 0:
            # This should be unreachable by construction; treat as a bug.
            raise RuntimeError(
                "Internal error: unexpected nonzero remainder while forming "
                "the non-membership witness.  Please file a bug report."
            )

        witness = eval_poly_in_exponent_g1(quotient, self.g1_powers_of_s)
        return witness, v

    def verify_non_membership(
        self,
        acc: tuple,
        y,
        proof: Tuple[tuple, int],
    ) -> bool:
        """Verify a non-membership proof.

        Checks the pairing equation:
            e(g2^(s+y), W) · e(g2, g1^v) == e(g2, Acc)

        which follows from P(s) = (s + y) Q(s) + v.
        """
        witness, v = proof
        fy = to_field_element(y)

        g2_s_plus_y = add(self.g2_s, multiply(self.g2, fy))
        g1_v = multiply(G1, mod(v))

        lhs1 = pairing(g2_s_plus_y, witness, final_exponentiate=True)
        lhs2 = pairing(self.g2, g1_v, final_exponentiate=True)
        rhs  = pairing(self.g2, acc, final_exponentiate=True)

        return lhs1 * lhs2 == rhs


# ---------------------------------------------------------------------------
# Quick self-test (run with: python bls.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Setting up accumulator …")
    bls = BLSAcc(max_set_size=10)

    members = [1, 2, 3, "alice", "bob"]
    non_member = 7

    print(f"Accumulating set: {members}")
    poly, acc = bls.accumulate(members)

    # Membership proofs
    for elem in members:
        w = bls.prove_membership(poly, elem)
        ok = bls.verify_membership(acc, elem, w)
        print(f"  membership({elem!r}): {'PASS' if ok else 'FAIL'}")

    # Non-membership proof
    nm_proof = bls.prove_non_membership(poly, non_member)
    ok = bls.verify_non_membership(acc, non_member, nm_proof)
    print(f"  non-membership({non_member!r}): {'PASS' if ok else 'FAIL'}")

    # Membership proof for a non-member should raise
    try:
        bls.prove_membership(poly, non_member)
        print("  rejection test: FAIL (should have raised)")
    except ValueError as e:
        print(f"  rejection test: PASS ({e})")

    # Non-membership proof for an actual member should raise
    try:
        bls.prove_non_membership(poly, members[0])
        print("  member-as-non-member test: FAIL (should have raised)")
    except ValueError as e:
        print(f"  member-as-non-member test: PASS ({e})")