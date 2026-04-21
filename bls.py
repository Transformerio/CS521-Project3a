from py_ecc.optimized_bls12_381 import G1, G2, add, multiply, pairing, curve_order
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple
import hashlib

g1 = G1
g2 = G2

def mod(x: int) -> int:
    return x % curve_order

def trim(poly: list[int]) -> list[int]:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly

def poly_mul(a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        for j, bv in enumerate(b):
            out[i + j] = mod(out[i + j] + av * bv)
    return trim(out)

def build_characteristic_polynomial(elements: list[int]) -> list[int]:
    # Build: P(z) = ∏ (z + x)
    poly = [1]
    for x in elements:
        fx = to_field_element(x)
        poly = poly_mul(poly, [fx, 1])

    return trim(poly)
def poly_eval(poly: list[int], z: int) -> int:
    # Evaluate poly(z) where poly = [c0, c1, c2, ...]
    z = mod(z)
    result = 0
    power = 1
    for coeff in poly:
        result = mod(result + coeff * power)
        power = mod(power * z)
    return result

def poly_div_by_linear(poly: list[int], c: int) -> tuple[list[int], int]:
    # Divide poly(z) by (z - c) using synthetic division
    # To divide by (z + x), use c = -x mod curve_order
    poly = trim(poly[:])

    if len(poly) == 1:
        return [0], poly[0]

    # Reverse to descending order for synthetic division
    desc = list(reversed(poly))
    b = [desc[0]]

    for i in range(1, len(desc)):
        b.append(mod(desc[i] + b[-1] * c))

    remainder = b[-1]
    quotient_desc = b[:-1]
    quotient = list(reversed(quotient_desc))
    return trim(quotient), remainder

def eval_poly_in_exponent_g1(coeffs: list[int], g1_powers_of_s: list[tuple]) -> tuple:
    # coeffs = [c0, c1, c2, ...]
    # srs points = [g1^(s^0), g1^(s^1), g1^(s^2), ...]
    # result -> g1^(c0 + c1*s + c2*s^2 + ...)

    if len(coeffs) > len(g1_powers_of_s):
        raise ValueError("Polynomial degree exceeds setup capacity")

    acc = None
    for i, coeff in enumerate(coeffs):
        coeff = mod(coeff)
        if coeff == 0:
            continue
        term = multiply(g1_powers_of_s[i], coeff)
        acc = term if acc is None else add(acc, term)

    if acc is None:
        return multiply(G1, 0)  # point at infinity

    return acc

def to_field_element(x) -> int:
    # Converts int/strings to standard elements
    if isinstance(x, int):
        return x % curve_order

    if isinstance(x, str):
        digest = hashlib.sha256(x.encode("utf-8")).digest()
        return int.from_bytes(digest, "big") % curve_order

    raise TypeError(f"Unsupported element type: {type(x)}")
class BLSAcc:
    def __init__(self, max_set_size: int, secret_s: int = 5):
        # uses a fixed secret s
        # Publishes:
        #     g1^(1), g1^(s), g1^(s^2), ...
        #     g2
        #     g2^s

        if max_set_size < 1:
            raise ValueError("max_set_size must be >= 1")

        self.max_set_size = max_set_size
        self.s = mod(secret_s)

        # Build SRS in G1: [g1^(s^0), g1^(s^1), ..., g1^(s^max_set_size)]
        self.g1_powers_of_s = []
        cur = 1
        for _ in range(max_set_size + 1):
            self.g1_powers_of_s.append(multiply(G1, cur))
            cur = mod(cur * self.s)

        self.g2 = G2
        self.g2_s = multiply(G2, self.s)
        

    def accumulate(self, elements: list[int]) -> tuple[list[int], tuple]:
        # P(z) = ∏ (z + x) = polynomial
        # Acc = g1^(P(s)) = accumulator_point
        elems = list(dict.fromkeys(elements))  # preserve order, remove duplicates
        if len(elems) > self.max_set_size:
            raise ValueError("Too many elements for this setup")

        poly = build_characteristic_polynomial(elems)
        acc = eval_poly_in_exponent_g1(poly, self.g1_powers_of_s)
        return poly, acc

    def prove_membership(self, poly: list[int], x: int) -> tuple:
        # If x is in the set then P(z) = (z + x)Q(z)
        # witness W = g1^(Q(s))

        fx = to_field_element(x)
        quotient, remainder = poly_div_by_linear(poly, mod(-fx))

        if remainder != 0:
            raise ValueError(f"{x!r} is not a member; remainder was nonzero")

        witness = eval_poly_in_exponent_g1(quotient, self.g1_powers_of_s)
        return witness

    def verify_membership(self, acc: tuple, x: int, witness: tuple) -> bool:
        # Verify that e(g2^(s+x), witness) == e(g2, acc)
        # Because of P(s) = (s + x)Q(s)
        
        fx = to_field_element(x)
        g2_s_plus_x = add(self.g2_s, multiply(self.g2, mod(fx)))

        left = pairing(g2_s_plus_x, witness, final_exponentiate=True)
        right = pairing(self.g2, acc, final_exponentiate=True)
        return left == right
    def prove_non_membership(self, poly: list[int], y: int) -> tuple:
        # If x is NOT in the set then P(z) = (z + x)Q(z) + v
        # where v = P(-y) != 0 for some potential factor y

        fy = to_field_element(y)
        v = poly_eval(poly, mod(-fy))
        if v == 0:
            raise ValueError(f"{y!r} is actually a member, so non-membership proof cannot be made")

        # P(z) - v = (z + y)Q(z)
        poly_minus_v = poly[:]
        poly_minus_v[0] = mod(poly_minus_v[0] - v)

        quotient, remainder = poly_div_by_linear(poly_minus_v, mod(-fy))
        if remainder != 0:
            raise ValueError("Unexpected nonzero remainder while forming non-membership witness")

        witness = eval_poly_in_exponent_g1(quotient, self.g1_powers_of_s)
        return (witness, v)
    def verify_non_membership(self, acc: tuple, y, proof) -> bool:
        """
        Verify:
            e(g2^(s+y), W) * e(g2, g1^v) == e(g2, acc)
        where proof = (W, v)
        """
        witness, v = proof
        fy = to_field_element(y)

        g2_s_plus_y = add(self.g2_s, multiply(self.g2, fy))
        g1_v = multiply(G1, mod(v))

        left1 = pairing(g2_s_plus_y, witness, final_exponentiate=True)
        left2 = pairing(self.g2, g1_v, final_exponentiate=True)
        right = pairing(self.g2, acc, final_exponentiate=True)

        return left1 * left2 == right


# Direct non-member proof attempt should fail
# try:
#     bls.prove_membership(poly, 7)
# except ValueError as e:
#     print("Non-member rejected correctly:", e)
