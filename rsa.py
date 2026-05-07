"""
RSA Accumulator with Membership and Non-Membership Proofs

Setup: Generate RSA modulus N = p * q (trusted setup).
Accumulate: acc = g^(product of prime reps) mod N
Membership proof: witness w such that w^e = acc mod N
Non-membership proof: Bezout coefficients (a, b) such that a*e + b*product = 1,
    then verify g^b * acc^a = acc' (Li-Li-Xue scheme)
"""

import random
import math
from hashlib import sha256


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def is_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
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


def generate_prime(bits: int) -> int:
    """Generate a random prime of approximately `bits` bits."""
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def extended_gcd(a: int, b: int):
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def hash_to_prime(element: bytes, bit_length: int = 128) -> int:
    """
    Deterministically map an arbitrary element to a prime number.
    Uses incremental hashing: H(element || nonce) until a prime is found.
    """
    nonce = 0
    while True:
        h = sha256(element + nonce.to_bytes(8, "big")).digest()
        candidate = int.from_bytes(h[:bit_length // 8], "big") | (1 << (bit_length - 1)) | 1
        if is_prime(candidate):
            return candidate
        nonce += 1


def _modpow(base: int, exp: int, mod: int) -> int:
    """pow(base, exp, mod) supporting negative exponents via modular inverse."""
    if exp < 0:
        base_inv = pow(base, -1, mod)
        return pow(base_inv, -exp, mod)
    return pow(base, exp, mod)


# ---------------------------------------------------------------------------
# RSA Accumulator
# ---------------------------------------------------------------------------

class RSAAccumulator:
    """
    RSA Accumulator supporting:
      - add / batch_add
      - membership proof  (witness)
      - non-membership proof (Bezout-based)
      - verification of both proof types
    """

    def __init__(self, bits: int = 1024):
        # Trusted setup: generate N = p * q
        half = bits // 2
        p = generate_prime(half)
        q = generate_prime(half)
        self.N = p * q

        # Pick a random generator in Z*_N
        self.g = random.randrange(2, self.N)
        while math.gcd(self.g, self.N) != 1:
            self.g = random.randrange(2, self.N)

        # Current accumulator value and set of accumulated prime representatives
        self.acc = self.g
        self.primes: dict[str, int] = {}  # element -> prime representative

    # ---- element ↔ prime mapping -----------------------------------------

    @staticmethod
    def _to_prime(element: str) -> int:
        """Deterministic map from element to a prime representative."""
        return hash_to_prime(element.encode())

    def _product_of_all(self) -> int:
        prod = 1
        for p in self.primes.values():
            prod *= p
        return prod

    # ---- accumulation -----------------------------------------------------

    def add(self, element: str) -> int:
        """Add a single element and return the new accumulator value."""
        e = self._to_prime(element)
        self.primes[element] = e
        self.acc = pow(self.acc, e, self.N)
        return self.acc

    def batch_add(self, elements: list[str]) -> int:
        """Add multiple elements at once."""
        for el in elements:
            self.add(el)
        return self.acc

    # ---- membership proof -------------------------------------------------

    def prove_membership(self, element: str) -> int:
        """
        Compute witness w = g^(product of all primes EXCEPT element's prime) mod N.
        Verifier checks: w^e ≡ acc (mod N).
        """
        e = self._to_prime(element)
        if element not in self.primes:
            raise ValueError(f"'{element}' is not in the accumulator")

        # Compute product of all primes except e
        exp = 1
        for el, p in self.primes.items():
            if el != element:
                exp *= p

        witness = pow(self.g, exp, self.N)
        return witness

    def verify_membership(self, element: str, witness: int) -> bool:
        """Verify that witness^e ≡ acc (mod N)."""
        e = self._to_prime(element)
        return pow(witness, e, self.N) == self.acc

    # ---- non-membership proof ---------------------------------------------
    def prove_non_membership(self, element: str):
        """
        Bézout non-membership proof.

        Extended GCD gives (g_val, a, b) satisfying:
            e·a  +  product·b  = 1          … (★)
        where
            e       = prime representative of the NON-member
            product = ∏ of prime reps of ALL accumulated elements

        Note the argument ORDER to extended_gcd:
            extended_gcd(e, product)  →  (g_val, a, b)
            meaning  e·a + product·b = 1

        *** Do NOT swap a and b — the identity is symmetric but the roles differ ***

        We publish:
            d = g^a  mod N          (uses 'a', the coefficient of e)
            b                       (the coefficient of product, i.e. of acc's exponent)

        Verification identity (derived from ★):
            d^e · acc^b
            = (g^a)^e · (g^product)^b
            = g^(a·e)  · g^(product·b)
            = g^(a·e + product·b)
            = g^1 = g                           ✓

        Both a and b may be negative → MUST use _modpow (not plain pow).
        """
        e = self._to_prime(element)
        if element in self.primes:
            raise ValueError(
                f"'{element}' IS in the accumulator; cannot prove non-membership"
            )

        product = self._product_of_all()

        # extended_gcd(e, product) → (gcd, coeff_of_e, coeff_of_product)
        g_val, a, b = extended_gcd(e, product)
        #              ↑  ↑  ↑
        #              │  │  └─ b : coefficient of product  → used as acc exponent
        #              │  └──── a : coefficient of e        → used to build d = g^a
        #              └─────── must equal 1 (distinct primes guarantee this)

        if g_val != 1:
            raise RuntimeError(
                "GCD != 1 — element shares a prime representative with an "
                "accumulated element (hash collision in hash_to_prime)"
            )

        # d = g^a mod N.  'a' can be negative → _modpow handles via modular inverse.
        d = _modpow(self.g, a, self.N)   # NOT pow() — pow() rejects negative exponents

        # Return (b, d):
        #   b  → will be used as the exponent of acc  in verification
        #   d  → precomputed g^a, will be raised to e in verification
        return b, d


    def verify_non_membership(self, element: str, proof: tuple[int, int]) -> bool:
        """
        Verify:  d^e · acc^b  ≡  g  (mod N)
    
        proof = (b, d)  where
            b  = Bézout coefficient of product  (exponent applied to acc)
            d  = g^a mod N                      (g raised to coeff of e, then raised to e)
    
        b may be negative → _modpow required for acc^b as well.
        """
        b, d = proof
        #  ↑  ↑
        #  │  └─ d = g^a;  raising to e gives g^(a·e)
        #  └──── b = coeff of product; acc^b = (g^product)^b = g^(product·b)
    
        e = self._to_prime(element)
    
        lhs = (pow(d, e, self.N) * _modpow(self.acc, b, self.N)) % self.N
        #       └─────────────┘   └────────────────────────────┘
        #         d^e = g^(a·e)      acc^b = g^(product·b)
        #       together: g^(a·e + product·b) = g^1 = g
    
        return lhs == self.g

    #def prove_non_membership(self, element: str):
    #    """
    #    Non-membership proof using Bezout coefficients.

    #    Since element is NOT in the set, gcd(e, product_of_all) = 1 (both are
    #    products of distinct primes and e is not among them).

    #    Find a, b such that  a*e + b*product = 1  (extended GCD).
    #    Return (a, b, d) where d = g^b mod N  (precomputed for the verifier).

    #    Verification:  d^e  *  acc^a  ≡  g  (mod N)
    #    """
    #    e = self._to_prime(element)
    #    if element in self.primes:
    #        raise ValueError(f"'{element}' IS in the accumulator; cannot prove non-membership")

    #    product = self._product_of_all()
    #    g_val, a, b = extended_gcd(e, product)
    #    # Bezout: a*e + b*product = 1

    #    if g_val != 1:
    #        raise RuntimeError("GCD != 1 — element may share a prime representative with an accumulated element")

    #    # Proof = (b, d) where d = g^a mod N
    #    # Verification: d^e * acc^b ≡ g (mod N)
    #    #   because d^e * acc^b = g^(a*e) * g^(product*b) = g^(a*e + b*product) = g^1 = g
    #    d = _modpow(self.g, a, self.N)

    #    return b, d

    #def verify_non_membership(self, element: str, proof: tuple[int, int]) -> bool:
    #    """
    #    Verify non-membership.

    #    Given proof = (b, d) where d = g^a:
    #        check  d^e  *  acc^b  ≡  g  (mod N)
    #    """
    #    b, d = proof
    #    e = self._to_prime(element)

    #    lhs = (pow(d, e, self.N) * _modpow(self.acc, b, self.N)) % self.N
    #    return lhs == self.g


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("RSA Accumulator Demo")
    print("=" * 60)

    acc = RSAAccumulator(bits=1024)

    # Accumulate some elements
    elements = ["alice", "bob", "charlie", "dave"]
    acc.batch_add(elements)
    print(f"\nAccumulated elements: {elements}")
    print(f"Accumulator value:    {acc.acc % (10**40)}...  (truncated)\n")

    # --- Membership proofs ---
    print("-" * 40)
    print("Membership Proofs")
    print("-" * 40)
    for el in elements:
        witness = acc.prove_membership(el)
        valid = acc.verify_membership(el, witness)
        print(f"  {el:>10}  ->  valid = {valid}")

    # --- Non-membership proof ---
    print("\n" + "-" * 40)
    print("Non-Membership Proofs")
    print("-" * 40)
    outsiders = ["eve", "mallory"]
    for el in outsiders:
        proof = acc.prove_non_membership(el)
        valid = acc.verify_non_membership(el, proof)
        print(f"  {el:>10}  ->  valid = {valid}")

    # --- Negative test: fake membership ---
    print("\n" + "-" * 40)
    print("Negative Tests")
    print("-" * 40)
    fake_witness = random.randrange(2, acc.N)
    valid = acc.verify_membership("eve", fake_witness)
    print(f"  Fake witness for 'eve'  ->  valid = {valid}  (expected False)")


if __name__ == "__main__":
    main()
