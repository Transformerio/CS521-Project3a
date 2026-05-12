from dataclasses import is_dataclass, fields
import mtree, bls, lattice, rsa
import time
import numpy as np
import sys 

def get_size(obj) -> int:
    if obj is None:
        return 0

    # Tuples/lists: recursively sum contents.
    if isinstance(obj, (tuple, list)):
        return sum(get_size(item) for item in obj)

    # Dicts: include keys and values.
    if isinstance(obj, dict):
        return sum(get_size(k) + get_size(v) for k, v in obj.items())

    # Integers: cryptographic size in bytes.
    if isinstance(obj, int):
        return (obj.bit_length() + 7) // 8

    # Strings: measure encoded byte length, not Python object overhead.
    if isinstance(obj, str):
        return len(obj.encode("utf-8"))

    # Bytes/bytearray: actual length.
    if isinstance(obj, (bytes, bytearray)):
        return len(obj)

    # NumPy arrays: actual backing buffer size.
    if isinstance(obj, np.ndarray):
        return obj.nbytes

    # Dataclasses: recursively inspect fields.
    # This is important for lattice MembershipProof / NonMembershipProof.
    if is_dataclass(obj):
        return sum(get_size(getattr(obj, f.name)) for f in fields(obj))

    # Fallback: Python object overhead.
    return sys.getsizeof(obj)

size = 10**2
np.random.seed(0)
elems = np.arange(size, dtype=np.int32)
np.random.shuffle(elems)
elems = elems.astype(str)

target = elems[np.random.randint(0, len(elems))]
nonTarget = "non"

def benchmark(label, acc_obj, m_proof_fn, m_verify_fn, nm_proof_fn, nm_verify_fn):
    print(f"[{label}] accumulator size = {get_size(acc_obj)} bytes")
    ts = time.time()
    proof = m_proof_fn()
    te = time.time()
    print(f"[{label}] member proof = {te - ts:.6f} s")
    print(f"[{label}] member proof size = {get_size(proof)} bytes")

    ts = time.time()
    ok = m_verify_fn(proof)
    assert ok, f"{label} membership verification failed"
    te = time.time()
    print(f"[{label}] verify = {te - ts:.6f} s")

    ts = time.time()
    proof = nm_proof_fn()
    te = time.time()
    print(f"[{label}] non-member proof = {te - ts:.6f} s")
    print(f"[{label}] non-member proof size = {get_size(proof)} bytes")

    ts = time.time()
    ok = nm_verify_fn(proof)
    assert ok, f"{label} non-membership verification failed"
    te = time.time()
    print(f"[{label}] non-member verify = {te - ts:.6f} s")

    return proof

print(f"target={target} nontarget={nonTarget}")

# Merkle Trees
ts = time.time()
mt = mtree.Tree(elems)
te = time.time()
print(f"[Merkle] accumulate took {te - ts:.6f} s")
benchmark(
    "Merkle",
    mt.get_root(),
    lambda: mt.get_membership_proof(target),
    lambda proof: mt.verify(mt.get_root(), target, proof[0], proof[1]),
    lambda: mt.get_nonmembership_proof(nonTarget),
    lambda proof: mt.verify_nonmembership_proof(mt.get_root(), nonTarget, proof[0][0], proof[0][1], proof[1][0], proof[1][1])
)

# BLS
ts = time.time()
bls = bls.BLSAcc(max_set_size=size, secret_s=5)
poly, acc = bls.accumulate(elems)
te = time.time()
print(f"[BLS] accumulate took {te - ts:.6f} s")
benchmark(
    "BLS",
    acc,
    lambda: bls.prove_membership(poly, target), # = witness,
    lambda proof: bls.verify_membership(acc, target, proof),
    lambda: bls.prove_non_membership(poly, nonTarget), # = witness
    lambda proof: bls.verify_non_membership(acc, nonTarget, proof)
)

# Lattice
ts = time.time()
lattice = lattice.LatticeAccumulator(seed=0)
lat_acc = lattice.accumulate(elems)
te = time.time()
print(f"[Lattice] accumulate took {te - ts:.6f} s")
benchmark(
    "Lattice",
    lat_acc,
    lambda: lattice.prove_membership(target),
    lambda proof: lattice.verify_membership(proof),
    lambda: lattice.prove_non_membership(nonTarget),
    lambda proof: lattice.verify_non_membership(proof)
)

# RSA
ts = time.time()
rsa = rsa.RSAAccumulator(bits=1024)
rsa.batch_add(elems)
te = time.time()
print(f"[RSA] accumulate took {te - ts:.6f} s")
benchmark(
    "RSA",
    rsa.acc,
    lambda: rsa.prove_membership(target),
    lambda proof: rsa.verify_membership(target, proof),
    lambda: rsa.prove_non_membership(nonTarget),
    lambda proof: rsa.verify_non_membership(nonTarget, proof)
)
