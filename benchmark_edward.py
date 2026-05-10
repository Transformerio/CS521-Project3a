import mtree, bls, lattice, rsa
import time
import numpy as np
import sys 

def get_size(obj) -> int:
    """Recursively compute size in bytes of proof objects."""
    if isinstance(obj, tuple):
        return sum(get_size(i) for i in obj)
    if isinstance(obj, list):
        return sum(get_size(i) for i in obj)
    if isinstance(obj, int):
        return (obj.bit_length() + 7) // 8  # actual byte length of the integer
    return sys.getsizeof(obj)

size = 10**6
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
    print(f"[{label}] member proof ({target}) = {te - ts:.6f} s")
    print(f"[{label}] member proof size ({get_size(proof)}) bytes")

    ts = time.time()
    m_verify_fn(proof)
    te = time.time()
    print(f"[{label}] verify({target}) = {te - ts:.6f} s")

    ts = time.time()
    proof = nm_proof_fn()
    te = time.time()
    print(f"[{label}] non-member proof ({nonTarget}) = {te - ts:.6f} s")
    print(f"[{label}] non-member proof size ({get_size(proof)}) bytes")

    ts = time.time()
    nm_verify_fn(proof)
    te = time.time()
    print(f"[{label}] non-member verify({nonTarget}) = {te - ts:.6f} s")

    return proof

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
    lambda proof: mt.verify_nonmembership_proof(mt.get_root(), nonTarget, proof[0], proof[1])
)

# BLS
# ts = time.time()
# bls = bls.BLSAcc(max_set_size=size, secret_s=5)
# poly, acc = bls.accumulate(elems)
# te = time.time()
# print(f"[BLS] accumulate took {te - ts:.6f} s")
# benchmark(
#     "BLS",
#     acc,
#     lambda: bls.prove_membership(poly, target), # = witness
#     lambda proof: bls.verify_membership(acc, target, proof),
#     lambda: bls.prove_non_membership(poly, nonTarget), # = witness
#     lambda proof: bls.verify_non_membership(acc, nonTarget, proof)
# )

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

# # RSA
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
