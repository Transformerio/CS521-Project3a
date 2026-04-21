import mtree, bls, lattice, rsa
import time

elems = ["alice", "bob", "charlie", "dave"]
target = "alice"
nonTarget = "david"

def benchmark(label, m_proof_fn, m_verify_fn, nm_proof_fn, nm_verify_fn):
    ts = time.time()
    proof = m_proof_fn()
    te = time.time()
    print(f"[{label}] member proof ({target}) = {te - ts:.6f} sec")

    ts = time.time()
    m_verify_fn(proof)
    te = time.time()
    print(f"[{label}] verify({target}) = {te - ts:.6f} sec")

    ts = time.time()
    proof = nm_proof_fn()
    te = time.time()
    print(f"[{label}] non-member proof ({nonTarget}) = {te - ts:.6f} sec")

    ts = time.time()
    nm_verify_fn(proof)
    te = time.time()
    print(f"[{label}] non-member verify({nonTarget}) = {te - ts:.6f} sec")

    return proof

# Merkle Trees
# mt = mtree.Tree(elems)
# benchmark(
#     "Merkle",
#     lambda: mt.get_membership_proof(target),
#     lambda proof: mt.verify(mt.get_root(), target, proof[0], proof[1]),
#     lambda: mt.get_nonmembership_proof(nonTarget),
#     lambda proof: mt.verify_nonmembership_proof(mt.get_root(), nonTarget, proof[0], proof[1])
# )

# BLS
bls = bls.BLSAcc(max_set_size=10, secret_s=5)
poly, acc = bls.accumulate(elems)
benchmark(
    "BLS",
    lambda: bls.prove_membership(poly, target), # = witness
    lambda proof: bls.verify_membership(acc, target, proof),
    lambda: bls.prove_non_membership(poly, nonTarget), # = witness
    lambda proof: bls.verify_non_membership(acc, nonTarget, proof)
)

# Lattice
lattice = lattice.LatticeAccumulator(seed=0)
lattice.accumulate(elems)

benchmark(
    "Lattice",
    lambda: lattice.prove_membership(target),
    lambda proof: lattice.verify_membership(proof),
    lambda: lattice.prove_non_membership(nonTarget),
    lambda proof: lattice.verify_non_membership(proof)
)

# # RSA
rsa = rsa.RSAAccumulator(bits=1024)
rsa.batch_add(elems)
benchmark(
    "RSA",
    lambda: rsa.prove_membership(target),
    lambda proof: rsa.verify_membership(target, proof),
    lambda: rsa.prove_non_membership(nonTarget),
    lambda proof: rsa.verify_non_membership(nonTarget, proof)
)
