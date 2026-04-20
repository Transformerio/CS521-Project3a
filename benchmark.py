import mtree
import bls
import time

elems = ['a','b', 'c', 'd','e','f','g','h']
target = 'c'
# Merkle Trees
mt = mtree.Tree(elems)
startMerkle = time.time()
mpMerkle = mt.get_membership_proof(target)
endMerkle = time.time()
print(f"[Merkle] get_membership_proof({target}) = {endMerkle - startMerkle} sec")
startMerkle = time.time()
verify_merkle = mt.verify(mt.get_root(), target, mpMerkle[0], mpMerkle[1])
print(f"[Merkle] verify_merkle({target}) = {endMerkle - startMerkle} sec")
endMerkle = time.time()

# BLS
bls = bls.BLSAcc(max_set_size=10, secret_s=5)
poly, acc = bls.accumulate(elems)
startBLS = time.time()
mpBLS = bls.prove_membership(poly, target) # = witness
endBLS = time.time()
print(f"[BLS] get_membership_proof({target}) = {endBLS - startBLS} sec")
startBLS = time.time()
verify_bls = bls.verify_membership(acc, target, mpBLS)
endBLS = time.time()
print(f"[BLS] verify_BLS({target}) = {endBLS - startBLS} sec")
# Lattice

# RSA
