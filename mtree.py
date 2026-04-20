import hashlib
import bisect

def H(x):
    return hashlib.sha256(x.encode()).hexdigest()

class Tree:
    def __init__(self, elems):
        self.elems = sorted(elems)
        # print(self.elems)
        self.numNodes = (2*len(self.elems))-1

        self.table = {}
        self.root = (self.build_map(0, self.elems))
    
    def build_map(self, lvl, x):
        if lvl not in self.table:
            self.table[lvl] = []
        if len(x) <= 1:
            leaf_hash = H(x[0])
            self.table[lvl].append(leaf_hash)
            return leaf_hash
        
        if (len(x) % 2) != 0:
            # print("duplicating last leaf")
            x.append(x[-1])

        left = x[:len(x)//2]
        right = x[len(x)//2:]
        left_node = self.build_map(lvl+1, left)
        right_node = self.build_map(lvl+1, right)
        curr_hash = H(left_node + right_node)

        self.table[lvl].append(curr_hash)
        return curr_hash
    
    def get_root(self):
        return self.root

    def get_map(self):
        return self.table

    def get_neighbors(self, sorted, target):
        idx = bisect.bisect_left(sorted, target)
        left = sorted[idx-1] if idx > 0 else None
        right = sorted[idx] if idx < len(sorted) else None
        return left, right
                
    def get_index(self, lvl, target):
        for i in range(0, len(self.table[lvl])):
            if self.table[lvl][i] == target:
                return i
        return -1

    def get_membership_proof(self, target):
        if target is None:
            return None
        tree_height = len(self.table)
        proof = []
        proof_side = []
        index_target = self.get_index((tree_height - 1), H(target))
        if index_target == -1:
            print(f"target (\'{target}\') does not exist, generating non-membership proof...")
            return self.get_nonmembership_proof(target)
        curr_index = index_target
        lvl = tree_height - 1
        for i in range(0, tree_height - 1):
            if (curr_index % 2 == 0):
                index_sibling = curr_index + 1
                proof_side.append('r')
            else:
                index_sibling = curr_index - 1
                proof_side.append('l')
            # index_sibling = curr_index ^ 1 if curr_index != -1 else -1
            # print(f"{lvl} {index_sibling}")
            proof.append(self.table[lvl][index_sibling])
            curr_index = curr_index // 2
            lvl-=1
        return proof, proof_side

    def get_nonmembership_proof(self, target):
        (left,right) = self.get_neighbors(self.elems, target)
        left_proof = self.get_membership_proof(left)
        right_proof = self.get_membership_proof(right)
        return (left_proof,right_proof)

    def verify(self, root, target, proof, proof_side):
        totalHash = H(target)
        for i in range(0, len(proof)):
            if proof_side[i] == 'r':
                # print(f"hashing {totalHash} + {proof[i]}")
                totalHash = H(totalHash + proof[i])
            else:
                totalHash = H(proof[i] + totalHash)
                # print(f"hashing {proof[i]} + {totalHash}")
        return root == totalHash


