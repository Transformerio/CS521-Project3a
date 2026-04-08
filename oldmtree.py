import hashlib
import bisect
class Node:
    def __init__(self, data, left, right):
        self.data = data
        self.left = left
        self.right = right

    def isLeaf(self):
        return ((self.left is None) and (self.right is None))

class Tree:
    def __init__(self, elems):
        self.elems = elems
        self.numNodes = (2*len(self.elems))-1

        self.root = self.build_tree(0, self.elems)
        self.table = {}
        print(self.build_map(0, self.elems))
    
    def H(self, x):
        return hashlib.sha256(x.encode()).hexdigest()

    def arr_to_str(self,x):
        temp = ""
        for i in x:
            temp+=i
        return temp

    def build_tree(self, lvl, x):
        if len(x) <= 1: 
            return Node(self.H(self.arr_to_str(x)), None, None)
        length = len(x)
        left = x[:length//2]
        right = x[length//2:]
        # print(f"lvl={lvl} left={left} right={right}")
        left_node = self.build_tree(lvl+1, left)
        right_node = self.build_tree(lvl+1, right)
        return Node(
            self.H(left_node.data + right_node.data), 
            left_node, 
            right_node
        )
    
    def build_map(self, lvl, x):
        if lvl not in self.table:
            self.table[lvl] = []
        if len(x) <= 1:
            leaf_hash = self.H(self.arr_to_str(x))
            self.table[lvl].append(leaf_hash)
            return leaf_hash
        
        if (len(x) % 2) != 0:
            print("duplicating last leaf")
            x.append(x[-1])

        left = x[:len(x)//2]
        right = x[len(x)//2:]
        left_node = self.build_map(lvl+1, left)
        right_node = self.build_map(lvl+1, right)
        curr_hash = self.H(left_node + right_node)

        self.table[lvl].append(curr_hash)

        return curr_hash
    
    def get_root(self):
        return self.root
    
    def print_tree(self):
        def rec(lvl, node):
            if node is None:
                return
            print("  " * lvl + node.data)
            rec(lvl+1, node.left)
            rec(lvl+1, node.right)
        rec(0, self.root)

    def get_map(self):
        return self.table
    
    def is_member(self, x):
        target = self.H(x)
        def rec(node):
            if node.data == target:
                return node.data
            if (node.left).data == target:
                return (node.left).data
            
        print(rec(self.root))

    def neighbors(self, sorted, target):
        idx = bisect.bisect_left(sorted, target)
        left = sorted[idx-1] if idx > 0 else None
        right = sorted[idx] if idx < len(sorted) else None
        return left, right

    def contains(self, x):
        for i in range(0, self.elems):
            if (self.elems)[i] == x:
                if i % 2 == 0: # sibling is to right
                    return ()
                
    def get_index(self, lvl, target):
        for i in range(0, len(self.table[lvl])):
            if self.table[lvl][i] == target:
                return i
        return -1

    def get_membership_proof(self, target):
        tree_height = len(self.table)
        proof = []
        index_target = self.get_index((tree_height - 1), self.H(target))
        if index_target == -1:
            return None
        curr_index = index_target
        lvl = tree_height - 1
        for i in range(0, tree_height - 1):
            # index_sibling = curr_index + 1 if (curr_index % 2 == 0) else curr_index - 1
            index_sibling = curr_index ^ 1 if curr_index != -1 else -1
            # print(f"{lvl} {index_sibling}")
            proof.append(self.table[lvl][index_sibling])
            curr_index = curr_index // 2
            lvl-=1
        return proof

    def get_nonmembership_proof(self, target):
        print(self.neighbors(self.table[len(self.table)-1], self.H(target)))


elems = ['a','b','d','e','f','g','h']
mt = Tree(elems)
print(mt.get_map())
print(mt.get_membership_proof('c'))
mt.get_nonmembership_proof('c')