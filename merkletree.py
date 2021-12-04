from Crypto.Hash import SHA256

class MerkleNode:
    """
    Stores the hash, hash_obj and the parent.
    """
    def __init__(self, hash, hash_obj):
        self.hash = hash
        self.hash_obj = hash_obj
        self.parent = None


class MerkleTree:
    """
    Stores the leaves and the root hash of the tree.
    """
    def __init__(self, messages):
        leaves = []

        for msg in messages:
            (hash, hash_obj) = self.compute_hash(msg)
            node = MerkleNode(hash, hash_obj)
            leaves.append(node)

        self.root = self.build_merkle_tree(leaves)

    def build_merkle_tree(self, leaves):
        """
        Builds the Merkle tree from a list of leaves. In case of an odd number of leaves, the last leaf is duplicated.
        """
        num_leaves = len(leaves)
        if num_leaves == 1:
            return leaves[0]

        parents = []

        i = 0
        while i < num_leaves:
            left_child = leaves[i]
            right_child = leaves[i + 1] if i + 1 < num_leaves else left_child

            parents.append(self.create_parent(left_child, right_child))

            i += 2

        return self.build_merkle_tree(parents)

    def create_parent(self, left_child, right_child):
        """
        Creates the parent node from the children, and updates
        their parent field.
        """
        (hash, hash_obj) = self.compute_hash(left_child.hash + right_child.hash)
        parent = MerkleNode(hash, hash_obj)
        left_child.parent, right_child.parent = parent, parent

        return parent

    @staticmethod
    def compute_hash(data):
        data = data.encode('utf-8')
        digest = SHA256.new()
        digest.update(data)
        return digest.hexdigest(), digest