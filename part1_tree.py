"""
Part 1 - Merkle Tree Implementation
=====================================
Pure Python implementation of a binary Merkle Tree.
Includes:
  - MerkleNode / MerkleTree classes
  - Proof generation (get_proof)
  - Standalone proof verification (verify_proof)
  - Unit tests
"""

import hashlib
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def sha256_pair(left: bytes, right: bytes) -> bytes:
    """Hash two child digests together to produce a parent node hash."""
    return sha256(left + right)


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

@dataclass
class MerkleNode:
    """A single node in the Merkle tree."""
    hash: bytes
    left: "MerkleNode | None" = field(default=None, repr=False)
    right: "MerkleNode | None" = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Tree
# ---------------------------------------------------------------------------

class MerkleTree:
    """
    Binary Merkle Tree built from a list of raw byte-string leaves.

    Construction rules
    ------------------
    * Each leaf is SHA-256 hashed to form a leaf node.
    * If the number of nodes at any level is odd, the last node is duplicated
      before pairing (standard Bitcoin/Ethereum convention).
    * The tree is built bottom-up until a single root remains.
    """

    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf.")
        # Build leaf nodes
        self._leaves: list[MerkleNode] = [
            MerkleNode(hash=sha256(leaf)) for leaf in leaves
        ]
        self._root: MerkleNode = self._build(list(self._leaves))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build(self, nodes: list[MerkleNode]) -> MerkleNode:
        """
        Recursively pair up nodes and hash each pair until one root remains.
        """
        if len(nodes) == 1:
            return nodes[0]

        # Duplicate last node if odd count
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])

        next_level: list[MerkleNode] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1]
            parent = MerkleNode(
                hash=sha256_pair(left.hash, right.hash),
                left=left,
                right=right,
            )
            next_level.append(parent)

        return self._build(next_level)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def root(self) -> bytes:
        """Return the Merkle root hash (32 bytes)."""
        return self._root.hash

    def get_proof(self, index: int) -> list[dict]:
        """
        Generate a Merkle proof for the leaf at *index*.

        Returns a list of dicts ordered from the leaf-level sibling up to
        the child of the root:
            [{"hash": <bytes>, "position": "left" | "right"}, ...]

        "position" indicates where the *sibling* sits relative to the
        current node.  To reconstruct the parent hash:
          - sibling is "left"  → sha256_pair(sibling, current)
          - sibling is "right" → sha256_pair(current, sibling)
        """
        leaves = list(self._leaves)
        n = len(leaves)
        if index < 0 or index >= n:
            raise IndexError(f"Leaf index {index} out of range [0, {n}).")

        proof: list[dict] = []
        current_index = index
        current_level = leaves

        while len(current_level) > 1:
            # Duplicate if odd
            level = list(current_level)
            if len(level) % 2 == 1:
                level.append(level[-1])

            # Determine sibling
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                sibling_position = "right"
            else:
                sibling_index = current_index - 1
                sibling_position = "left"

            proof.append({
                "hash": level[sibling_index].hash,
                "position": sibling_position,
            })

            # Move up one level
            next_level: list[MerkleNode] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1]
                parent = MerkleNode(
                    hash=sha256_pair(left.hash, right.hash),
                    left=left,
                    right=right,
                )
                next_level.append(parent)

            current_index //= 2
            current_level = next_level

        return proof


# ---------------------------------------------------------------------------
# Standalone verifier
# ---------------------------------------------------------------------------

def verify_proof(
    leaf_data: bytes,
    proof: list[dict],
    expected_root: bytes,
) -> bool:
    """
    Verify a Merkle proof without access to the original tree.

    Parameters
    ----------
    leaf_data    : The raw data of the leaf (will be SHA-256 hashed).
    proof        : List of {"hash": bytes, "position": "left"|"right"} dicts.
    expected_root: The trusted Merkle root to verify against.

    Returns True if the recomputed root matches *expected_root*.
    """
    current_hash = sha256(leaf_data)

    for step in proof:
        sibling_hash = step["hash"]
        position = step["position"]

        if position == "left":
            # Sibling is on the left
            current_hash = sha256_pair(sibling_hash, current_hash)
        elif position == "right":
            # Sibling is on the right
            current_hash = sha256_pair(current_hash, sibling_hash)
        else:
            raise ValueError(f"Invalid position value: {position!r}")

    return current_hash == expected_root


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def run_tests() -> None:
    """Run a suite of correctness tests for the Merkle tree implementation."""
    print("=" * 60)
    print("PART 1 - Merkle Tree Unit Tests")
    print("=" * 60)

    # ------------------------------------------------------------------ #
    # Test 1 – Basic four-leaf tree
    # ------------------------------------------------------------------ #
    items = [b"alice", b"bob", b"carol", b"dave"]
    tree = MerkleTree(items)

    print(f"\n[Test 1] Four-leaf tree")
    print(f"  Root: {tree.root.hex()}")

    # Valid proof for "carol" (index 2)
    proof = tree.get_proof(2)
    assert verify_proof(b"carol", proof, tree.root), \
        "FAIL: Valid proof should verify."
    print("  [OK] Valid proof for 'carol' verified successfully.")

    # Tampered leaf data
    assert not verify_proof(b"mallory", proof, tree.root), \
        "FAIL: Tampered leaf data should not verify."
    print("  [OK] Tampered leaf data correctly rejected.")

    # Tampered proof hash
    tampered_proof = [dict(step) for step in proof]
    tampered_proof[0]["hash"] = b"\x00" * 32
    assert not verify_proof(b"carol", tampered_proof, tree.root), \
        "FAIL: Tampered proof hash should not verify."
    print("  [OK] Tampered proof hash correctly rejected.")

    # ------------------------------------------------------------------ #
    # Test 2 – Odd number of leaves (5 leaves)
    # ------------------------------------------------------------------ #
    items_odd = [b"tx1", b"tx2", b"tx3", b"tx4", b"tx5"]
    tree_odd = MerkleTree(items_odd)

    print(f"\n[Test 2] Odd leaf count (5 leaves)")
    print(f"  Root: {tree_odd.root.hex()}")

    for i in range(5):
        p = tree_odd.get_proof(i)
        assert verify_proof(items_odd[i], p, tree_odd.root), \
            f"FAIL: Valid proof for index {i} should verify."
    print("  [OK] All five proofs verified successfully.")

    # ------------------------------------------------------------------ #
    # Test 3 – Single leaf
    # ------------------------------------------------------------------ #
    tree_single = MerkleTree([b"only"])
    print(f"\n[Test 3] Single-leaf tree")
    print(f"  Root: {tree_single.root.hex()}")
    proof_single = tree_single.get_proof(0)
    assert proof_single == [], "FAIL: Single-leaf proof should be empty."
    assert verify_proof(b"only", proof_single, tree_single.root), \
        "FAIL: Single-leaf proof should verify."
    print("  [OK] Single-leaf proof verified (empty proof).")

    # ------------------------------------------------------------------ #
    # Test 4 – All leaves, every index
    # ------------------------------------------------------------------ #
    items_8 = [f"item{i}".encode() for i in range(8)]
    tree_8 = MerkleTree(items_8)
    print(f"\n[Test 4] Eight-leaf tree - all indices")
    for i in range(8):
        p = tree_8.get_proof(i)
        assert verify_proof(items_8[i], p, tree_8.root), \
            f"FAIL: Valid proof for index {i} should verify."
    print("  [OK] All eight proofs verified successfully.")

    # ------------------------------------------------------------------ #
    # Test 5 – Two-leaf tree
    # ------------------------------------------------------------------ #
    tree_two = MerkleTree([b"left", b"right"])
    print(f"\n[Test 5] Two-leaf tree")
    assert verify_proof(b"left", tree_two.get_proof(0), tree_two.root)
    assert verify_proof(b"right", tree_two.get_proof(1), tree_two.root)
    print("  [OK] Both leaves verified.")

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED [OK]")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_tests()
