"""
Part 3 - Reconstruct and Verify
==================================
Ties together Part 1 (Merkle Tree) and Part 2 (Ethereum block fetching) to:

  1. Hash every transaction in a block using the simplified method
     (SHA-256 of the tx hash string) and the accurate method
     (Keccak-256 of the RLP-encoded transaction).
  2. Build a Merkle tree over the resulting hashes.
  3. Compare the reconstructed root against the block header's
     transactionsRoot.
  4. Generate and verify an inclusion proof for any transaction.
  5. Demonstrate that tampering with the proof breaks verification.

Extension A (RLP + Keccak-256) is implemented alongside the simplified path.
Extension B (odd-leaf handling) is covered by the existing MerkleTree logic.
Extension C (light-client simulation) is a standalone function at the bottom.
Extension D (historical block) is triggered via CLI flags.
"""

import os
import sys
import hashlib

# -- third-party (installed via requirements.txt) ------------------------------
try:
    import sha3  # type: ignore # pysha3 – registers hashlib.sha3_256 and sha3_256 as "sha3_256"
except ImportError:
    sha3 = None  # type: ignore

try:
    import rlp  # type: ignore # rlp library for encoding
    HAS_RLP = True
except ImportError:
    HAS_RLP = False

# -- local modules -------------------------------------------------------------
from part1_tree import MerkleTree, sha256
from part2_fetch import fetch_block, inspect_block


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of *data* (requires pysha3)."""
    if sha3 is None:
        raise RuntimeError(
            "pysha3 is required for Keccak-256. "
            "Install it with: pip install pysha3"
        )
    k = hashlib.new("sha3_256")  # pysha3 patches this to be keccak
    k.update(data)
    return k.digest()


# ---------------------------------------------------------------------------
# Transaction hashing – Option A (simplified / SHA-256)
# ---------------------------------------------------------------------------

def hash_transaction_simple(tx: dict) -> bytes:
    """
    Simplified hash: SHA-256 of the transaction's hex hash string.

    This does NOT reproduce Ethereum's actual transactionsRoot but is useful
    to validate that the Merkle tree logic is correct.
    """
    tx_hash_hex: str = tx["hash"]
    return sha256(tx_hash_hex.encode())


# ---------------------------------------------------------------------------
# Transaction hashing – Option B (accurate / RLP + Keccak-256)
# ---------------------------------------------------------------------------

def _to_bytes(hex_str: str | None, length: int | None = None) -> bytes:
    """Convert a 0x-prefixed hex string to bytes, zero-padding to *length*."""
    if hex_str is None or hex_str == "0x":
        b = b""
    else:
        b = bytes.fromhex(hex_str[2:] if hex_str.startswith("0x") else hex_str)
    if length is not None:
        b = b.rjust(length, b"\x00")
    return b


def _to_int(hex_str: str | None) -> int:
    """Convert a 0x-prefixed hex string to an integer."""
    if hex_str is None or hex_str == "0x":
        return 0
    return int(hex_str, 16)


def hash_transaction_rlp(tx: dict) -> bytes:
    """
    Accurate hash: Keccak-256 of the RLP-encoded transaction fields.

    Covers legacy (type 0), EIP-2930 (type 1), and EIP-1559 (type 2)
    transactions.  Type 3 (blob) transactions are treated as type 2
    for simplicity.

    NOTE: Due to Ethereum's Merkle Patricia Trie (not a plain binary tree),
    the reconstructed root will still differ from the block header value.
    This extension demonstrates the correct per-transaction hash computation.
    """
    if not HAS_RLP:
        raise RuntimeError(
            "rlp library is required for RLP encoding. "
            "Install it with: pip install rlp"
        )
    if sha3 is None:
        raise RuntimeError(
            "pysha3 is required for Keccak-256. "
            "Install it with: pip install pysha3"
        )

    tx_type = _to_int(tx.get("type", "0x0"))
    nonce    = _to_int(tx.get("nonce"))
    gas      = _to_int(tx.get("gas"))
    value    = _to_int(tx.get("value"))
    to_addr  = _to_bytes(tx.get("to"))
    data     = _to_bytes(tx.get("input", "0x"))

    if tx_type == 0:
        # Legacy: nonce, gasPrice, gas, to, value, data, v, r, s
        gas_price = _to_int(tx.get("gasPrice", "0x0"))
        v = _to_int(tx.get("v", "0x0"))
        r = _to_bytes(tx.get("r", "0x0"))
        s = _to_bytes(tx.get("s", "0x0"))
        fields = [nonce, gas_price, gas, to_addr, value, data, v, r, s]
        encoded = rlp.encode(fields)
    elif tx_type == 1:
        # EIP-2930: chainId, nonce, gasPrice, gas, to, value, data, accessList, v, r, s
        chain_id  = _to_int(tx.get("chainId", "0x1"))
        gas_price = _to_int(tx.get("gasPrice", "0x0"))
        access    = []  # simplified: skip access list encoding
        v = _to_int(tx.get("v", "0x0"))
        r = _to_bytes(tx.get("r", "0x0"))
        s = _to_bytes(tx.get("s", "0x0"))
        fields = [chain_id, nonce, gas_price, gas, to_addr, value, data, access, v, r, s]
        encoded = b"\x01" + rlp.encode(fields)
    else:
        # EIP-1559 (type 2) and beyond
        chain_id       = _to_int(tx.get("chainId", "0x1"))
        max_priority   = _to_int(tx.get("maxPriorityFeePerGas", "0x0"))
        max_fee        = _to_int(tx.get("maxFeePerGas", "0x0"))
        access         = []  # simplified
        v = _to_int(tx.get("v", "0x0"))
        r = _to_bytes(tx.get("r", "0x0"))
        s = _to_bytes(tx.get("s", "0x0"))
        fields = [chain_id, nonce, max_priority, max_fee, gas, to_addr, value, data, access, v, r, s]
        encoded = b"\x02" + rlp.encode(fields)

    return keccak256(encoded)


# ---------------------------------------------------------------------------
# Root reconstruction
# ---------------------------------------------------------------------------

def reconstruct_transactions_root(
    transactions: list[dict],
    use_rlp: bool = False,
) -> bytes:
    """
    Hash each transaction and build a MerkleTree over the resulting hashes.

    Parameters
    ----------
    transactions : List of full transaction dicts from the RPC response.
    use_rlp      : If True, use RLP + Keccak-256 (Option B).
                   If False, use SHA-256 of tx hash string (Option A).

    Returns
    -------
    bytes
        The 32-byte Merkle root of all transaction hashes.
    """
    if not transactions:
        raise ValueError("Block has no transactions.")

    hash_fn = hash_transaction_rlp if use_rlp else hash_transaction_simple

    leaf_hashes: list[bytes] = []
    for tx in transactions:
        h = hash_fn(tx)
        leaf_hashes.append(h)

    tree = MerkleTree(leaf_hashes)
    return tree.root, tree


def verify_transactions_root(block: dict, use_rlp: bool = False) -> bool:
    """
    Compare the reconstructed Merkle root against the block header value.

    Prints both values for visual inspection. With Option A the roots will
    differ (different hash function). With Option B they may differ because
    Ethereum uses a Merkle Patricia Trie, not a plain binary tree.

    Returns True if both roots match exactly.
    """
    transactions = block.get("transactions", [])
    if not transactions:
        print("  Block has no transactions – skipping root verification.")
        return False

    header_root = block["transactionsRoot"]
    computed_root, _ = reconstruct_transactions_root(transactions, use_rlp=use_rlp)
    label = "RLP+Keccak" if use_rlp else "SHA-256 (simplified)"

    print(f"\n  Hash method         : {label}")
    print(f"  Block header root   : {header_root}")
    print(f"  Reconstructed root  : {computed_root.hex()}")

    match = computed_root.hex() == header_root.lower().lstrip("0x") or \
            "0x" + computed_root.hex() == header_root.lower()
    print(f"  Match               : {'[OK] YES' if match else '[x] NO (expected – different tree structure)'}")
    return match


# ---------------------------------------------------------------------------
# Inclusion proof – end to end
# ---------------------------------------------------------------------------

def prove_transaction_inclusion(
    block: dict,
    tx_index: int,
    use_rlp: bool = False,
) -> None:
    """
    Full end-to-end demo:

    1. Reconstruct the Merkle tree over all block transactions.
    2. Generate a proof for the transaction at *tx_index*.
    3. Verify the proof against the reconstructed root.
    4. Print the proof path so the structure is visible.
    5. Demonstrate that modifying any sibling hash breaks verification.
    """
    transactions = block.get("transactions", [])
    n = len(transactions)
    if not transactions:
        print("  Block has no transactions.")
        return
    if tx_index < 0 or tx_index >= n:
        print(f"  tx_index {tx_index} out of range [0, {n}).")
        return

    hash_fn = hash_transaction_rlp if use_rlp else hash_transaction_simple
    leaf_hashes = [hash_fn(tx) for tx in transactions]
    tree = MerkleTree(leaf_hashes)

    target_tx = transactions[tx_index]
    target_leaf = hash_fn(target_tx)

    proof = tree.get_proof(tx_index)

    print("\n" + "-" * 64)
    print(f"  INCLUSION PROOF FOR TRANSACTION INDEX {tx_index}")
    print("-" * 64)
    print(f"  Tx hash : {target_tx.get('hash', 'N/A')}")
    print(f"  Leaf    : {target_leaf.hex()}")
    print(f"  Root    : {tree.root.hex()}")
    print(f"\n  Proof path ({len(proof)} steps):")
    for step_i, step in enumerate(proof):
        print(
            f"    [{step_i}] sibling={step['hash'].hex()[:16]}...  "
            f"position={step['position']}"
        )

    # -- Verify (correct) ------------------------------------------------------
    # verify_proof expects the *raw leaf data*, but our leaves are already
    # pre-hashed bytes (not the original data).  We therefore re-implement
    # the walk directly using the pre-hashed leaf.
    from part1_tree import sha256_pair
    current = target_leaf
    for step in proof:
        if step["position"] == "left":
            current = sha256_pair(step["hash"], current)
        else:
            current = sha256_pair(current, step["hash"])
    valid = (current == tree.root)
    print(f"\n  Verification result : {'[OK] VALID' if valid else '[FAIL] INVALID'}")

    # -- Tamper demonstration --------------------------------------------------
    if proof:
        tampered_proof = [dict(s) for s in proof]
        tampered_proof[0] = dict(tampered_proof[0])
        tampered_proof[0]["hash"] = b"\xde\xad\xbe\xef" * 8  # 32 bytes of garbage

        current_t = target_leaf
        for step in tampered_proof:
            if step["position"] == "left":
                current_t = sha256_pair(step["hash"], current_t)
            else:
                current_t = sha256_pair(current_t, step["hash"])
        tampered_valid = (current_t == tree.root)
        print(
            f"  Tampered proof check: "
            f"{'[FAIL] VALID (unexpected!)' if tampered_valid else '[OK] INVALID (correct – tampering detected)'}"
        )

    print("-" * 64)


# ---------------------------------------------------------------------------
# Extension C – Light-client simulation
# ---------------------------------------------------------------------------

def light_client_verify(
    block_header: dict,
    tx_hash_hex: str,
    proof: list[dict],
    reconstructed_root: bytes,
) -> bool:
    """
    Simulate what an Ethereum light client does:

    * Accept only the block header (for its transactionsRoot) and a proof.
    * Do NOT have access to the full block or tree.
    * Verify that *tx_hash_hex* is committed to by the header.

    Parameters
    ----------
    block_header       : Dict containing at least ``transactionsRoot``.
    tx_hash_hex        : 0x-prefixed transaction hash to prove.
    proof              : Merkle proof produced by MerkleTree.get_proof().
    reconstructed_root : The root from our Merkle tree (passed in because
                         our tree is not a Patricia Trie, so the roots differ).

    Returns True if the inclusion is verified against *reconstructed_root*.
    """
    _ = block_header  # Simulated: normally we'd check if reconstructed_root matches block_header['transactionsRoot']
    from part1_tree import sha256_pair
    leaf = sha256(tx_hash_hex.encode())

    current = leaf
    for step in proof:
        if step["position"] == "left":
            current = sha256_pair(step["hash"], current)
        else:
            current = sha256_pair(current, step["hash"])

    return current == reconstructed_root


# ---------------------------------------------------------------------------
# Main runnable script
# ---------------------------------------------------------------------------

def main() -> None:
    rpc_url = os.environ.get("ETH_RPC_URL", "")
    if not rpc_url:
        print(
            "ERROR: Set ETH_RPC_URL to your Alchemy / Infura endpoint.\n"
            "  Example (PowerShell):\n"
            "    $env:ETH_RPC_URL='https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY'\n"
            "  Or add it to a .env file and run with docker-compose.",
            file=sys.stderr,
        )
        sys.exit(1)

    # -- Optionally fetch a historical block ----------------------------------
    # Trigger Extension D by setting ETH_BLOCK_NUMBER env var to a block number.
    block_env = os.environ.get("ETH_BLOCK_NUMBER", "latest")
    try:
        block_number: int | str = int(block_env)
    except ValueError:
        block_number = block_env

    print(f"\n{'='*64}")
    print("  ETHEREUM MERKLE TREE - FULL VERIFICATION DEMO")
    print(f"{'='*64}")
    print(f"\nStep 1 - Fetching Ethereum block ({block_number!r}) ...")
    block = fetch_block(rpc_url, block_number)
    inspect_block(block)

    transactions = block.get("transactions", [])
    if not transactions:
        print("\nBlock has no transactions. Try a different block number.")
        sys.exit(0)

    print(f"\nStep 2 - Reconstructing transactions root (Option A: SHA-256) ...")
    verify_transactions_root(block, use_rlp=False)

    if HAS_RLP and sha3 is not None:
        print(f"\nStep 3 - Reconstructing transactions root (Option B: RLP + Keccak-256) ...")
        verify_transactions_root(block, use_rlp=True)
    else:
        print("\nStep 3 - Skipping RLP+Keccak root (libraries not installed).")
        print("  Install them with: pip install rlp pysha3")

    print(f"\nStep 4 - Generating and verifying inclusion proof ...")
    tx_index = int(os.environ.get("ETH_TX_INDEX", "0"))
    prove_transaction_inclusion(block, tx_index, use_rlp=False)

    # -- Extension C -----------------------------------------------------------
    print(f"\nStep 5 - Light-client simulation (Extension C) ...")
    hash_fn = hash_transaction_simple
    leaf_hashes = [hash_fn(tx) for tx in transactions]
    lc_tree = MerkleTree(leaf_hashes)
    lc_proof = lc_tree.get_proof(tx_index)
    lc_tx_hash = transactions[tx_index]["hash"]
    lc_result = light_client_verify(block, lc_tx_hash, lc_proof, lc_tree.root)
    print(f"  Light-client verification for tx {lc_tx_hash}:")
    print(f"  Result: {'[OK] INCLUDED' if lc_result else '[FAIL] NOT INCLUDED'}")

    print(f"\n{'='*64}")
    print("  ALL STEPS COMPLETE")
    print(f"{'='*64}\n")


if __name__ == "__main__":
    # Also run Part 1 tests first for a complete demo
    from part1_tree import run_tests
    run_tests()
    print()
    main()
