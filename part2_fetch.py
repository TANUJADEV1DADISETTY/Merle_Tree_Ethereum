"""
Part 2 - Fetch Real Ethereum Data
====================================
Connects to an Ethereum JSON-RPC endpoint (Alchemy / Infura) and retrieves
live block data including the full transaction list and the transactionsRoot.

Functions
---------
fetch_block          – eth_getBlockByNumber with full transaction objects
fetch_transaction    – eth_getTransactionByHash
inspect_block        – Pretty-print key block header fields
"""

import os
import sys
import json
import requests


# ---------------------------------------------------------------------------
# JSON-RPC helper
# ---------------------------------------------------------------------------

def _rpc_call(rpc_url: str, method: str, params: list) -> dict:
    """
    Send a JSON-RPC 2.0 request and return the 'result' field.

    Raises RuntimeError on transport errors or JSON-RPC error responses.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    try:
        response = requests.post(rpc_url, json=payload, timeout=30)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"HTTP error calling {method}: {exc}") from exc

    data = response.json()
    if "error" in data:
        raise RuntimeError(
            f"JSON-RPC error [{data['error'].get('code')}]: "
            f"{data['error'].get('message')}"
        )

    return data["result"]


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def fetch_block(rpc_url: str, block_number: int | str = "latest") -> dict:
    """
    Fetch a full block (with transactions) from an Ethereum JSON-RPC endpoint.

    Parameters
    ----------
    rpc_url      : Full URL including the API key, e.g.
                   "https://eth-mainnet.g.alchemy.com/v2/<key>"
    block_number : An integer block number OR the string "latest".

    Returns
    -------
    dict
        Raw block dictionary including ``transactionsRoot`` and a
        ``transactions`` list of full transaction objects.
    """
    if isinstance(block_number, int):
        block_param = hex(block_number)
    else:
        block_param = block_number  # "latest", "earliest", etc.

    block = _rpc_call(rpc_url, "eth_getBlockByNumber", [block_param, True])

    if block is None:
        raise RuntimeError(
            f"Block {block_number!r} not found – the node returned null."
        )

    return block


def fetch_transaction(rpc_url: str, tx_hash: str) -> dict:
    """
    Fetch a single transaction by its hash.

    Parameters
    ----------
    rpc_url : Full RPC endpoint URL.
    tx_hash : 0x-prefixed transaction hash string.

    Returns
    -------
    dict
        Full transaction object as returned by the node.
    """
    tx = _rpc_call(rpc_url, "eth_getTransactionByHash", [tx_hash])
    if tx is None:
        raise RuntimeError(f"Transaction {tx_hash!r} not found.")
    return tx


def inspect_block(block: dict) -> None:
    """
    Print the key header fields of a fetched block in a human-readable way.

    Printed fields
    --------------
    * Block number (decimal)
    * Timestamp (UNIX epoch)
    * Transaction count
    * Miner / fee recipient
    * Gas used / gas limit
    * Base fee per gas (EIP-1559)
    * transactionsRoot  ← the value we will reconstruct in Part 3
    """
    def hex_to_int(h: str | None) -> int:
        return int(h, 16) if h else 0

    block_number = hex_to_int(block.get("number"))
    timestamp    = hex_to_int(block.get("timestamp"))
    gas_used     = hex_to_int(block.get("gasUsed"))
    gas_limit    = hex_to_int(block.get("gasLimit"))
    base_fee     = hex_to_int(block.get("baseFeePerGas"))
    tx_count     = len(block.get("transactions", []))
    miner        = block.get("miner", block.get("feeRecipient", "N/A"))
    tx_root      = block.get("transactionsRoot", "N/A")

    print("=" * 64)
    print("  ETHEREUM BLOCK INSPECTOR")
    print("=" * 64)
    print(f"  Block number      : {block_number:,}")
    print(f"  Timestamp (epoch) : {timestamp}")
    print(f"  Miner / validator : {miner}")
    print(f"  Transactions      : {tx_count}")
    print(f"  Gas used          : {gas_used:,}")
    print(f"  Gas limit         : {gas_limit:,}")
    print(f"  Base fee (wei)    : {base_fee:,}")
    print(f"  transactionsRoot  : {tx_root}")
    print("=" * 64)

    if tx_count > 0:
        print("\n  First 3 transactions:")
        for tx in block["transactions"][:3]:
            print(
                f"    [{tx.get('transactionIndex', '?')}] "
                f"{tx.get('hash', 'N/A')}"
            )
        if tx_count > 3:
            print(f"    ... ({tx_count - 3} more)")


# ---------------------------------------------------------------------------
# Entry point – standalone demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    rpc_url = os.environ.get("ETH_RPC_URL", "")
    if not rpc_url:
        print(
            "ERROR: Set the ETH_RPC_URL environment variable to your "
            "Alchemy / Infura endpoint, e.g.\n"
            "  $env:ETH_RPC_URL='https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY'",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Fetching the latest Ethereum block ...")
    block = fetch_block(rpc_url, "latest")
    inspect_block(block)

    tx_count = len(block.get("transactions", []))
    if tx_count > 0:
        sample_tx = block["transactions"][0]
        print(f"\nFetching full details for tx {sample_tx['hash']} ...")
        tx_detail = fetch_transaction(rpc_url, sample_tx["hash"])
        print(json.dumps(tx_detail, indent=2))
