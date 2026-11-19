#!/usr/bin/env python3
"""Show whether the 4 GhostFrame Besu nodes agree on one shared ledger.

Usage:
    python3 tools/check_nodes.py              # status of all nodes
    python3 tools/check_nodes.py --tx 0xabc.. # is this transaction on every node?

Needs only the Python standard library.
"""
import argparse
import json
import sys
import urllib.request

NODES = [
    ("Node 1 (processing)", "http://127.0.0.1:8545"),
    ("Node 2 (client)", "http://127.0.0.1:8546"),
    ("Node 3 (auditor)", "http://127.0.0.1:8547"),
    ("Node 4 (validator)", "http://127.0.0.1:8548"),
]


def rpc(url, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=3) as resp:
        data = json.loads(resp.read())
    if "error" in data:
        raise RuntimeError(data["error"].get("message", str(data["error"])))
    return data["result"]


def short(h):
    return h[:10] + "…" + h[-6:] if h else "-"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tx", help="transaction hash to look for on every node")
    args = ap.parse_args()

    live = []
    print(f"{'Node':<22}{'Status':<10}{'Block':>8}{'Peers':>7}")
    print("-" * 47)
    for name, url in NODES:
        try:
            height = int(rpc(url, "eth_blockNumber"), 16)
            peers = int(rpc(url, "net_peerCount"), 16)
            live.append((name, url, height))
            print(f"{name:<22}{'UP':<10}{height:>8}{peers:>7}")
        except Exception:
            print(f"{name:<22}{'DOWN':<10}{'-':>8}{'-':>7}")

    if not live:
        print("\nNo node is running. Start the network first: ./chain.sh start")
        return 1

    validators = rpc(live[0][1], "qbft_getValidatorsByBlockNumber", ["latest"])
    n = len(validators)
    quorum = -(-2 * n // 3)  # ceil(2n/3): 3 of 4
    print(f"\nQBFT validators: {n}  (every block needs {quorum} of {n} to sign)")
    print(f"Nodes up: {len(live)} of {len(NODES)}")

    # Compare the block hash at a height every live node already has.
    common = min(h for _, _, h in live)
    hashes = {}
    for name, url, _ in live:
        hashes[name] = rpc(url, "eth_getBlockByNumber", [hex(common), False])["hash"]
    same = len(set(hashes.values())) == 1
    print(f"\nBlock #{common} hash on every live node:")
    for name, h in hashes.items():
        print(f"  {name:<22}{short(h)}")
    print("  => SHARED LEDGER OK: all live nodes hold the same chain" if same
          else "  => MISMATCH: nodes disagree!")

    if len(live) == quorum and len(live) < len(NODES):
        print(f"\nNote: {len(NODES) - len(live)} node down, but {quorum} of {n} is enough, so new blocks keep coming.")
    elif len(live) < quorum:
        print("\nNote: only", len(live), "nodes up. QBFT needs 3, so the chain is PAUSED (no new blocks) until a node comes back.")

    ok = same
    if args.tx:
        if not args.tx.startswith("0x"):
            args.tx = "0x" + args.tx
        print(f"\nTransaction {short(args.tx)} on each live node:")
        found = set()
        for name, url, _ in live:
            r = rpc(url, "eth_getTransactionReceipt", [args.tx])
            if r is None:
                print(f"  {name:<22}NOT FOUND (yet)")
                ok = False
            else:
                status = "success" if r["status"] == "0x1" else "reverted"
                print(f"  {name:<22}block #{int(r['blockNumber'], 16)}  {status}")
                found.add((r["blockNumber"], r["blockHash"]))
        if len(found) == 1:
            print("  => Same transaction in the same block on every live node")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
