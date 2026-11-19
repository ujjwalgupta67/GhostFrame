#!/usr/bin/env python3
"""Mini GhostFrame-style demo on the 4-node network.

    python tools/demo_anchor.py deploy          # put DemoAnchor contract on the chain (once)
    python tools/demo_anchor.py anchor FILE     # record FILE's SHA-256 on the chain
    python tools/demo_anchor.py verify FILE     # check FILE against the chain on EVERY node

Transactions are signed here on the laptop (the same way GhostFrame's EvmAnchor
will do it), then sent to Node 1. QBFT copies them to all 4 nodes.
"""
import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from eth_account import Account
from web3 import Web3

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = ROOT / "tools" / "demo_anchor_artifact.json"
DEPLOYMENT = ROOT / "build" / "demo_anchor_deployment.json"

CHAIN_ID = 4242
WRITE_NODE = "http://127.0.0.1:8545"
NODES = [
    ("Node 1 (processing)", "http://127.0.0.1:8545"),
    ("Node 2 (client)", "http://127.0.0.1:8546"),
    ("Node 3 (auditor)", "http://127.0.0.1:8547"),
    ("Node 4 (validator)", "http://127.0.0.1:8548"),
]
# Demo-only key, pre-funded in genesis. Well known from the Besu docs: never use on a real network.
DEV_KEY = os.environ.get("GF_DEV_KEY", "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63")


def connect(url):
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 5}))
    try:
        w3.eth.block_number
    except Exception:
        return None
    return w3


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def send(w3, tx):
    """Sign locally and send. Waits until the block is final (QBFT: 1 block)."""
    acct = Account.from_key(DEV_KEY)
    tx.update({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
        "chainId": CHAIN_ID,
        "gasPrice": 0,
    })
    # Gas is free on this network, so leave a wide safety margin over the estimate.
    tx.pop("gas", None)
    tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.5) + 21000
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  tx sent: 0x{tx_hash.hex().removeprefix('0x')}  (waiting for consensus...)")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    if receipt.status != 1:
        sys.exit("  Transaction REVERTED.")
    print(f"  confirmed in block #{receipt.blockNumber}")
    return receipt


def deployed_address(w3):
    """Address of DemoAnchor on THIS chain, or None (never deployed, or chain was reset)."""
    if not DEPLOYMENT.exists():
        return None
    addr = json.loads(DEPLOYMENT.read_text())["address"]
    return addr if w3.eth.get_code(addr) else None


def load_contract(w3):
    addr = deployed_address(w3)
    if not addr:
        sys.exit("DemoAnchor is not deployed on this chain. Run:  ./chain.sh demo  (or: python tools/demo_anchor.py deploy)")
    art = json.loads(ARTIFACT.read_text())
    return w3.eth.contract(address=addr, abi=art["abi"])


def cmd_deploy(args):
    w3 = connect(WRITE_NODE)
    if not w3:
        sys.exit("Could not connect to Node 1. Start the network: ./chain.sh start")
    if w3.eth.chain_id != CHAIN_ID:
        sys.exit(f"Wrong chain: expected {CHAIN_ID}, got {w3.eth.chain_id}")
    if args.if_missing and deployed_address(w3):
        return 0
    art = json.loads(ARTIFACT.read_text())
    print("Deploying DemoAnchor ...")
    factory = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
    receipt = send(w3, factory.constructor().build_transaction({"gasPrice": 0, "chainId": CHAIN_ID}))
    DEPLOYMENT.parent.mkdir(exist_ok=True)
    DEPLOYMENT.write_text(json.dumps({"address": receipt.contractAddress, "block": receipt.blockNumber}, indent=1))
    print(f"DemoAnchor deployed at {receipt.contractAddress}")


def cmd_anchor(args):
    w3 = connect(WRITE_NODE)
    if not w3:
        sys.exit("Could not connect to Node 1.")
    c = load_contract(w3)
    digest = sha256_file(args.file)
    print(f"File:    {args.file}\nSHA-256: {digest.hex()}")
    if c.functions.records(digest).call()[0] != 0:
        sys.exit("This exact file is already anchored (the contract does not allow duplicates).")
    receipt = send(w3, c.functions.anchor(digest).build_transaction({"gasPrice": 0, "chainId": CHAIN_ID}))
    print(f"Anchored. Tx hash for check_nodes.py:  0x{receipt.transactionHash.hex().removeprefix('0x')}")


def cmd_verify(args):
    digest = sha256_file(args.file)
    print(f"File:    {args.file}\nSHA-256: {digest.hex()}\n")
    results = []
    for name, url in NODES:
        w3 = connect(url)
        if not w3:
            print(f"  {name:<22}DOWN (skipped)")
            continue
        block, submitter = load_contract(w3).functions.records(digest).call()
        found = block != 0
        results.append(found)
        print(f"  {name:<22}{'FOUND, anchored in block #' + str(block) if found else 'NOT FOUND'}")
    if not results:
        sys.exit("No node is running.")
    if all(results):
        print(f"\nVERIFIED: {len(results)} independent node(s) hold this exact file's hash.")
    elif not any(results):
        print("\nFAILED: this file does not match anything on the chain.\n"
              "Either it was never anchored, or it has been MODIFIED (even 1 byte changes the hash).")
        return 1
    else:
        print("\nWARNING: nodes disagree. Wait a few seconds and run again.")
        return 2
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("deploy"); p.add_argument("--if-missing", action="store_true"); p.set_defaults(fn=cmd_deploy)
    p = sub.add_parser("anchor"); p.add_argument("file"); p.set_defaults(fn=cmd_anchor)
    p = sub.add_parser("verify"); p.add_argument("file"); p.set_defaults(fn=cmd_verify)
    args = ap.parse_args()
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
