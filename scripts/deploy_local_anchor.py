from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy GhostFrameAnchor to an explicitly configured local EVM.")
    parser.add_argument("--rpc", default="http://127.0.0.1:8545")
    parser.add_argument("--account", help="Unlocked local development account; defaults to the first RPC account.")
    args = parser.parse_args()
    if args.rpc not in {"http://127.0.0.1:8545", "http://localhost:8545"}:
        raise SystemExit("Phase 5 deployment tooling only accepts the local loopback EVM endpoint.")
    try:
        from web3 import HTTPProvider, Web3
    except ImportError as exc:
        raise SystemExit("Install requirements-blockchain.txt first.") from exc
    from ghostframe.blockchain.evm import EvmAnchor

    web3 = Web3(HTTPProvider(args.rpc, request_kwargs={"timeout": 30}))
    if not web3.is_connected():
        raise SystemExit("Local EVM is not reachable.")
    adapter = EvmAnchor.deploy(web3, submitter=args.account)
    print(json.dumps({
        "chain_id": adapter.config.expected_chain_id,
        "contract_address": adapter.config.contract_address,
        "contract_code_hash": adapter.config.expected_code_hash,
        "contract_version": adapter.config.expected_contract_version,
        "deployment_transaction": _hex(adapter.deployment_receipt["transactionHash"]),
        "gas_used": int(adapter.deployment_receipt["gasUsed"]),
    }, sort_keys=True))
    return 0


def _hex(value: object) -> str:
    return value if isinstance(value, str) else "0x" + bytes(value).hex()


if __name__ == "__main__":
    raise SystemExit(main())
