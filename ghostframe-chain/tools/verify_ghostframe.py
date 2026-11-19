#!/usr/bin/env python3
"""Verify a GFP 2.0 package independently through all four local Besu nodes."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghostframe.blockchain.besu import BesuDeploymentManifest
from ghostframe.blockchain.multinode import verify_package_across_nodes
from ghostframe.blockchain.network import BESU_FOUR_NODE_ENDPOINTS, observe_network


DEFAULT_MANIFEST = ROOT / "ghostframe-chain" / "build" / "ghostframe_deployment.json"


def _result(value) -> dict[str, object]:
    return {
        "stage": value.stage.value,
        "state": value.state.value,
        "verified_nodes": value.verified_nodes,
        "required_nodes": value.required_nodes,
        "detail": value.detail,
        "nodes": [
            {
                "node_id": item.node_id,
                "label": item.label,
                "state": item.state.value,
                "detail": item.detail,
            }
            for item in value.results
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify GhostFrame GFP 2.0 receipts through the four-node Besu network."
    )
    parser.add_argument("package", type=Path, help="Path to a GhostFrame .gfp package")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--required-nodes", type=int, default=4, choices=range(1, 5),
        help="Verification policy threshold; the default requires all four nodes.",
    )
    args = parser.parse_args()
    passphrase = getpass.getpass("Evidence passphrase: ")
    manifest = BesuDeploymentManifest.load(args.manifest)
    network = observe_network(
        expected_chain_id=manifest.chain_id,
        expected_genesis_hash=manifest.genesis_hash,
    )
    inspection, verification = verify_package_across_nodes(
        args.package.read_bytes(),
        passphrase,
        BESU_FOUR_NODE_ENDPOINTS,
        expected_chain_id=manifest.chain_id,
        expected_genesis_hash=manifest.genesis_hash,
        contract_address=manifest.contract_address,
        expected_code_hash=manifest.runtime_code_hash,
        expected_contract_version=manifest.contract_version,
        required_nodes=args.required_nodes,
    )
    output = {
        "network_agreement": network.agreement.value,
        "network_detail": network.detail,
        "inspection": _result(inspection),
        "verification": _result(verification),
    }
    print(json.dumps(output, indent=2))
    return 0 if inspection.state.value == verification.state.value == "CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
