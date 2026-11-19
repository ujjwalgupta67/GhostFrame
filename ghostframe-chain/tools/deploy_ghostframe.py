#!/usr/bin/env python3
"""Deploy or validate GhostFrameAnchor on the local four-node Besu network."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghostframe.blockchain.besu import BESU_MANIFEST_VERSION, BesuDeploymentManifest, besu_web3
from ghostframe.blockchain.evm import EvmAnchor
from ghostframe.blockchain.models import AnchorState, BlockchainConfig
from ghostframe.blockchain.network import BESU_FOUR_NODE_ENDPOINTS
from ghostframe.blockchain.signing import LocalDevelopmentSigner


CHAIN_ID = 4242
MANIFEST = ROOT / "ghostframe-chain" / "build" / "ghostframe_deployment.json"


def web3_for(url: str):
    return besu_web3(url, timeout=5)


def genesis_hash(web3) -> str:
    return "0x" + bytes(web3.eth.get_block(0)["hash"]).hex()


def configured_adapter(web3, manifest: BesuDeploymentManifest, rpc_url: str) -> EvmAnchor:
    return EvmAnchor(BlockchainConfig(
        enabled=True, rpc_url=rpc_url, expected_chain_id=manifest.chain_id,
        contract_address=manifest.contract_address, expected_code_hash=manifest.runtime_code_hash,
        expected_contract_version=manifest.contract_version,
    ), web3=web3)


def main() -> int:
    primary_url = BESU_FOUR_NODE_ENDPOINTS[0].rpc_url
    primary = web3_for(primary_url)
    if not primary.is_connected():
        raise SystemExit("Node 1 is unavailable. Start the four-node network first.")
    if int(primary.eth.chain_id) != CHAIN_ID:
        raise SystemExit("Wrong chain ID; expected the local Besu chain 4242.")
    current_genesis = genesis_hash(primary).lower()
    if MANIFEST.exists():
        manifest = BesuDeploymentManifest.load(MANIFEST)
        if manifest.chain_id != CHAIN_ID or manifest.genesis_hash != current_genesis:
            raise SystemExit("Stale deployment manifest: the Besu chain identity changed. Move the old manifest aside before a deliberate redeployment.")
        for endpoint in BESU_FOUR_NODE_ENDPOINTS:
            node = web3_for(endpoint.rpc_url)
            if not node.is_connected() or genesis_hash(node).lower() != manifest.genesis_hash:
                raise SystemExit(f"{endpoint.label} does not expose the manifest's chain identity.")
            health = configured_adapter(node, manifest, endpoint.rpc_url).health()
            if health.state != AnchorState.CONFIRMED:
                raise SystemExit(f"Stale deployment manifest on {endpoint.label}: {health.detail}")
        print(json.dumps(manifest.to_dict(), indent=2))
        return 0
    signer = LocalDevelopmentSigner.from_environment("GF_BESU_DEV_KEY", chain_id=CHAIN_ID, gas_price_wei=0)
    adapter = EvmAnchor.deploy(primary, signer=signer)
    receipt = adapter.deployment_receipt
    identity = hashlib.sha256(
        f"{CHAIN_ID}:{current_genesis}:{adapter.config.contract_address.lower()}:{adapter.config.expected_code_hash}".encode()
    ).hexdigest()[:20]
    manifest = BesuDeploymentManifest(
        BESU_MANIFEST_VERSION, CHAIN_ID, current_genesis,
        str(adapter.config.contract_address), str(adapter.config.expected_contract_version),
        str(adapter.config.expected_code_hash), "0x" + bytes(receipt["transactionHash"]).hex(),
        int(receipt["blockNumber"]), signer.address, f"ghostframe-besu-{identity}",
    )
    for endpoint in BESU_FOUR_NODE_ENDPOINTS:
        node = web3_for(endpoint.rpc_url)
        if not node.is_connected() or configured_adapter(node, manifest, endpoint.rpc_url).health().state != AnchorState.CONFIRMED:
            raise SystemExit(f"{endpoint.label} does not expose the expected contract; deployment manifest was not written.")
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
