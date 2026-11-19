from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evm import EvmAnchor
from .models import ADDRESS_RE, BYTES32_RE, BlockchainConfig, CONTRACT_INTERFACE_VERSION
from .signing import LocalDevelopmentSigner


BESU_MANIFEST_VERSION = "ghostframe-besu-deployment/1.0"


def besu_web3(rpc_url: str, *, timeout: int = 30):
    from web3 import HTTPProvider, Web3
    from web3.middleware import ExtraDataToPOAMiddleware
    from .ui import validate_local_rpc_url

    validate_local_rpc_url(rpc_url)
    web3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
    web3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return web3


def validate_besu_network_identity(web3: Any, manifest: "BesuDeploymentManifest") -> None:
    """Bind a manifest to the live chain, including reset-sensitive genesis identity."""

    try:
        if not web3.is_connected():
            raise RuntimeError("Four-node Besu RPC is unavailable.")
        if int(web3.eth.chain_id) != manifest.chain_id:
            raise RuntimeError("Four-node Besu RPC returned the wrong chain ID.")
        live_genesis = "0x" + bytes(web3.eth.get_block(0)["hash"]).hex()
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError("Four-node Besu chain identity could not be verified.") from exc
    if live_genesis.lower() != manifest.genesis_hash.lower():
        raise RuntimeError(
            "The Besu genesis hash changed. This deployment manifest is stale after a chain reset."
        )


@dataclass(frozen=True)
class BesuDeploymentManifest:
    manifest_version: str
    chain_id: int
    genesis_hash: str
    contract_address: str
    contract_version: str
    runtime_code_hash: str
    deployment_transaction: str
    deployment_block: int
    signer_address: str
    network_profile: str

    def __post_init__(self) -> None:
        if self.manifest_version != BESU_MANIFEST_VERSION:
            raise ValueError("Unsupported Besu deployment manifest version.")
        if self.chain_id <= 0 or self.deployment_block < 0:
            raise ValueError("Malformed Besu deployment manifest numbers.")
        if not ADDRESS_RE.fullmatch(self.contract_address) or not ADDRESS_RE.fullmatch(self.signer_address):
            raise ValueError("Malformed Besu deployment manifest address.")
        for value in (self.genesis_hash, self.runtime_code_hash, self.deployment_transaction):
            if not BYTES32_RE.fullmatch(value):
                raise ValueError("Malformed Besu deployment manifest hash.")
        if self.contract_version != CONTRACT_INTERFACE_VERSION or not self.network_profile:
            raise ValueError("Besu deployment manifest contract identity is invalid.")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "BesuDeploymentManifest":
        expected = {
            "manifest_version", "chain_id", "genesis_hash", "contract_address",
            "contract_version", "runtime_code_hash", "deployment_transaction",
            "deployment_block", "signer_address", "network_profile",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("Malformed Besu deployment manifest fields.")
        return cls(**value)

    @classmethod
    def load(cls, path: Path) -> "BesuDeploymentManifest":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Besu deployment manifest is missing or unreadable.") from exc
        return cls.from_dict(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version, "chain_id": self.chain_id,
            "genesis_hash": self.genesis_hash, "contract_address": self.contract_address,
            "contract_version": self.contract_version, "runtime_code_hash": self.runtime_code_hash,
            "deployment_transaction": self.deployment_transaction, "deployment_block": self.deployment_block,
            "signer_address": self.signer_address, "network_profile": self.network_profile,
        }


def create_besu_adapter(
    manifest: BesuDeploymentManifest, *, rpc_url: str = "http://127.0.0.1:8545",
    signer_environment_variable: str = "GF_BESU_DEV_KEY", confirmations_required: int = 1,
) -> EvmAnchor:
    signer = LocalDevelopmentSigner.from_environment(
        signer_environment_variable, chain_id=manifest.chain_id, gas_price_wei=0,
    )
    if signer.address.lower() != manifest.signer_address.lower():
        raise RuntimeError("Configured Besu development signer does not match the deployment manifest.")
    web3 = besu_web3(rpc_url)
    validate_besu_network_identity(web3, manifest)
    config = BlockchainConfig(
        enabled=True, rpc_url=rpc_url, expected_chain_id=manifest.chain_id,
        contract_address=manifest.contract_address, expected_code_hash=manifest.runtime_code_hash,
        expected_contract_version=manifest.contract_version,
        confirmations_required=confirmations_required,
    )
    return EvmAnchor(config, web3=web3, signer=signer)


def create_besu_verifier(
    manifest: BesuDeploymentManifest, *, rpc_url: str = "http://127.0.0.1:8545",
    confirmations_required: int = 1,
) -> EvmAnchor:
    web3 = besu_web3(rpc_url)
    validate_besu_network_identity(web3, manifest)
    config = BlockchainConfig(
        enabled=True, rpc_url=rpc_url, expected_chain_id=manifest.chain_id,
        contract_address=manifest.contract_address, expected_code_hash=manifest.runtime_code_hash,
        expected_contract_version=manifest.contract_version,
        confirmations_required=confirmations_required,
    )
    return EvmAnchor(config, web3=web3)
