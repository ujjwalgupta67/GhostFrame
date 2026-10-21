from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONTRACT_DIR = ROOT / "ghostframe" / "blockchain" / "contracts"


def test_contract_artifact_is_minimal_pinned_and_bound_to_source():
    source = (CONTRACT_DIR / "GhostFrameAnchor.sol").read_bytes()
    artifact = json.loads((CONTRACT_DIR / "GhostFrameAnchor.json").read_text(encoding="utf-8"))
    assert set(artifact) == {
        "abi", "artifact_version", "bytecode", "compiler", "contract_name", "contract_version",
        "deployed_bytecode", "deployed_code_sha256", "source_sha256",
    }
    assert artifact["compiler"] == "solc-0.8.30"
    assert artifact["contract_version"] == "ghostframe-anchor/1.0"
    assert artifact["source_sha256"] == hashlib.sha256(source).hexdigest()
    deployed = bytes.fromhex(artifact["deployed_bytecode"][2:])
    assert artifact["deployed_code_sha256"] == "0x" + hashlib.sha256(deployed).hexdigest()
    assert len(artifact["abi"]) == 11


def test_contract_has_no_sensitive_or_financial_interface():
    artifact = json.loads((CONTRACT_DIR / "GhostFrameAnchor.json").read_text(encoding="utf-8"))
    public = json.dumps(artifact["abi"], sort_keys=True).lower()
    for forbidden in (
        "metadata", "filename", "passphrase", "privatekey", "evidenceblob", "token", "nft",
        "payment", "withdraw", "upgrade", "admin", "owner",
    ):
        assert forbidden not in public
    assert all(item.get("stateMutability") != "payable" for item in artifact["abi"] if item["type"] == "function")
