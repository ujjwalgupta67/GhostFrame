from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOLC_VERSION = "0.8.30"
CONTRACT_VERSION = "ghostframe-anchor/1.0"


def compile_contract(root: Path, *, install: bool = False) -> Path:
    try:
        import solcx
    except ImportError as exc:
        raise RuntimeError("Install requirements-blockchain.txt to compile the contract.") from exc

    installed = {str(version) for version in solcx.get_installed_solc_versions()}
    if SOLC_VERSION not in installed:
        if not install:
            raise RuntimeError(
                f"Solidity {SOLC_VERSION} is not installed. Run this script with --install-solc during development."
            )
        solcx.install_solc(SOLC_VERSION)

    source_path = root / "ghostframe" / "blockchain" / "contracts" / "GhostFrameAnchor.sol"
    output_path = root / "ghostframe" / "blockchain" / "contracts" / "GhostFrameAnchor.json"
    source = source_path.read_text(encoding="utf-8")
    compiled = solcx.compile_standard(
        {
            "language": "Solidity",
            "sources": {"GhostFrameAnchor.sol": {"content": source}},
            "settings": {
                "optimizer": {"enabled": True, "runs": 200},
                "metadata": {"bytecodeHash": "none", "appendCBOR": False},
                "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]}},
            },
        },
        solc_version=SOLC_VERSION,
    )
    contract = compiled["contracts"]["GhostFrameAnchor.sol"]["GhostFrameAnchor"]
    deployed = bytes.fromhex(contract["evm"]["deployedBytecode"]["object"])
    artifact = {
        "artifact_version": "ghostframe-contract-artifact/1.0",
        "compiler": f"solc-{SOLC_VERSION}",
        "contract_name": "GhostFrameAnchor",
        "contract_version": CONTRACT_VERSION,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "deployed_code_sha256": "0x" + hashlib.sha256(deployed).hexdigest(),
        "abi": contract["abi"],
        "bytecode": "0x" + contract["evm"]["bytecode"]["object"],
        "deployed_bytecode": "0x" + contract["evm"]["deployedBytecode"]["object"],
    }
    output_path.write_text(json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile the pinned GhostFrame anchor contract.")
    parser.add_argument("--install-solc", action="store_true", help="Explicitly download pinned solc for development.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    print(compile_contract(root, install=args.install_solc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
