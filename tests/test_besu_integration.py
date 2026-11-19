from __future__ import annotations

from dataclasses import replace

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_tester")

from web3 import EthereumTesterProvider, Web3

from ghostframe.blockchain.besu import BESU_MANIFEST_VERSION, BesuDeploymentManifest
from ghostframe.blockchain.evm import EvmAnchor
from ghostframe.blockchain.models import AnchorState, InspectionAnchorRequest
from ghostframe.blockchain.signing import LocalDevelopmentSigner


def h(char: str) -> str:
    return "0x" + char * 64


def manifest() -> BesuDeploymentManifest:
    return BesuDeploymentManifest(
        BESU_MANIFEST_VERSION,
        4242,
        h("1"),
        "0x" + "2" * 40,
        "ghostframe-anchor/1.0",
        h("3"),
        h("4"),
        7,
        "0x" + "5" * 40,
        "ghostframe-besu-test",
    )


def test_besu_manifest_is_strict_and_round_trips(tmp_path):
    value = manifest()
    path = tmp_path / "deployment.json"
    import json

    path.write_text(json.dumps(value.to_dict()), encoding="utf-8")
    assert BesuDeploymentManifest.load(path) == value
    with pytest.raises(ValueError, match="fields"):
        BesuDeploymentManifest.from_dict({**value.to_dict(), "unexpected": True})
    with pytest.raises(ValueError, match="contract identity"):
        replace(value, contract_version="wrong")


def test_local_signer_requires_server_environment(monkeypatch):
    monkeypatch.delenv("GF_BESU_DEV_KEY", raising=False)
    with pytest.raises(RuntimeError, match="server environment"):
        LocalDevelopmentSigner.from_environment("GF_BESU_DEV_KEY", chain_id=4242)


def test_local_signer_deploys_and_submits_raw_transactions():
    web3 = Web3(EthereumTesterProvider())
    key = web3.provider.ethereum_tester.backend.account_keys[0].to_hex()
    signer = LocalDevelopmentSigner(key, int(web3.eth.chain_id), gas_price_wei=1_000_000_000)
    assert key not in repr(signer)
    adapter = EvmAnchor.deploy(web3, signer=signer)
    request = InspectionAnchorRequest(h("1"), h("2"), h("3"), h("4"))
    receipt = adapter.anchor_inspection(request)
    assert adapter.submitter.lower() == signer.address.lower()
    assert receipt.state == AnchorState.CONFIRMED
    assert receipt.submitter_address.lower() == signer.address.lower()
    assert adapter.verify_anchor(request, receipt).state == AnchorState.CONFIRMED


def test_local_signer_refuses_wrong_chain_before_nonce_or_submission():
    web3 = Web3(EthereumTesterProvider())
    key = web3.provider.ethereum_tester.backend.account_keys[0].to_hex()
    signer = LocalDevelopmentSigner(key, int(web3.eth.chain_id) + 1, gas_price_wei=1_000_000_000)
    with pytest.raises(RuntimeError, match="wrong chain"):
        signer.submit(web3, object())

