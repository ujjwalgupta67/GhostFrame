from __future__ import annotations

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_tester")

from eth_tester.exceptions import TransactionFailed
from web3 import EthereumTesterProvider, Web3

from ghostframe.blockchain.evm import EvmAnchor


def b(char: str) -> str:
    return "0x" + char * 64


@pytest.fixture
def deployed():
    web3 = Web3(EthereumTesterProvider())
    adapter = EvmAnchor.deploy(web3)
    return web3, adapter.contract, adapter


def anchor_inspection(contract, sender, op="1"):
    return contract.functions.anchorInspection(b(op), b("2"), b("3"), b("4")).transact({"from": sender})


def test_contract_stores_inspection_and_emits_matching_event(deployed):
    web3, contract, _ = deployed
    receipt = web3.eth.wait_for_transaction_receipt(anchor_inspection(contract, web3.eth.accounts[0]))
    record = contract.functions.getRecord(b("1")).call()
    event = contract.events.InspectionAnchored().process_receipt(receipt)[0]["args"]
    block = web3.eth.get_block(receipt["blockNumber"])
    assert record[:5] == (web3.eth.accounts[0], block["timestamp"], bytes.fromhex("2" * 64), bytes.fromhex("3" * 64), bytes.fromhex("4" * 64))
    assert event["operationCommitment"] == bytes.fromhex("1" * 64)
    assert event["submitter"] == web3.eth.accounts[0]
    assert event["timestamp"] == block["timestamp"]


def test_contract_rejects_duplicate_inspection_and_preserves_state(deployed):
    web3, contract, _ = deployed
    anchor_inspection(contract, web3.eth.accounts[0])
    before = contract.functions.getRecord(b("1")).call()
    with pytest.raises((TransactionFailed, ValueError)):
        anchor_inspection(contract, web3.eth.accounts[1])
    assert contract.functions.getRecord(b("1")).call() == before


@pytest.mark.parametrize("zero_index", range(4))
def test_contract_rejects_every_zero_inspection_commitment(deployed, zero_index):
    web3, contract, _ = deployed
    values = [b("1"), b("2"), b("3"), b("4")]
    values[zero_index] = "0x" + "0" * 64
    with pytest.raises((TransactionFailed, ValueError)):
        contract.functions.anchorInspection(*values).transact({"from": web3.eth.accounts[0]})


def test_contract_rejects_verification_before_inspection(deployed):
    web3, contract, _ = deployed
    with pytest.raises((TransactionFailed, ValueError)):
        contract.functions.anchorVerification(b("1"), b("5"), b("6"), b("7")).transact({"from": web3.eth.accounts[0]})


def test_contract_enforces_owner_and_verification_is_immutable(deployed):
    web3, contract, _ = deployed
    owner, other = web3.eth.accounts[:2]
    anchor_inspection(contract, owner)
    with pytest.raises((TransactionFailed, ValueError)):
        contract.functions.anchorVerification(b("1"), b("5"), b("6"), b("7")).transact({"from": other})
    tx = contract.functions.anchorVerification(b("1"), b("5"), b("6"), b("7")).transact({"from": owner})
    receipt = web3.eth.wait_for_transaction_receipt(tx)
    record = contract.functions.getRecord(b("1")).call()
    event = contract.events.VerificationAnchored().process_receipt(receipt)[0]["args"]
    assert record[6:] == (bytes.fromhex("5" * 64), bytes.fromhex("6" * 64), bytes.fromhex("7" * 64))
    assert event["submitter"] == owner
    assert event["timestamp"] == record[5]
    with pytest.raises((TransactionFailed, ValueError)):
        contract.functions.anchorVerification(b("1"), b("8"), b("9"), b("a")).transact({"from": owner})
    assert contract.functions.getRecord(b("1")).call() == record


@pytest.mark.parametrize("zero_index", (1, 2, 3))
def test_contract_rejects_zero_verification_commitments(deployed, zero_index):
    web3, contract, _ = deployed
    anchor_inspection(contract, web3.eth.accounts[0])
    values = [b("1"), b("5"), b("6"), b("7")]
    values[zero_index] = "0x" + "0" * 64
    with pytest.raises((TransactionFailed, ValueError)):
        contract.functions.anchorVerification(*values).transact({"from": web3.eth.accounts[0]})


def test_contract_has_no_payable_entrypoint_and_rejects_eth(deployed):
    web3, contract, _ = deployed
    assert all(item.get("stateMutability") != "payable" for item in contract.abi if item["type"] == "function")
    with pytest.raises((TransactionFailed, ValueError)):
        web3.eth.send_transaction({"from": web3.eth.accounts[0], "to": contract.address, "value": 1})

