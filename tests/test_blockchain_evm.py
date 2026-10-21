from __future__ import annotations

from dataclasses import replace

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_tester")

from web3 import EthereumTesterProvider, Web3

from ghostframe.blockchain.evm import EvmAnchor
from ghostframe.blockchain.models import AnchorState, BlockchainConfig, FailureCategory, InspectionAnchorRequest, VerificationAnchorRequest


def h(char: str) -> str:
    return "0x" + char * 64


@pytest.fixture
def local_evm():
    web3 = Web3(EthereumTesterProvider())
    return web3, EvmAnchor.deploy(web3)


def inspection() -> InspectionAnchorRequest:
    return InspectionAnchorRequest(h("1"), h("2"), h("3"), h("4"))


def verification() -> VerificationAnchorRequest:
    return VerificationAnchorRequest(h("1"), h("5"), h("6"), h("7"))


def test_evm_adapter_health_anchor_retrieve_and_independent_verification(local_evm):
    web3 = Web3(EthereumTesterProvider())
    adapter = EvmAnchor.deploy(web3)
    assert adapter.health().state == AnchorState.CONFIRMED
    inspection_receipt = adapter.anchor_inspection(inspection())
    verification_receipt = adapter.anchor_verification(verification())
    assert inspection_receipt.state == verification_receipt.state == AnchorState.CONFIRMED
    assert adapter.verify_anchor(inspection(), inspection_receipt).state == AnchorState.CONFIRMED
    assert adapter.verify_anchor(verification(), verification_receipt).state == AnchorState.CONFIRMED


def test_evm_adapter_reports_reverted_transitions_without_leaking_exception(local_evm):
    _, adapter = local_evm
    missing = adapter.anchor_verification(verification())
    assert missing.state == AnchorState.FAILED
    assert missing.failure_category == FailureCategory.TRANSACTION_REVERTED
    first = adapter.anchor_inspection(inspection())
    duplicate = adapter.anchor_inspection(inspection())
    assert first.state == AnchorState.CONFIRMED and duplicate.state == AnchorState.FAILED
    assert "execution reverted" not in duplicate.detail.lower()


def test_evm_adapter_distinguishes_submission_rejection(local_evm):
    _, adapter = local_evm
    class RejectedFunction:
        @staticmethod
        def transact(_):
            raise RuntimeError("synthetic wallet rejection containing private details")
    receipt = adapter._submit(inspection(), RejectedFunction())
    assert receipt.failure_category == FailureCategory.TRANSACTION_REJECTED
    assert "private details" not in receipt.detail


def test_evm_adapter_distinguishes_pending_from_confirmed(local_evm):
    web3, original = local_evm
    adapter = EvmAnchor.deploy(web3, confirmations_required=2)
    receipt = adapter.anchor_inspection(inspection())
    assert receipt.state == AnchorState.PENDING
    assert receipt.confirmations == 1
    web3.provider.ethereum_tester.mine_blocks(1)
    checked = adapter.verify_anchor(inspection(), receipt)
    assert checked.state == AnchorState.CONFIRMED
    assert checked.receipt.confirmations >= 2


def test_evm_adapter_rejects_wrong_chain_code_contract_and_domain_receipt(local_evm):
    web3, adapter = local_evm
    base = adapter.config
    wrong_chain = EvmAnchor(replace(base, expected_chain_id=base.expected_chain_id + 1), web3=web3)
    assert "chain ID" in wrong_chain.health().detail
    wrong_code = EvmAnchor(replace(base, expected_code_hash=h("f")), web3=web3)
    assert "bytecode" in wrong_code.health().detail
    missing = EvmAnchor(replace(base, contract_address=web3.eth.accounts[2]), web3=web3)
    assert "No contract" in missing.health().detail
    wrong_version = EvmAnchor(replace(base, expected_contract_version="ghostframe-anchor/999"), web3=web3)
    assert "version" in wrong_version.health().detail
    receipt = adapter.anchor_inspection(inspection())
    altered = replace(receipt, chain_id=receipt.chain_id + 1)
    assert adapter.verify_anchor(inspection(), altered).state == AnchorState.FAILED


def test_evm_adapter_detects_wrong_event_and_state(monkeypatch, local_evm):
    _, adapter = local_evm
    monkeypatch.setattr(adapter, "_event_values", lambda request, raw: (None, None))
    receipt = adapter.anchor_inspection(inspection())
    assert receipt.failure_category == FailureCategory.UNEXPECTED_EVENT

    web3 = Web3(EthereumTesterProvider())
    adapter = EvmAnchor.deploy(web3)
    monkeypatch.setattr(adapter, "_event_values", lambda request, raw: ({
        "operationCommitment": request.operation_commitment,
        "submitter": adapter.submitter,
        "sourceFileHash": h("9"),
        "inspectionCommitment": request.inspection_commitment,
        "schemaCommitment": request.schema_commitment,
        "timestamp": adapter.get_anchor(request.operation_commitment).inspection_timestamp,
    }, 0))
    mismatched = adapter.anchor_inspection(InspectionAnchorRequest(h("a"), h("2"), h("3"), h("4")))
    assert mismatched.failure_category == FailureCategory.EVENT_MISMATCH

    web3 = Web3(EthereumTesterProvider())
    adapter = EvmAnchor.deploy(web3)
    original = adapter.get_anchor
    monkeypatch.setattr(adapter, "get_anchor", lambda operation: None)
    receipt = adapter.anchor_inspection(InspectionAnchorRequest(h("8"), h("2"), h("3"), h("4")))
    assert receipt.failure_category == FailureCategory.STATE_MISMATCH
    monkeypatch.setattr(adapter, "get_anchor", original)


def test_evm_adapter_classifies_timeout_missing_and_malformed_receipts(monkeypatch, local_evm):
    _, adapter = local_evm
    class TimedOut:
        @staticmethod
        def is_connected():
            raise TimeoutError
    adapter.web3 = TimedOut()
    timed_out = adapter.anchor_inspection(inspection())
    assert timed_out.failure_category == FailureCategory.RPC_TIMEOUT

    web3 = Web3(EthereumTesterProvider())
    adapter = EvmAnchor.deploy(web3)
    monkeypatch.setattr(adapter.web3.eth, "wait_for_transaction_receipt", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("missing")))
    missing = adapter.anchor_inspection(InspectionAnchorRequest(h("8"), h("2"), h("3"), h("4")))
    assert missing.failure_category == FailureCategory.MISSING_RECEIPT

    web3 = Web3(EthereumTesterProvider())
    adapter = EvmAnchor.deploy(web3)
    malformed = adapter._evaluate_receipt(inspection(), {})
    assert malformed.failure_category == FailureCategory.MALFORMED_RECEIPT


def test_evm_adapter_reports_rpc_unavailable_without_throwing(local_evm):
    _, adapter = local_evm
    class Offline:
        @staticmethod
        def is_connected():
            return False
    adapter.web3 = Offline()
    assert adapter.health().state == AnchorState.FAILED
    receipt = adapter.anchor_inspection(inspection())
    assert receipt.failure_category == FailureCategory.RPC_UNAVAILABLE


def test_evm_privacy_boundary_contains_only_commitments_and_chain_data(local_evm):
    web3, adapter = local_evm
    receipt = adapter.anchor_inspection(inspection())
    transaction = web3.eth.get_transaction(receipt.transaction_hash)
    record = adapter.get_anchor(h("1"))
    event_receipt = web3.eth.get_transaction_receipt(receipt.transaction_hash)
    event = adapter.contract.events.InspectionAnchored().process_receipt(event_receipt)[0]["args"]
    combined = (str(dict(transaction)) + str(record.to_dict()) + str(dict(event)) + receipt.to_json_bytes().decode()).lower()
    for sensitive in ("author@example.test", "51.5007,-0.1246", "synthetic-user", "private-file.pdf", "synthetic comment"):
        assert sensitive.lower() not in combined
