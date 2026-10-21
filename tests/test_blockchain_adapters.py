from __future__ import annotations

from dataclasses import replace

from ghostframe.blockchain import DisabledAnchor, InMemoryAnchor
from ghostframe.blockchain.models import AnchorState, InspectionAnchorRequest, VerificationAnchorRequest


def h(char: str) -> str:
    return "0x" + char * 64


def inspection() -> InspectionAnchorRequest:
    return InspectionAnchorRequest(h("1"), h("2"), h("3"), h("4"))


def verification() -> VerificationAnchorRequest:
    return VerificationAnchorRequest(h("1"), h("5"), h("6"), h("7"))


def test_disabled_adapter_needs_no_rpc_and_returns_structured_states():
    adapter = DisabledAnchor()
    assert adapter.health().state == AnchorState.DISABLED
    receipt = adapter.anchor_inspection(inspection())
    assert receipt.state == AnchorState.DISABLED
    assert receipt.transaction_hash is None
    assert adapter.get_anchor(h("1")) is None
    assert adapter.verify_anchor(inspection(), receipt).state == AnchorState.DISABLED


def test_memory_adapter_registers_retrieves_and_verifies_both_stages():
    adapter = InMemoryAnchor()
    first = adapter.anchor_inspection(inspection())
    second = adapter.anchor_verification(verification())
    assert first.state == second.state == AnchorState.CONFIRMED
    record = adapter.get_anchor(h("1"))
    assert record is not None and record.verification_exists
    assert adapter.verify_anchor(inspection(), first).state == AnchorState.CONFIRMED
    assert adapter.verify_anchor(verification(), second).state == AnchorState.CONFIRMED


def test_memory_adapter_rejects_duplicates_and_missing_inspection():
    adapter = InMemoryAnchor()
    assert adapter.anchor_verification(verification()).state == AnchorState.FAILED
    assert adapter.anchor_inspection(inspection()).state == AnchorState.CONFIRMED
    assert adapter.anchor_inspection(inspection()).state == AnchorState.FAILED
    assert adapter.anchor_verification(verification()).state == AnchorState.CONFIRMED
    assert adapter.anchor_verification(verification()).state == AnchorState.FAILED


def test_memory_adapter_enforces_inspection_owner_for_verification():
    owner = InMemoryAnchor(submitter="0x" + "11" * 20)
    owner.anchor_inspection(inspection())
    owner.submitter = "0x" + "22" * 20
    assert owner.anchor_verification(verification()).state == AnchorState.FAILED


def test_memory_verification_detects_wrong_state_or_receipt():
    adapter = InMemoryAnchor()
    receipt = adapter.anchor_inspection(inspection())
    wrong = InspectionAnchorRequest(h("1"), h("8"), h("3"), h("4"))
    assert adapter.verify_anchor(wrong, receipt).state == AnchorState.FAILED
    assert adapter.verify_anchor(inspection(), replace(receipt, operation_commitment=h("9"))).state == AnchorState.FAILED


def test_memory_adapter_is_deterministic_for_identical_sequences():
    left = InMemoryAnchor(); right = InMemoryAnchor()
    assert left.anchor_inspection(inspection()).to_dict() == right.anchor_inspection(inspection()).to_dict()
    assert left.anchor_verification(verification()).to_dict() == right.anchor_verification(verification()).to_dict()

