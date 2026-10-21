from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest

from ghostframe.blockchain.memory import InMemoryAnchor
from ghostframe.blockchain.models import AnchorState
from ghostframe.evidence import (
    GFP_FORMAT_VERSION_V1,
    GFP_FORMAT_VERSION_V2,
    MalformedPackageError,
    UnsupportedEvidenceError,
    VerificationMismatchError,
    VerificationState,
    canonical_json_bytes,
    parse_evidence_package,
    run_evidence_lifecycle,
    schema_commitment,
    verify_evidence_package,
)
from ghostframe.evidence.package import MANIFEST_NAME, RECEIPTS_NAME
from tests.evidence_support import PASSPHRASE
from tests.test_evidence_lifecycle import FIXTURES


def _members(package: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        return {item.filename: archive.read(item) for item in archive.infolist()}


def _rebuild(package: bytes, replacements: dict[str, bytes], *, update_receipts_hash: bool = False) -> bytes:
    members = _members(package)
    members.update(replacements)
    if update_receipts_hash:
        manifest = json.loads(members[MANIFEST_NAME])
        manifest["members"][RECEIPTS_NAME]["size"] = len(members[RECEIPTS_NAME])
        manifest["members"][RECEIPTS_NAME]["sha256"] = hashlib.sha256(members[RECEIPTS_NAME]).hexdigest()
        members[MANIFEST_NAME] = canonical_json_bytes(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return output.getvalue()


def test_schema_commitment_known_answer_and_domain_binding():
    assert schema_commitment() == "256e477d0dfc90edc2dc5a981f617ba94aadfc7ccccad9f5a354c3af2a99d937"


def test_default_is_immutable_v1_and_explicit_adapter_selects_v2():
    source, name = FIXTURES[1]()
    v1 = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False)
    v2 = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=InMemoryAnchor())
    parsed_v1 = parse_evidence_package(v1.evidence_package)
    parsed_v2 = parse_evidence_package(v2.evidence_package)
    assert parsed_v1.package_version == GFP_FORMAT_VERSION_V1
    assert parsed_v1.receipts["blockchain"]["inspection_anchor"] == {"state": "NOT_APPLICABLE"}
    assert v1.inspection_anchor.state == v1.verification_anchor.state == AnchorState.DISABLED
    assert parsed_v2.package_version == GFP_FORMAT_VERSION_V2
    assert parsed_v2.inspection_receipt.state == AnchorState.CONFIRMED
    assert parsed_v2.verification_receipt.state == AnchorState.CONFIRMED


@pytest.mark.parametrize("fixture", FIXTURES, ids=["jpeg", "png", "pdf", "docx"])
def test_two_stage_anchor_order_and_round_trip_for_all_formats(fixture):
    source, name = fixture()
    adapter = InMemoryAnchor()
    result = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=adapter)
    assert result.execution_trace == (
        "INSPECTION_FINALIZED", "INSPECTION_ANCHOR_ATTEMPTED", "INSPECTION_ANCHOR_CONFIRMED",
        "SANITIZATION_STARTED", "SANITIZATION_COMPLETED", "LOCAL_VERIFICATION_COMPLETED",
        "VERIFICATION_ANCHOR_ATTEMPTED", "VERIFICATION_ANCHOR_CONFIRMED", "PACKAGE_COMPLETED",
    )
    assert all(name not in json.dumps(event.to_dict()) for event in result.blockchain_events)
    offline = verify_evidence_package(result.evidence_package, PASSPHRASE, source_file=source, sanitized_file=result.sanitization_outcome.data)
    assert offline.locally_verified
    assert offline.recorded_inspection_anchor_state == "CONFIRMED"
    assert offline.inspection_blockchain_anchor.state == VerificationState.NOT_CHECKED
    online = verify_evidence_package(result.evidence_package, PASSPHRASE, blockchain_anchor=adapter)
    assert online.locally_verified
    assert online.inspection_blockchain_anchor.state == VerificationState.VERIFIED
    assert online.verification_blockchain_anchor.state == VerificationState.VERIFIED


class _FailingAnchor(InMemoryAnchor):
    def anchor_inspection(self, request):
        raise RuntimeError("synthetic sensitive rpc failure")


def test_anchor_failure_isolated_and_verification_not_requested():
    source, name = FIXTURES[0]()
    result = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=_FailingAnchor())
    assert result.local_verification.locally_verified
    assert result.inspection_anchor.state == AnchorState.FAILED
    assert result.verification_anchor.state == AnchorState.NOT_REQUESTED
    public = _members(result.evidence_package)[RECEIPTS_NAME]
    assert b"synthetic sensitive" not in public


def test_strict_cross_version_dispatch_rejects_v2_receipts_in_v1_manifest():
    source, name = FIXTURES[1]()
    v1 = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False)
    v2 = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=InMemoryAnchor())
    mixed = _rebuild(v1.evidence_package, {RECEIPTS_NAME: _members(v2.evidence_package)[RECEIPTS_NAME]}, update_receipts_hash=True)
    with pytest.raises((MalformedPackageError, UnsupportedEvidenceError, VerificationMismatchError)):
        parse_evidence_package(mixed)


def test_v2_rejects_v1_receipts_and_unknown_or_future_versions():
    source, name = FIXTURES[1]()
    v1 = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False)
    v2 = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=InMemoryAnchor())
    reverse_mixed = _rebuild(v2.evidence_package, {RECEIPTS_NAME: _members(v1.evidence_package)[RECEIPTS_NAME]}, update_receipts_hash=True)
    with pytest.raises(UnsupportedEvidenceError):
        parse_evidence_package(reverse_mixed)

    manifest = json.loads(_members(v2.evidence_package)[MANIFEST_NAME])
    manifest["package_version"] = "ghostframe-gfp/999.0"
    with pytest.raises(UnsupportedEvidenceError):
        parse_evidence_package(_rebuild(v2.evidence_package, {MANIFEST_NAME: canonical_json_bytes(manifest)}))

    receipts = json.loads(_members(v2.evidence_package)[RECEIPTS_NAME])
    receipts["receipts_version"] = "ghostframe-receipts/999.0"
    unknown_receipts = _rebuild(v2.evidence_package, {RECEIPTS_NAME: canonical_json_bytes(receipts)}, update_receipts_hash=True)
    with pytest.raises(UnsupportedEvidenceError):
        parse_evidence_package(unknown_receipts)

    receipts = json.loads(_members(v2.evidence_package)[RECEIPTS_NAME])
    receipts["blockchain"]["inspection_anchor"]["receipt_version"] = "ghostframe-blockchain-receipt/999.0"
    future_receipt = _rebuild(v2.evidence_package, {RECEIPTS_NAME: canonical_json_bytes(receipts)}, update_receipts_hash=True)
    with pytest.raises(MalformedPackageError):
        parse_evidence_package(future_receipt)


def test_receipt_substitution_from_another_operation_is_rejected_even_with_updated_member_hash():
    source, name = FIXTURES[1]()
    first = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=InMemoryAnchor())
    second = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=InMemoryAnchor())
    substituted = _rebuild(
        first.evidence_package,
        {RECEIPTS_NAME: _members(second.evidence_package)[RECEIPTS_NAME]},
        update_receipts_hash=True,
    )
    with pytest.raises(VerificationMismatchError, match="operation commitment"):
        parse_evidence_package(substituted)


def test_current_verification_does_not_treat_receipt_as_trust_root():
    source, name = FIXTURES[1]()
    writer = InMemoryAnchor()
    result = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=writer)
    independent_empty_state = InMemoryAnchor()
    checked = verify_evidence_package(result.evidence_package, PASSPHRASE, blockchain_anchor=independent_empty_state)
    assert checked.locally_verified
    assert checked.recorded_inspection_anchor_state == "CONFIRMED"
    assert checked.inspection_blockchain_anchor.state == VerificationState.FAILED


class _ChangedIdentityAnchor(InMemoryAnchor):
    def anchor_inspection(self, request):
        receipt = super().anchor_inspection(request)
        self.submitter = "0x" + "33" * 20
        return receipt


def test_changed_anchor_identity_fails_verification_without_losing_local_evidence():
    source, name = FIXTURES[1]()
    result = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=_ChangedIdentityAnchor())
    assert result.local_verification.locally_verified
    assert result.inspection_anchor.state == AnchorState.CONFIRMED
    assert result.verification_anchor.state == AnchorState.FAILED
    assert result.sanitization_outcome.data


def test_local_evm_full_lifecycle_gas_and_receipt_tamper_detection():
    web3_module = pytest.importorskip("web3")
    pytest.importorskip("eth_tester")
    from web3 import EthereumTesterProvider, Web3
    from ghostframe.blockchain.evm import EvmAnchor

    web3 = Web3(EthereumTesterProvider())
    adapter = EvmAnchor.deploy(web3)
    source, name = FIXTURES[1]()
    result = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=adapter)
    assert result.inspection_anchor.state == result.verification_anchor.state == AnchorState.CONFIRMED
    inspection_raw = web3.eth.get_transaction_receipt(result.inspection_anchor.transaction_hash)
    verification_raw = web3.eth.get_transaction_receipt(result.verification_anchor.transaction_hash)
    assert 50_000 < inspection_raw["gasUsed"] < 200_000
    assert 50_000 < verification_raw["gasUsed"] < 200_000
    checked = verify_evidence_package(result.evidence_package, PASSPHRASE, blockchain_anchor=adapter)
    assert checked.inspection_blockchain_anchor.state == VerificationState.VERIFIED
    assert checked.verification_blockchain_anchor.state == VerificationState.VERIFIED

    mutations = {
        "chain_id": 999999,
        "contract_address": "0x" + "f" * 40,
        "transaction_hash": "0x" + "f" * 64,
        "block_number": result.inspection_anchor.block_number + 1,
        "block_hash": "0x" + "f" * 64,
        "log_index": result.inspection_anchor.log_index + 1,
        "submitter_address": "0x" + "f" * 40,
    }
    for field, value in mutations.items():
        receipts = json.loads(_members(result.evidence_package)[RECEIPTS_NAME])
        receipts["blockchain"]["inspection_anchor"][field] = value
        altered = canonical_json_bytes(receipts)
        tampered = _rebuild(result.evidence_package, {RECEIPTS_NAME: altered}, update_receipts_hash=True)
        rejected = verify_evidence_package(tampered, PASSPHRASE, blockchain_anchor=adapter)
        assert rejected.locally_verified
        assert rejected.inspection_blockchain_anchor.state == VerificationState.FAILED, field


def test_pending_recorded_state_can_be_rechecked_as_confirmed_without_package_rewrite():
    pytest.importorskip("web3")
    pytest.importorskip("eth_tester")
    from web3 import EthereumTesterProvider, Web3
    from ghostframe.blockchain.evm import EvmAnchor

    web3 = Web3(EthereumTesterProvider())
    adapter = EvmAnchor.deploy(web3, confirmations_required=2)
    source, name = FIXTURES[1]()
    result = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False, blockchain_anchor=adapter)
    original_package = result.evidence_package
    parsed = parse_evidence_package(original_package)
    assert parsed.inspection_receipt.state == AnchorState.PENDING
    assert parsed.verification_receipt.state == AnchorState.PENDING
    web3.provider.ethereum_tester.mine_blocks(1)
    checked = verify_evidence_package(original_package, PASSPHRASE, blockchain_anchor=adapter)
    assert checked.recorded_inspection_anchor_state == "PENDING"
    assert checked.recorded_verification_anchor_state == "PENDING"
    assert checked.inspection_blockchain_anchor.state == VerificationState.VERIFIED
    assert checked.verification_blockchain_anchor.state == VerificationState.VERIFIED
    assert result.evidence_package == original_package
