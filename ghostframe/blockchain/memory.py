from __future__ import annotations

import hashlib
import json

from .interface import BlockchainAnchor
from .models import (
    AnchorHealth,
    AnchorReceipt,
    AnchorRecord,
    AnchorRequest,
    AnchorStage,
    AnchorState,
    AnchorVerification,
    FailureCategory,
    InspectionAnchorRequest,
    VerificationAnchorRequest,
)


MEMORY_CHAIN_ID = 31337
MEMORY_CONTRACT = "0x" + "11" * 20
MEMORY_CODE_HASH = "0x" + hashlib.sha256(b"ghostframe-memory-adapter/1").hexdigest()


class InMemoryAnchor(BlockchainAnchor):
    """Deterministic state-machine simulation; it provides no blockchain security."""

    def __init__(self, *, submitter: str = "0x" + "22" * 20, start_timestamp: int = 1_900_000_000):
        self.submitter = submitter
        self._timestamp = start_timestamp
        self._sequence = 0
        self._records: dict[str, AnchorRecord] = {}
        self._receipts: dict[tuple[str, AnchorStage], AnchorReceipt] = {}

    def health(self) -> AnchorHealth:
        return AnchorHealth(AnchorState.CONFIRMED, "Deterministic in-memory simulation is available; it is not a blockchain.", MEMORY_CHAIN_ID, MEMORY_CONTRACT, MEMORY_CODE_HASH, "ghostframe-memory/1")

    def _receipt(self, request: AnchorRequest, stage: AnchorStage, state: AnchorState, detail: str, category: FailureCategory | None = None) -> AnchorReceipt:
        self._sequence += 1
        payload = json.dumps({"request": request.to_dict(), "sequence": self._sequence, "stage": stage.value}, sort_keys=True, separators=(",", ":")).encode()
        tx_hash = "0x" + hashlib.sha256(payload).hexdigest()
        receipt = AnchorReceipt(
            state=state, stage=stage, operation_commitment=request.operation_commitment,
            chain_id=MEMORY_CHAIN_ID, contract_address=MEMORY_CONTRACT,
            contract_code_hash=MEMORY_CODE_HASH, contract_version="ghostframe-memory/1",
            transaction_hash=tx_hash, block_number=self._sequence,
            block_hash="0x" + hashlib.sha256(b"block:" + payload).hexdigest(), log_index=0,
            confirmations=1, submitter_address=self.submitter,
            failure_category=category, detail=detail,
        )
        if state in {AnchorState.PENDING, AnchorState.CONFIRMED}:
            self._receipts[(request.operation_commitment, stage)] = receipt
        return receipt

    def anchor_inspection(self, request: InspectionAnchorRequest) -> AnchorReceipt:
        if request.operation_commitment in self._records:
            return self._receipt(request, AnchorStage.INSPECTION, AnchorState.FAILED, "Inspection anchor already exists.", FailureCategory.TRANSACTION_REVERTED)
        self._timestamp += 1
        self._records[request.operation_commitment] = AnchorRecord(
            operation_commitment=request.operation_commitment,
            inspection_submitter=self.submitter,
            inspection_timestamp=self._timestamp,
            source_file_hash=request.source_file_hash,
            inspection_commitment=request.inspection_commitment,
            schema_commitment=request.schema_commitment,
        )
        return self._receipt(request, AnchorStage.INSPECTION, AnchorState.CONFIRMED, "Inspection commitment registered in the in-memory simulation.")

    def anchor_verification(self, request: VerificationAnchorRequest) -> AnchorReceipt:
        current = self._records.get(request.operation_commitment)
        if current is None:
            return self._receipt(request, AnchorStage.VERIFICATION, AnchorState.FAILED, "Inspection anchor does not exist.", FailureCategory.TRANSACTION_REVERTED)
        if current.verification_exists:
            return self._receipt(request, AnchorStage.VERIFICATION, AnchorState.FAILED, "Verification anchor already exists.", FailureCategory.TRANSACTION_REVERTED)
        if current.inspection_submitter.lower() != self.submitter.lower():
            return self._receipt(request, AnchorStage.VERIFICATION, AnchorState.FAILED, "Verification submitter does not own the inspection anchor.", FailureCategory.TRANSACTION_REVERTED)
        self._timestamp += 1
        self._records[request.operation_commitment] = AnchorRecord(
            **{**current.to_dict(), "verification_timestamp": self._timestamp,
               "sanitized_file_hash": request.sanitized_file_hash,
               "verification_commitment": request.verification_commitment,
               "final_lifecycle_commitment": request.final_lifecycle_commitment}
        )
        return self._receipt(request, AnchorStage.VERIFICATION, AnchorState.CONFIRMED, "Verification commitment registered in the in-memory simulation.")

    def get_anchor(self, operation_commitment: str) -> AnchorRecord | None:
        return self._records.get(operation_commitment)

    def verify_anchor(self, request: AnchorRequest, receipt: AnchorReceipt | None = None) -> AnchorVerification:
        stage = AnchorStage.INSPECTION if isinstance(request, InspectionAnchorRequest) else AnchorStage.VERIFICATION
        record = self.get_anchor(request.operation_commitment)
        if record is None:
            return AnchorVerification(AnchorState.FAILED, "No matching anchor exists.", stage, request.operation_commitment, receipt=receipt)
        if isinstance(request, InspectionAnchorRequest):
            matches = (
                record.source_file_hash == request.source_file_hash
                and record.inspection_commitment == request.inspection_commitment
                and record.schema_commitment == request.schema_commitment
            )
        else:
            matches = record.verification_exists and (
                record.sanitized_file_hash == request.sanitized_file_hash
                and record.verification_commitment == request.verification_commitment
                and record.final_lifecycle_commitment == request.final_lifecycle_commitment
            )
        if receipt is not None:
            expected_receipt = self._receipts.get((request.operation_commitment, stage))
            immutable = (
                "chain_id", "contract_address", "contract_code_hash", "contract_version",
                "transaction_hash", "block_number", "block_hash", "log_index",
                "submitter_address", "operation_commitment", "stage",
            )
            matches = matches and expected_receipt is not None and all(
                getattr(receipt, field) == getattr(expected_receipt, field) for field in immutable
            ) and receipt.state in {AnchorState.PENDING, AnchorState.CONFIRMED}
        return AnchorVerification(
            AnchorState.CONFIRMED if matches else AnchorState.FAILED,
            "Commitments match the deterministic simulation state." if matches else "Stored commitments or receipt do not match the request.",
            stage, request.operation_commitment, record, receipt,
        )
