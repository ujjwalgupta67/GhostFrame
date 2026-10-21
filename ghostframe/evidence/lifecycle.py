from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from ghostframe.blockchain.disabled import DisabledAnchor
from ghostframe.blockchain.interface import BlockchainAnchor
from ghostframe.blockchain.models import AnchorReceipt, AnchorStage, AnchorState, FailureCategory
from ghostframe.core import SanitizationOutcome, inspect_file, sanitize_with_verification
from ghostframe.models import InspectionResult

from .audit import AuditChain, verify_audit_chain
from .crypto import encrypt_evidence
from .anchoring import (
    BlockchainAuditEvent,
    LIFECYCLE_FORMAT_VERSION,
    inspection_anchor_request,
    lifecycle_commitment,
    verification_anchor_request,
)
from .models import EvidenceRecord, build_inspection_evidence, complete_lifecycle_evidence
from .package import create_evidence_package
from .projection import project_inspection, project_verification
from .verification import EvidencePackageVerification, VerificationState, verify_evidence_package


class LifecycleState(str, Enum):
    CREATED = "CREATED"
    INSPECTED = "INSPECTED"
    SANITIZING = "SANITIZING"
    SANITIZED = "SANITIZED"
    REINSPECTED = "REINSPECTED"
    VERIFIED = "VERIFIED"
    PACKAGED = "PACKAGED"
    FAILED = "FAILED"


class LifecycleFailureCode(str, Enum):
    INVALID_TRANSITION = "INVALID_TRANSITION"
    INITIAL_INSPECTION_FAILED = "INITIAL_INSPECTION_FAILED"
    SOURCE_BINDING_MISMATCH = "SOURCE_BINDING_MISMATCH"
    EVIDENCE_CREATION_FAILED = "EVIDENCE_CREATION_FAILED"
    SANITIZATION_FAILED = "SANITIZATION_FAILED"
    BEFORE_INSPECTION_MISMATCH = "BEFORE_INSPECTION_MISMATCH"
    SANITIZED_BINDING_MISMATCH = "SANITIZED_BINDING_MISMATCH"
    REINSPECTION_FAILED = "REINSPECTION_FAILED"
    AFTER_INSPECTION_MISMATCH = "AFTER_INSPECTION_MISMATCH"
    VERIFICATION_MISMATCH = "VERIFICATION_MISMATCH"
    EVIDENCE_COMPLETION_FAILED = "EVIDENCE_COMPLETION_FAILED"
    ENCRYPTION_FAILED = "ENCRYPTION_FAILED"
    PACKAGE_CREATION_FAILED = "PACKAGE_CREATION_FAILED"
    SELF_VERIFICATION_FAILED = "SELF_VERIFICATION_FAILED"


class LifecycleExecutionError(RuntimeError):
    """Controlled lifecycle failure without source data, metadata, or secrets."""

    def __init__(self, code: LifecycleFailureCode, state: LifecycleState, detail: str):
        self.code = code
        self.state = state
        super().__init__(detail)


@dataclass(frozen=True)
class EvidenceLifecycleResult:
    operation_id: str
    public_operation_commitment: str
    original_inspection: InspectionResult
    sanitization_outcome: SanitizationOutcome
    evidence_record: EvidenceRecord
    audit_chain: AuditChain
    inspection_commitment: str
    verification_commitment: str
    expected_audit_head: str
    lifecycle_commitment: str
    encrypted_evidence: bytes
    evidence_package: bytes
    local_verification: EvidencePackageVerification
    inspection_anchor: AnchorReceipt
    verification_anchor: AnchorReceipt
    blockchain_events: tuple[BlockchainAuditEvent, ...]
    execution_trace: tuple[str, ...]
    state: LifecycleState = LifecycleState.PACKAGED


Inspector = Callable[..., InspectionResult]
Sanitizer = Callable[..., SanitizationOutcome]
Encryptor = Callable[[EvidenceRecord, str], bytes]
PackageCreator = Callable[..., bytes]
PackageVerifier = Callable[..., EvidencePackageVerification]
EvidenceCompleter = Callable[..., EvidenceRecord]


class EvidenceLifecycleService:
    """Memory-first orchestration over the existing GhostFrame engine.

    The service never persists artifacts and never stores a passphrase. Python
    cannot guarantee immediate erasure of immutable strings or intermediate
    cryptographic buffers from process memory.
    """

    def __init__(
        self,
        source_data: bytes,
        source_name: str,
        *,
        use_exiftool: bool = True,
        operation_id: str | None = None,
        created_at: datetime | None = None,
        inspector: Inspector = inspect_file,
        sanitizer: Sanitizer = sanitize_with_verification,
        encryptor: Encryptor = encrypt_evidence,
        package_creator: PackageCreator = create_evidence_package,
        package_verifier: PackageVerifier = verify_evidence_package,
        evidence_completer: EvidenceCompleter = complete_lifecycle_evidence,
        blockchain_anchor: BlockchainAnchor | None = None,
    ) -> None:
        if not isinstance(source_data, bytes):
            raise TypeError("Lifecycle source must be bytes.")
        if not isinstance(source_name, str) or not source_name:
            raise ValueError("Lifecycle source requires a display name.")
        self._source_data = source_data
        self._source_name = source_name
        self._use_exiftool = use_exiftool
        self._operation_id = operation_id
        self._created_at = created_at
        self._inspector = inspector
        self._sanitizer = sanitizer
        self._encryptor = encryptor
        self._package_creator = package_creator
        self._package_verifier = package_verifier
        self._evidence_completer = evidence_completer
        self._blockchain_anchor = blockchain_anchor if blockchain_anchor is not None else DisabledAnchor()
        self._blockchain_requested = blockchain_anchor is not None and not isinstance(blockchain_anchor, DisabledAnchor)
        self.state = LifecycleState.CREATED
        self.original_inspection: InspectionResult | None = None
        self.sanitization_outcome: SanitizationOutcome | None = None
        self.evidence_record: EvidenceRecord | None = None
        self.audit_chain: AuditChain | None = None
        self.inspection_commitment: str | None = None
        self.verification_commitment: str | None = None
        self.expected_audit_head: str | None = None
        self.lifecycle_commitment: str | None = None
        self.inspection_anchor: AnchorReceipt | None = None
        self.verification_anchor: AnchorReceipt | None = None
        self.blockchain_events: list[BlockchainAuditEvent] = []
        self.execution_trace: list[str] = []

    def _fail(self, code: LifecycleFailureCode, detail: str) -> None:
        self.state = LifecycleState.FAILED
        raise LifecycleExecutionError(code, self.state, detail) from None

    def _require(self, expected: LifecycleState) -> None:
        if self.state != expected:
            self._fail(
                LifecycleFailureCode.INVALID_TRANSITION,
                f"Lifecycle transition requires {expected.value} state.",
            )

    def inspect(self) -> EvidenceRecord:
        self._require(LifecycleState.CREATED)
        try:
            inspection = self._inspector(
                self._source_data,
                self._source_name,
                use_exiftool=self._use_exiftool,
            )
        except Exception:
            self._fail(LifecycleFailureCode.INITIAL_INSPECTION_FAILED, "Initial inspection failed.")
        source_hash = hashlib.sha256(self._source_data).hexdigest()
        if inspection.file_sha256 != source_hash or inspection.file_size != len(self._source_data):
            self._fail(LifecycleFailureCode.SOURCE_BINDING_MISMATCH, "Initial inspection does not match the source bytes.")
        try:
            record = build_inspection_evidence(
                inspection,
                operation_id=self._operation_id,
                created_at=self._created_at,
            )
            commitment = record.inspection_commitment()
            chain = AuditChain(record.public_operation_commitment)
            chain = chain.append("INSPECTION_COMPLETED", payload_commitment=commitment)
            chain = chain.append("EVIDENCE_CREATED", payload_commitment=commitment)
        except Exception:
            self._fail(LifecycleFailureCode.EVIDENCE_CREATION_FAILED, "Inspection evidence creation failed.")
        self.original_inspection = inspection
        self.evidence_record = record
        self.inspection_commitment = commitment
        self.audit_chain = chain
        self.state = LifecycleState.INSPECTED
        self.execution_trace.append("INSPECTION_FINALIZED")
        return record

    def _failed_receipt(self, stage: AnchorStage, detail: str) -> AnchorReceipt:
        assert self.evidence_record is not None
        return AnchorReceipt(
            state=AnchorState.FAILED,
            stage=stage,
            operation_commitment="0x" + self.evidence_record.public_operation_commitment,
            failure_category=FailureCategory.RPC_UNAVAILABLE,
            detail=detail,
        )

    def _not_requested_receipt(self, stage: AnchorStage, detail: str) -> AnchorReceipt:
        assert self.evidence_record is not None
        return AnchorReceipt(
            state=AnchorState.NOT_REQUESTED,
            stage=stage,
            operation_commitment="0x" + self.evidence_record.public_operation_commitment,
            detail=detail,
        )

    def _anchor_inspection(self) -> None:
        assert self.evidence_record is not None
        request = inspection_anchor_request(self.evidence_record)
        self.execution_trace.append("INSPECTION_ANCHOR_ATTEMPTED")
        self.blockchain_events.append(BlockchainAuditEvent.attempted(AnchorStage.INSPECTION, request.operation_commitment))
        try:
            receipt = self._blockchain_anchor.anchor_inspection(request)
        except Exception:
            receipt = self._failed_receipt(AnchorStage.INSPECTION, "Inspection anchoring failed safely; local processing continued.")
        if receipt.stage != AnchorStage.INSPECTION or receipt.operation_commitment != request.operation_commitment:
            receipt = self._failed_receipt(AnchorStage.INSPECTION, "Inspection adapter returned a receipt with invalid lifecycle binding.")
        self.inspection_anchor = receipt
        self.blockchain_events.append(BlockchainAuditEvent.from_receipt(receipt))
        self.execution_trace.append(f"INSPECTION_ANCHOR_{receipt.state.value}")

    def sanitize_and_complete(self) -> EvidenceRecord:
        self._require(LifecycleState.INSPECTED)
        assert self.original_inspection is not None
        assert self.evidence_record is not None
        assert self.audit_chain is not None
        assert self.inspection_commitment is not None
        if self.inspection_anchor is None:
            self._anchor_inspection()
        initial_projection = project_inspection(self.original_inspection)
        self.audit_chain = self.audit_chain.append(
            "SANITIZATION_STARTED",
            payload_commitment=self.inspection_commitment,
        )
        self.state = LifecycleState.SANITIZING
        self.execution_trace.append("SANITIZATION_STARTED")
        try:
            outcome = self._sanitizer(
                self._source_data,
                self._source_name,
                copy.deepcopy(self.original_inspection),
                use_exiftool=self._use_exiftool,
            )
        except Exception:
            self._fail(LifecycleFailureCode.SANITIZATION_FAILED, "Sanitization failed.")
        if not isinstance(outcome, SanitizationOutcome):
            self._fail(LifecycleFailureCode.SANITIZATION_FAILED, "Sanitization returned an invalid outcome.")
        if project_inspection(outcome.before) != initial_projection:
            self._fail(LifecycleFailureCode.BEFORE_INSPECTION_MISMATCH, "Sanitization used a different source inspection.")
        source_identity = (hashlib.sha256(self._source_data).hexdigest(), len(self._source_data), self.original_inspection.file_type)
        before_identity = (outcome.before.file_sha256, outcome.before.file_size, outcome.before.file_type)
        if source_identity != before_identity:
            self._fail(LifecycleFailureCode.BEFORE_INSPECTION_MISMATCH, "Sanitization source binding is inconsistent.")
        if not isinstance(outcome.data, bytes):
            self._fail(LifecycleFailureCode.SANITIZED_BINDING_MISMATCH, "Sanitization output is not bytes.")
        sanitized_hash = hashlib.sha256(outcome.data).hexdigest()
        if outcome.after.file_sha256 != sanitized_hash or outcome.after.file_size != len(outcome.data):
            self._fail(LifecycleFailureCode.SANITIZED_BINDING_MISMATCH, "Sanitized inspection does not match the output bytes.")
        self.sanitization_outcome = outcome
        self.state = LifecycleState.SANITIZED
        self.audit_chain = self.audit_chain.append("SANITIZATION_COMPLETED", payload_commitment=sanitized_hash)
        self.execution_trace.append("SANITIZATION_COMPLETED")

        try:
            independent_after = self._inspector(
                outcome.data,
                outcome.filename,
                use_exiftool=self._use_exiftool,
            )
        except Exception:
            self._fail(LifecycleFailureCode.REINSPECTION_FAILED, "Independent output re-inspection failed.")
        if project_inspection(independent_after) != project_inspection(outcome.after):
            self._fail(LifecycleFailureCode.AFTER_INSPECTION_MISMATCH, "Sanitized inspection is inconsistent with independent re-inspection.")
        self.state = LifecycleState.REINSPECTED
        self.audit_chain = self.audit_chain.append("REINSPECTION_COMPLETED", payload_commitment=sanitized_hash)

        try:
            from ghostframe.comparison import compare_results

            expected_verification = compare_results(
                copy.deepcopy(outcome.before),
                copy.deepcopy(independent_after),
                list(outcome.actions),
            )
        except Exception:
            self._fail(LifecycleFailureCode.VERIFICATION_MISMATCH, "Verification consistency check failed.")
        if project_verification(expected_verification) != project_verification(outcome.verification):
            self._fail(LifecycleFailureCode.VERIFICATION_MISMATCH, "Verification report is inconsistent with the before and after inspections.")
        try:
            completed = self._evidence_completer(
                self.evidence_record,
                outcome.after,
                outcome.verification,
                outcome.actions,
            )
            verification_commitment = completed.verification_commitment()
            chain = self.audit_chain.append(
                "VERIFICATION_COMPLETED",
                payload_commitment=verification_commitment,
            )
            chain_result = verify_audit_chain(
                chain,
                expected_operation_commitment=completed.public_operation_commitment,
                expected_head=chain.head_hash,
            )
            if not chain_result.valid or chain.head_hash is None:
                raise ValueError("invalid completed audit chain")
            final_lifecycle_commitment = lifecycle_commitment(
                operation_commitment=completed.public_operation_commitment,
                inspection_commitment=self.inspection_commitment,
                evidence_verification_commitment=verification_commitment,
                audit_head=chain.head_hash,
            )
        except Exception:
            self._fail(LifecycleFailureCode.EVIDENCE_COMPLETION_FAILED, "Completed evidence creation failed.")
        self.evidence_record = completed
        self.audit_chain = chain
        self.verification_commitment = verification_commitment
        self.expected_audit_head = chain.head_hash
        self.lifecycle_commitment = final_lifecycle_commitment
        self.state = LifecycleState.VERIFIED
        self.execution_trace.append("LOCAL_VERIFICATION_COMPLETED")
        return completed

    def _anchor_final_verification(self) -> None:
        assert self.evidence_record is not None
        assert self.lifecycle_commitment is not None
        assert self.inspection_anchor is not None
        if not self._blockchain_requested:
            request = verification_anchor_request(
                self.evidence_record,
                final_lifecycle_commitment=self.lifecycle_commitment,
            )
            self.verification_anchor = self._blockchain_anchor.anchor_verification(request)
            self.blockchain_events.append(BlockchainAuditEvent.from_receipt(self.verification_anchor))
            self.execution_trace.append("VERIFICATION_ANCHOR_DISABLED")
            return
        if self.inspection_anchor.state not in {AnchorState.CONFIRMED, AnchorState.PENDING}:
            self.verification_anchor = self._not_requested_receipt(
                AnchorStage.VERIFICATION,
                "Verification anchoring was not requested because inspection anchoring did not establish a usable transaction.",
            )
            self.blockchain_events.append(BlockchainAuditEvent.from_receipt(self.verification_anchor))
            self.execution_trace.append("VERIFICATION_ANCHOR_NOT_REQUESTED")
            return
        request = verification_anchor_request(
            self.evidence_record,
            final_lifecycle_commitment=self.lifecycle_commitment,
        )
        self.execution_trace.append("VERIFICATION_ANCHOR_ATTEMPTED")
        self.blockchain_events.append(BlockchainAuditEvent.attempted(AnchorStage.VERIFICATION, request.operation_commitment))
        try:
            receipt = self._blockchain_anchor.anchor_verification(request)
        except Exception:
            receipt = self._failed_receipt(AnchorStage.VERIFICATION, "Verification anchoring failed safely; local evidence remained valid.")
        if receipt.stage != AnchorStage.VERIFICATION or receipt.operation_commitment != request.operation_commitment:
            receipt = self._failed_receipt(AnchorStage.VERIFICATION, "Verification adapter returned a receipt with invalid lifecycle binding.")
        self.verification_anchor = receipt
        self.blockchain_events.append(BlockchainAuditEvent.from_receipt(receipt))
        self.execution_trace.append(f"VERIFICATION_ANCHOR_{receipt.state.value}")

    def package(self, passphrase: str) -> EvidenceLifecycleResult:
        self._require(LifecycleState.VERIFIED)
        assert self.original_inspection is not None
        assert self.sanitization_outcome is not None
        assert self.evidence_record is not None
        assert self.audit_chain is not None
        assert self.inspection_commitment is not None
        assert self.verification_commitment is not None
        assert self.expected_audit_head is not None
        assert self.lifecycle_commitment is not None
        if self.inspection_anchor is None:
            self._anchor_inspection()
        if self.verification_anchor is None:
            self._anchor_final_verification()
        assert self.inspection_anchor is not None and self.verification_anchor is not None
        try:
            encrypted = self._encryptor(self.evidence_record, passphrase)
        except Exception:
            self._fail(LifecycleFailureCode.ENCRYPTION_FAILED, "Evidence encryption failed.")
        try:
            package_options: dict[str, Any] = {"encrypted_evidence": encrypted}
            if self._blockchain_requested:
                package_options.update(
                    inspection_receipt=self.inspection_anchor,
                    verification_receipt=self.verification_anchor,
                )
            package = self._package_creator(self.evidence_record, passphrase, self.audit_chain, **package_options)
        except Exception:
            self._fail(LifecycleFailureCode.PACKAGE_CREATION_FAILED, "Evidence package creation failed.")
        try:
            verify_options: dict[str, Any] = {
                "source_file": self._source_data,
                "sanitized_file": self.sanitization_outcome.data,
                "expected_operation_commitment": self.evidence_record.public_operation_commitment,
                "expected_audit_head": self.expected_audit_head,
            }
            if self._blockchain_requested:
                verify_options["blockchain_anchor"] = self._blockchain_anchor
            verification = self._package_verifier(package, passphrase, **verify_options)
            required = (
                verification.package_structure,
                verification.encrypted_evidence_authenticity,
                verification.evidence_commitment,
                verification.audit_chain,
                verification.source_file,
                verification.sanitized_file,
            )
            if not all(check.state == VerificationState.VERIFIED for check in required):
                raise ValueError("required local verification failed")
        except Exception:
            self._fail(LifecycleFailureCode.SELF_VERIFICATION_FAILED, "Final independent package verification failed.")
        self.state = LifecycleState.PACKAGED
        self.execution_trace.append("PACKAGE_COMPLETED")
        return EvidenceLifecycleResult(
            operation_id=self.evidence_record.operation_id,
            public_operation_commitment=self.evidence_record.public_operation_commitment,
            original_inspection=self.original_inspection,
            sanitization_outcome=self.sanitization_outcome,
            evidence_record=self.evidence_record,
            audit_chain=self.audit_chain,
            inspection_commitment=self.inspection_commitment,
            verification_commitment=self.verification_commitment,
            expected_audit_head=self.expected_audit_head,
            lifecycle_commitment=self.lifecycle_commitment,
            encrypted_evidence=encrypted,
            evidence_package=package,
            local_verification=verification,
            inspection_anchor=self.inspection_anchor,
            verification_anchor=self.verification_anchor,
            blockchain_events=tuple(self.blockchain_events),
            execution_trace=tuple(self.execution_trace),
        )

    def run(self, passphrase: str) -> EvidenceLifecycleResult:
        self.inspect()
        self.sanitize_and_complete()
        return self.package(passphrase)


def run_evidence_lifecycle(
    source_data: bytes,
    source_name: str,
    passphrase: str,
    *,
    use_exiftool: bool = True,
    **service_options: Any,
) -> EvidenceLifecycleResult:
    """Run one complete in-memory GhostFrame evidence lifecycle."""

    service = EvidenceLifecycleService(
        source_data,
        source_name,
        use_exiftool=use_exiftool,
        **service_options,
    )
    return service.run(passphrase)
