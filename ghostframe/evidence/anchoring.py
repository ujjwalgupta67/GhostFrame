from __future__ import annotations

from dataclasses import dataclass

from ghostframe.blockchain.models import (
    AnchorReceipt,
    AnchorStage,
    AnchorState,
    InspectionAnchorRequest,
    VerificationAnchorRequest,
)

from .hashing import (
    BLOCKCHAIN_SCHEMA_DOMAIN,
    INSPECTION_DOMAIN,
    LIFECYCLE_DOMAIN,
    VERIFICATION_DOMAIN,
    commit_canonical,
)
from .models import CANONICALIZATION_VERSION, EVIDENCE_SCHEMA_VERSION, EvidenceRecord


LIFECYCLE_FORMAT_VERSION = "ghostframe-lifecycle/1.0"


def _bytes32(value: str) -> str:
    return "0x" + value


def schema_commitment() -> str:
    """Commit to the exact evidence and commitment schemas sent to an anchor."""

    return commit_canonical(
        BLOCKCHAIN_SCHEMA_DOMAIN,
        {
            "canonicalization_version": CANONICALIZATION_VERSION,
            "commitment_domains": {
                "inspection": INSPECTION_DOMAIN,
                "lifecycle": LIFECYCLE_DOMAIN,
                "verification": VERIFICATION_DOMAIN,
            },
            "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
            "lifecycle_version": LIFECYCLE_FORMAT_VERSION,
        },
    )


def lifecycle_commitment(
    *, operation_commitment: str, inspection_commitment: str,
    evidence_verification_commitment: str, audit_head: str,
) -> str:
    return commit_canonical(
        LIFECYCLE_DOMAIN,
        {
            "audit_head": audit_head,
            "evidence_verification_commitment": evidence_verification_commitment,
            "inspection_commitment": inspection_commitment,
            "lifecycle_version": LIFECYCLE_FORMAT_VERSION,
            "operation_commitment": operation_commitment,
        },
    )


def inspection_anchor_request(record: EvidenceRecord) -> InspectionAnchorRequest:
    return InspectionAnchorRequest(
        operation_commitment=_bytes32(record.public_operation_commitment),
        source_file_hash=_bytes32(record.source_file.sha256),
        inspection_commitment=_bytes32(record.inspection_commitment()),
        schema_commitment=_bytes32(schema_commitment()),
    )


def verification_anchor_request(
    record: EvidenceRecord, *, final_lifecycle_commitment: str,
) -> VerificationAnchorRequest:
    if record.sanitized_file is None:
        raise ValueError("Verification anchoring requires a sanitized file.")
    return VerificationAnchorRequest(
        operation_commitment=_bytes32(record.public_operation_commitment),
        sanitized_file_hash=_bytes32(record.sanitized_file.sha256),
        verification_commitment=_bytes32(record.verification_commitment()),
        final_lifecycle_commitment=_bytes32(final_lifecycle_commitment),
    )


@dataclass(frozen=True)
class BlockchainAuditEvent:
    """Privacy-safe controller event kept outside the committed evidence audit chain.

    Blockchain events cannot be inserted into the evidence chain being anchored
    without making the final anchor circular. They are therefore an outer
    lifecycle log and never change the approved audit hash contract.
    """

    event_type: str
    stage: AnchorStage
    state: AnchorState | None
    operation_commitment: str
    transaction_hash: str | None = None
    block_number: int | None = None
    confirmations: int = 0

    @classmethod
    def attempted(cls, stage: AnchorStage, operation_commitment: str) -> "BlockchainAuditEvent":
        return cls(f"{stage.value}_ANCHOR_ATTEMPTED", stage, None, operation_commitment)

    @classmethod
    def from_receipt(cls, receipt: AnchorReceipt) -> "BlockchainAuditEvent":
        return cls(
            f"{receipt.stage.value}_ANCHOR_{receipt.state.value}", receipt.stage,
            receipt.state, receipt.operation_commitment, receipt.transaction_hash,
            receipt.block_number, receipt.confirmations,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "event_type": self.event_type,
            "stage": self.stage.value,
            "state": self.state.value if self.state else None,
            "operation_commitment": self.operation_commitment,
            "transaction_hash": self.transaction_hash,
            "block_number": self.block_number,
            "confirmations": self.confirmations,
        }
