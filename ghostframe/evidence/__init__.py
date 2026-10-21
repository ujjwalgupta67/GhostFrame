"""Deterministic evidence foundations for GhostFrame.

This package is intentionally independent of persistence, encryption, UI code,
and blockchain clients.  It converts existing GhostFrame results into a
versioned evidence record and produces domain-separated commitments.
"""

from .canonical import CanonicalizationError, canonical_json_bytes, normalize_utc_timestamp
from .audit import (
    AUDIT_FORMAT_VERSION,
    GENESIS_PREVIOUS_HASH,
    AuditChain,
    AuditChainVerification,
    AuditEvent,
    verify_audit_chain,
)
from .crypto import (
    GFE_FORMAT_VERSION,
    decrypt_evidence,
    decrypt_evidence_bytes,
    encrypt_evidence,
)
from .errors import (
    EvidenceAuthenticationError,
    EvidenceError,
    EvidenceResourceLimitError,
    MalformedEvidenceError,
    MalformedPackageError,
    UnsupportedEvidenceError,
    VerificationMismatchError,
)
from .hashing import (
    AUDIT_EVENT_DOMAIN,
    FILE_DOMAIN,
    INSPECTION_DOMAIN,
    LIFECYCLE_DOMAIN,
    OPERATION_DOMAIN,
    VERIFICATION_DOMAIN,
    BLOCKCHAIN_SCHEMA_DOMAIN,
    commit_bytes,
    commit_canonical,
    file_sha256,
    hash_stream,
    new_operation_id,
    operation_commitment,
)
from .models import (
    CANONICALIZATION_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    EvidenceRecord,
    FileEvidence,
    build_inspection_evidence,
    complete_lifecycle_evidence,
)
from .projection import project_inspection, project_verification
from .package import (
    GFP_FORMAT_VERSION, GFP_FORMAT_VERSION_V1, GFP_FORMAT_VERSION_V2,
    RECEIPTS_FORMAT_VERSION_V1, RECEIPTS_FORMAT_VERSION_V2,
    ParsedEvidencePackage, create_evidence_package, parse_evidence_package,
)
from .anchoring import BlockchainAuditEvent, schema_commitment
from .verification import EvidencePackageVerification, VerificationCheck, VerificationState, verify_evidence_package
from .lifecycle import (
    EvidenceLifecycleResult,
    EvidenceLifecycleService,
    LifecycleExecutionError,
    LifecycleFailureCode,
    LifecycleState,
    lifecycle_commitment,
    run_evidence_lifecycle,
)
from .store import (
    EvidenceCollisionError,
    EvidencePersistenceError,
    EvidenceStore,
    PersistedEvidence,
    evidence_artifact_names,
)

__all__ = [
    "AUDIT_EVENT_DOMAIN",
    "AUDIT_FORMAT_VERSION",
    "BLOCKCHAIN_SCHEMA_DOMAIN",
    "BlockchainAuditEvent",
    "CANONICALIZATION_VERSION",
    "CanonicalizationError",
    "AuditChain",
    "AuditChainVerification",
    "AuditEvent",
    "EVIDENCE_SCHEMA_VERSION",
    "EvidenceRecord",
    "EvidenceAuthenticationError",
    "EvidenceError",
    "EvidencePackageVerification",
    "EvidenceResourceLimitError",
    "FILE_DOMAIN",
    "FileEvidence",
    "INSPECTION_DOMAIN",
    "LIFECYCLE_DOMAIN",
    "GENESIS_PREVIOUS_HASH",
    "GFE_FORMAT_VERSION",
    "GFP_FORMAT_VERSION",
    "GFP_FORMAT_VERSION_V1",
    "GFP_FORMAT_VERSION_V2",
    "RECEIPTS_FORMAT_VERSION_V1",
    "RECEIPTS_FORMAT_VERSION_V2",
    "MalformedEvidenceError",
    "MalformedPackageError",
    "OPERATION_DOMAIN",
    "ParsedEvidencePackage",
    "UnsupportedEvidenceError",
    "VERIFICATION_DOMAIN",
    "VerificationCheck",
    "VerificationMismatchError",
    "VerificationState",
    "EvidenceLifecycleResult",
    "EvidenceLifecycleService",
    "LifecycleExecutionError",
    "LifecycleFailureCode",
    "LifecycleState",
    "lifecycle_commitment",
    "EvidenceCollisionError",
    "EvidencePersistenceError",
    "EvidenceStore",
    "PersistedEvidence",
    "evidence_artifact_names",
    "build_inspection_evidence",
    "canonical_json_bytes",
    "commit_bytes",
    "commit_canonical",
    "complete_lifecycle_evidence",
    "create_evidence_package",
    "decrypt_evidence",
    "decrypt_evidence_bytes",
    "encrypt_evidence",
    "file_sha256",
    "hash_stream",
    "new_operation_id",
    "normalize_utc_timestamp",
    "operation_commitment",
    "parse_evidence_package",
    "project_inspection",
    "project_verification",
    "verify_audit_chain",
    "verify_evidence_package",
    "run_evidence_lifecycle",
    "schema_commitment",
]
