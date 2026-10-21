from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO

from ghostframe.blockchain.interface import BlockchainAnchor
from ghostframe.blockchain.models import AnchorState, AnchorVerification

from .anchoring import inspection_anchor_request, lifecycle_commitment, verification_anchor_request
from .audit import verify_audit_chain
from .crypto import decrypt_evidence
from .errors import EvidenceAuthenticationError, EvidenceError
from .hashing import hash_stream
from .package import parse_evidence_package


class VerificationState(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    NOT_PROVIDED = "NOT_PROVIDED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_CHECKED = "NOT_CHECKED"


@dataclass(frozen=True)
class VerificationCheck:
    state: VerificationState
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"state": self.state.value, "detail": self.detail}


@dataclass(frozen=True)
class EvidencePackageVerification:
    package_structure: VerificationCheck
    encrypted_evidence_authenticity: VerificationCheck
    evidence_commitment: VerificationCheck
    audit_chain: VerificationCheck
    source_file: VerificationCheck
    sanitized_file: VerificationCheck
    inspection_blockchain_anchor: VerificationCheck
    verification_blockchain_anchor: VerificationCheck
    recorded_inspection_anchor_state: str | None = None
    recorded_verification_anchor_state: str | None = None
    current_inspection_anchor: AnchorVerification | None = None
    current_verification_anchor: AnchorVerification | None = None

    @property
    def locally_verified(self) -> bool:
        required = (self.package_structure, self.encrypted_evidence_authenticity, self.evidence_commitment, self.audit_chain)
        artifacts = (self.source_file, self.sanitized_file)
        return all(item.state == VerificationState.VERIFIED for item in required) and all(item.state in {VerificationState.VERIFIED, VerificationState.NOT_PROVIDED} for item in artifacts)

    def to_dict(self) -> dict[str, object]:
        return {
            "locally_verified": self.locally_verified,
            "package_structure": self.package_structure.to_dict(),
            "encrypted_evidence_authenticity": self.encrypted_evidence_authenticity.to_dict(),
            "evidence_commitment": self.evidence_commitment.to_dict(),
            "audit_chain": self.audit_chain.to_dict(),
            "source_file": self.source_file.to_dict(),
            "sanitized_file": self.sanitized_file.to_dict(),
            "inspection_blockchain_anchor": self.inspection_blockchain_anchor.to_dict(),
            "verification_blockchain_anchor": self.verification_blockchain_anchor.to_dict(),
            "recorded_inspection_anchor_state": self.recorded_inspection_anchor_state,
            "recorded_verification_anchor_state": self.recorded_verification_anchor_state,
        }


ArtifactInput = bytes | str | Path | BinaryIO


def _artifact_hash(value: ArtifactInput) -> str:
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    if isinstance(value, (str, Path)):
        with Path(value).open("rb") as stream:
            return hash_stream(stream)
    if hasattr(value, "read"):
        return hash_stream(value)
    raise TypeError("Artifact must be bytes, a path, or a binary stream.")


def _artifact_check(value: ArtifactInput | None, expected: str, label: str) -> VerificationCheck:
    if value is None:
        return VerificationCheck(VerificationState.NOT_PROVIDED, f"{label} was not supplied for byte-level verification.")
    try:
        actual = _artifact_hash(value)
    except (OSError, TypeError, ValueError):
        return VerificationCheck(VerificationState.FAILED, f"{label} could not be hashed safely.")
    if actual != expected:
        return VerificationCheck(VerificationState.FAILED, f"{label} SHA-256 does not match the encrypted evidence record.")
    return VerificationCheck(VerificationState.VERIFIED, f"{label} bytes match the SHA-256 recorded in encrypted evidence; this does not prove authorship or origin.")


def _unchecked(detail: str) -> VerificationCheck:
    return VerificationCheck(VerificationState.NOT_CHECKED, detail)


def verify_evidence_package(
    package: bytes,
    passphrase: str,
    *,
    source_file: ArtifactInput | None = None,
    sanitized_file: ArtifactInput | None = None,
    expected_operation_commitment: str | None = None,
    expected_audit_head: str | None = None,
    blockchain_anchor: BlockchainAnchor | None = None,
) -> EvidencePackageVerification:
    blockchain = VerificationCheck(VerificationState.NOT_APPLICABLE, "This version 1 package has no blockchain receipts.")
    try:
        parsed = parse_evidence_package(package)
    except (EvidenceError, ValueError, TypeError) as exc:
        failed = VerificationCheck(VerificationState.FAILED, str(exc))
        return EvidencePackageVerification(
            failed, _unchecked("Encrypted evidence was not checked because package parsing failed."),
            _unchecked("Evidence commitments were not checked because package parsing failed."),
            _unchecked("Audit chain was not checked because package parsing failed."),
            _unchecked("Source file was not checked because package parsing failed."),
            _unchecked("Sanitized file was not checked because package parsing failed."), blockchain, blockchain,
        )
    package_ok = VerificationCheck(VerificationState.VERIFIED, "Package structure, limits, member allow-list, sizes, and member hashes are verified.")
    try:
        record = decrypt_evidence(parsed.encrypted_evidence, passphrase)
    except EvidenceAuthenticationError:
        auth_failed = VerificationCheck(VerificationState.FAILED, "Encrypted evidence authentication failed; the passphrase or evidence bytes are not valid.")
        return EvidencePackageVerification(
            package_ok, auth_failed, _unchecked("Evidence commitments require authenticated decryption."),
            _unchecked("Audit operation binding requires authenticated decryption."),
            _unchecked("Source file requires authenticated evidence."), _unchecked("Sanitized file requires authenticated evidence."),
            blockchain, blockchain,
        )
    except (EvidenceError, ValueError, TypeError) as exc:
        auth_failed = VerificationCheck(VerificationState.FAILED, str(exc))
        return EvidencePackageVerification(
            package_ok, auth_failed, _unchecked("Evidence commitments require a valid evidence record."),
            _unchecked("Audit operation binding requires a valid evidence record."),
            _unchecked("Source file requires a valid evidence record."), _unchecked("Sanitized file requires a valid evidence record."),
            blockchain, blockchain,
        )
    auth_ok = VerificationCheck(VerificationState.VERIFIED, "AES-256-GCM authenticated the encrypted canonical evidence.")
    manifest = parsed.manifest
    try:
        commitments_match = (
            manifest["operation_commitment"] == record.public_operation_commitment
            and manifest["inspection_commitment"] == record.inspection_commitment()
            and manifest["verification_commitment"] == record.verification_commitment()
            and (expected_operation_commitment is None or record.public_operation_commitment == expected_operation_commitment)
        )
    except (KeyError, TypeError, ValueError):
        commitments_match = False
    evidence_check = VerificationCheck(
        VerificationState.VERIFIED if commitments_match else VerificationState.FAILED,
        "Encrypted evidence matches the package commitments." if commitments_match else "Encrypted evidence does not match the expected package or operation commitment.",
    )
    audit = verify_audit_chain(
        parsed.audit_chain,
        expected_operation_commitment=record.public_operation_commitment,
        expected_head=expected_audit_head,
    )
    audit_check = VerificationCheck(VerificationState.VERIFIED if audit.valid else VerificationState.FAILED, audit.detail)
    source_check = _artifact_check(source_file, record.source_file.sha256, "Source file")
    if record.sanitized_file is None:
        sanitized_check = VerificationCheck(VerificationState.NOT_APPLICABLE, "Evidence record does not contain a sanitized file.")
    else:
        sanitized_check = _artifact_check(sanitized_file, record.sanitized_file.sha256, "Sanitized file")
    inspection_check = blockchain
    verification_check = blockchain
    recorded_inspection = None
    recorded_verification = None
    current_inspection = None
    current_verification = None
    if parsed.inspection_receipt is not None and parsed.verification_receipt is not None:
        recorded_inspection = parsed.inspection_receipt.state.value
        recorded_verification = parsed.verification_receipt.state.value
        if blockchain_anchor is None:
            offline = VerificationCheck(
                VerificationState.NOT_CHECKED,
                "A version 2 receipt is recorded, but current blockchain state was not checked because no independent adapter was supplied.",
            )
            inspection_check = offline
            verification_check = offline
        else:
            try:
                inspection_request = inspection_anchor_request(record)
                final_commitment = lifecycle_commitment(
                    operation_commitment=record.public_operation_commitment,
                    inspection_commitment=record.inspection_commitment(),
                    evidence_verification_commitment=record.verification_commitment(),
                    audit_head=parsed.audit_chain.head_hash or "",
                )
                verification_request = verification_anchor_request(record, final_lifecycle_commitment=final_commitment)
                current_inspection = blockchain_anchor.verify_anchor(inspection_request, parsed.inspection_receipt)
                inspection_check = _anchor_check(current_inspection, "inspection")
                if parsed.verification_receipt.state == AnchorState.NOT_REQUESTED:
                    verification_check = VerificationCheck(
                        VerificationState.NOT_APPLICABLE,
                        "Verification anchoring was not requested because the inspection stage did not establish an anchor.",
                    )
                else:
                    current_verification = blockchain_anchor.verify_anchor(verification_request, parsed.verification_receipt)
                    verification_check = _anchor_check(current_verification, "verification")
            except Exception:
                failed = VerificationCheck(VerificationState.FAILED, "Current blockchain verification failed safely without changing local evidence validity.")
                inspection_check = failed
                verification_check = failed
    return EvidencePackageVerification(
        package_ok, auth_ok, evidence_check, audit_check, source_check, sanitized_check,
        inspection_check, verification_check, recorded_inspection, recorded_verification,
        current_inspection, current_verification,
    )


def _anchor_check(result: AnchorVerification, label: str) -> VerificationCheck:
    if result.state == AnchorState.CONFIRMED:
        state = VerificationState.VERIFIED
    elif result.state == AnchorState.PENDING:
        state = VerificationState.NOT_CHECKED
    else:
        state = VerificationState.FAILED
    return VerificationCheck(state, f"Current {label} anchor state: {result.state.value}. {result.detail}")
