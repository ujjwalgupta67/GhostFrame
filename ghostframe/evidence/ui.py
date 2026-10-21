from __future__ import annotations

import hashlib
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ghostframe.blockchain.interface import BlockchainAnchor
from ghostframe.blockchain.models import AnchorReceipt
from ghostframe.core import SanitizationOutcome

from .crypto import MIN_PASSPHRASE_LENGTH
from .lifecycle import EvidenceLifecycleResult, LifecycleExecutionError, run_evidence_lifecycle
from .store import EvidenceStore, PersistedEvidence, evidence_artifact_names
from .verification import EvidencePackageVerification, verify_evidence_package


EVIDENCE_RESULT_KEY = "gf_evidence_result"
EVIDENCE_REQUEST_KEY = "gf_evidence_request_key"
EVIDENCE_PERSISTED_KEY = "gf_evidence_persisted"
EVIDENCE_UI_PREFIXES = ("gf_evidence_", "gf_verify_")


class EvidenceUIError(RuntimeError):
    """A concise error safe to display in the local UI."""

    def __init__(self, detail: str, *, sanitization_succeeded: bool = False):
        self.sanitization_succeeded = sanitization_succeeded
        super().__init__(detail)


@dataclass(frozen=True)
class EvidenceDownloadNames:
    package: str
    encrypted_evidence: str


@dataclass(frozen=True)
class EvidenceUISessionResult:
    """Minimum successful lifecycle material retained for UI downloads."""

    public_operation_commitment: str
    sanitization_outcome: SanitizationOutcome
    encrypted_evidence: bytes
    evidence_package: bytes
    local_verification: EvidencePackageVerification
    inspection_anchor: AnchorReceipt
    verification_anchor: AnchorReceipt
    package_version: str


def evidence_request_key(source_data: bytes, *, use_exiftool: bool, blockchain_fingerprint: str = "disabled") -> str:
    return f"{hashlib.sha256(source_data).hexdigest()}:{use_exiftool}:{blockchain_fingerprint}"


def evidence_download_names(operation_commitment: str) -> EvidenceDownloadNames:
    package, encrypted = evidence_artifact_names(operation_commitment)
    return EvidenceDownloadNames(package, encrypted)


def clear_evidence_session(state: MutableMapping[str, Any]) -> None:
    for key in list(state):
        if key.startswith(EVIDENCE_UI_PREFIXES):
            del state[key]


def generate_evidence_once(
    state: MutableMapping[str, Any],
    *,
    source_data: bytes,
    source_name: str,
    passphrase: str,
    confirmation: str,
    use_exiftool: bool,
    runner: Callable[..., EvidenceLifecycleResult] = run_evidence_lifecycle,
    blockchain_anchor: BlockchainAnchor | None = None,
    blockchain_fingerprint: str = "disabled",
) -> EvidenceUISessionResult:
    request_key = evidence_request_key(source_data, use_exiftool=use_exiftool, blockchain_fingerprint=blockchain_fingerprint)
    if state.get(EVIDENCE_REQUEST_KEY) == request_key and isinstance(state.get(EVIDENCE_RESULT_KEY), EvidenceUISessionResult):
        return state[EVIDENCE_RESULT_KEY]
    if passphrase == "":
        raise EvidenceUIError("Enter an evidence passphrase.")
    if passphrase != confirmation:
        raise EvidenceUIError("The passphrase confirmation does not match.")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise EvidenceUIError(f"Use at least {MIN_PASSPHRASE_LENGTH} characters for the evidence passphrase.")
    try:
        options = {"use_exiftool": use_exiftool}
        if blockchain_anchor is not None:
            options["blockchain_anchor"] = blockchain_anchor
        lifecycle = runner(source_data, source_name, passphrase, **options)
    except LifecycleExecutionError as exc:
        completed_sanitization = exc.code.value in {
            "REINSPECTION_FAILED",
            "AFTER_INSPECTION_MISMATCH",
            "VERIFICATION_MISMATCH",
            "EVIDENCE_COMPLETION_FAILED",
            "ENCRYPTION_FAILED",
            "PACKAGE_CREATION_FAILED",
            "SELF_VERIFICATION_FAILED",
        }
        detail = (
            "A sanitized copy was created in memory, but the evidence package could not be completed."
            if completed_sanitization
            else "GhostFrame could not complete sanitization and verifiable evidence generation."
        )
        raise EvidenceUIError(detail, sanitization_succeeded=completed_sanitization) from None
    except Exception:
        raise EvidenceUIError("Evidence generation failed safely. The original file was not modified.") from None
    result = EvidenceUISessionResult(
        public_operation_commitment=lifecycle.public_operation_commitment,
        sanitization_outcome=lifecycle.sanitization_outcome,
        encrypted_evidence=lifecycle.encrypted_evidence,
        evidence_package=lifecycle.evidence_package,
        local_verification=lifecycle.local_verification,
        inspection_anchor=lifecycle.inspection_anchor,
        verification_anchor=lifecycle.verification_anchor,
        package_version="ghostframe-gfp/2.0" if blockchain_anchor is not None else "ghostframe-gfp/1.0",
    )
    state[EVIDENCE_RESULT_KEY] = result
    state[EVIDENCE_REQUEST_KEY] = request_key
    state.pop(EVIDENCE_PERSISTED_KEY, None)
    return result


def verify_package_for_ui(
    *,
    package: bytes,
    passphrase: str,
    source_file: bytes | None = None,
    sanitized_file: bytes | None = None,
    verifier: Callable[..., EvidencePackageVerification] = verify_evidence_package,
    blockchain_anchor: BlockchainAnchor | None = None,
) -> EvidencePackageVerification:
    if not isinstance(package, bytes) or not package:
        raise EvidenceUIError("Choose a GhostFrame evidence package to verify.")
    if passphrase == "":
        raise EvidenceUIError("Enter the evidence passphrase.")
    try:
        options: dict[str, Any] = {
            "source_file": source_file,
            "sanitized_file": sanitized_file,
        }
        if blockchain_anchor is not None:
            options["blockchain_anchor"] = blockchain_anchor
        return verifier(
            package,
            passphrase,
            **options,
        )
    except Exception:
        raise EvidenceUIError("The evidence package could not be verified safely.") from None


def persist_evidence_result(
    result: EvidenceUISessionResult,
    *,
    root: str | Path | None = None,
    include_encrypted_evidence: bool = False,
    store_factory: Callable[..., EvidenceStore] = EvidenceStore,
) -> PersistedEvidence:
    store = store_factory(root)
    return store.persist(
        operation_commitment=result.public_operation_commitment,
        evidence_package=result.evidence_package,
        encrypted_evidence=result.encrypted_evidence,
        include_encrypted_evidence=include_encrypted_evidence,
    )
