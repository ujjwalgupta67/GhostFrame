from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from ghostframe import __version__
from ghostframe.models import InspectionResult, VerificationReport

from .canonical import normalize_utc_timestamp
from .hashing import INSPECTION_DOMAIN, VERIFICATION_DOMAIN, commit_canonical, new_operation_id, operation_commitment
from .projection import project_inspection, project_verification


EVIDENCE_SCHEMA_VERSION = "ghostframe-evidence/1.0"
CANONICALIZATION_VERSION = "ghostframe-canonical-json/1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True)
class FileEvidence:
    sha256: str
    size: int
    file_type: str

    def __post_init__(self) -> None:
        if not SHA256_RE.fullmatch(self.sha256):
            raise ValueError("File evidence requires a lowercase SHA-256 digest.")
        if self.size < 0:
            raise ValueError("File evidence size cannot be negative.")
        if not self.file_type:
            raise ValueError("File evidence requires a verified file type.")

    def to_dict(self) -> dict[str, Any]:
        return {"file_type": self.file_type, "sha256": self.sha256, "size": self.size}

    @classmethod
    def from_inspection(cls, result: InspectionResult) -> FileEvidence:
        return cls(result.file_sha256, result.file_size, result.file_type)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> FileEvidence:
        if not isinstance(value, Mapping) or set(value) != {"file_type", "sha256", "size"}:
            raise ValueError("Malformed file evidence.")
        if (
            not isinstance(value["file_type"], str)
            or not isinstance(value["sha256"], str)
            or not isinstance(value["size"], int)
            or isinstance(value["size"], bool)
        ):
            raise ValueError("Malformed file evidence values.")
        return cls(value["sha256"], value["size"], value["file_type"])


@dataclass(frozen=True)
class EvidenceRecord:
    operation_id: str
    created_at: datetime
    source_file: FileEvidence
    initial_inspection: Mapping[str, Any]
    sanitization_actions: tuple[str, ...] = ()
    sanitized_file: FileEvidence | None = None
    sanitized_inspection: Mapping[str, Any] | None = None
    verification: Mapping[str, Any] | None = None
    schema_version: str = EVIDENCE_SCHEMA_VERSION
    canonicalization_version: str = CANONICALIZATION_VERSION
    ghostframe_version: str = __version__

    def __post_init__(self) -> None:
        try:
            parsed = uuid.UUID(self.operation_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("Evidence operation ID must be a valid UUID.") from exc
        if parsed.version != 4 or str(parsed) != self.operation_id:
            raise ValueError("Evidence operation ID must be a canonical lowercase UUIDv4 value.")
        normalize_utc_timestamp(self.created_at)
        if self.schema_version != EVIDENCE_SCHEMA_VERSION:
            raise ValueError(f"Unsupported evidence schema: {self.schema_version}")
        if self.canonicalization_version != CANONICALIZATION_VERSION:
            raise ValueError(f"Unsupported canonicalization contract: {self.canonicalization_version}")
        object.__setattr__(self, "initial_inspection", _freeze_json(self.initial_inspection))
        if self.sanitized_inspection is not None:
            object.__setattr__(self, "sanitized_inspection", _freeze_json(self.sanitized_inspection))
        if self.verification is not None:
            object.__setattr__(self, "verification", _freeze_json(self.verification))
        complete = (self.sanitized_file, self.sanitized_inspection, self.verification)
        if any(item is not None for item in complete) and not all(item is not None for item in complete):
            raise ValueError("Completed evidence requires sanitized file, inspection, and verification together.")

    @property
    def public_operation_commitment(self) -> str:
        return operation_commitment(self.operation_id)

    @property
    def is_complete(self) -> bool:
        return self.verification is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonicalization_version": self.canonicalization_version,
            "created_at": normalize_utc_timestamp(self.created_at),
            "ghostframe_version": self.ghostframe_version,
            "initial_inspection": _thaw_json(self.initial_inspection),
            "operation_id": self.operation_id,
            "sanitization": {"actions": list(self.sanitization_actions)} if self.is_complete else None,
            "sanitized_file": self.sanitized_file.to_dict() if self.sanitized_file else None,
            "sanitized_inspection": _thaw_json(self.sanitized_inspection),
            "schema_version": self.schema_version,
            "source_file": self.source_file.to_dict(),
            "verification": _thaw_json(self.verification),
        }

    def inspection_commitment(self) -> str:
        projection = {
            "canonicalization_version": self.canonicalization_version,
            "created_at": normalize_utc_timestamp(self.created_at),
            "ghostframe_version": self.ghostframe_version,
            "initial_inspection": _thaw_json(self.initial_inspection),
            "operation_id": self.operation_id,
            "schema_version": self.schema_version,
            "source_file": self.source_file.to_dict(),
        }
        return commit_canonical(INSPECTION_DOMAIN, projection)

    def verification_commitment(self) -> str:
        if not self.is_complete:
            raise ValueError("Verification commitment requires completed lifecycle evidence.")
        return commit_canonical(VERIFICATION_DOMAIN, self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> EvidenceRecord:
        expected = {
            "canonicalization_version", "created_at", "ghostframe_version", "initial_inspection", "operation_id",
            "sanitization", "sanitized_file", "sanitized_inspection", "schema_version", "source_file", "verification",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("Malformed evidence record fields.")
        if not all(isinstance(value[key], str) for key in ("canonicalization_version", "created_at", "ghostframe_version", "operation_id", "schema_version")):
            raise ValueError("Malformed evidence record identity.")
        try:
            created_at = datetime.strptime(value["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError("Malformed evidence creation timestamp.") from exc
        if not isinstance(value["initial_inspection"], Mapping):
            raise ValueError("Malformed initial inspection evidence.")
        sanitization = value["sanitization"]
        if sanitization is None:
            actions: tuple[str, ...] = ()
        else:
            if not isinstance(sanitization, Mapping) or set(sanitization) != {"actions"} or not isinstance(sanitization["actions"], list) or not all(isinstance(item, str) for item in sanitization["actions"]):
                raise ValueError("Malformed sanitization evidence.")
            actions = tuple(sanitization["actions"])
        sanitized_file = None if value["sanitized_file"] is None else FileEvidence.from_dict(value["sanitized_file"])
        if value["sanitized_inspection"] is not None and not isinstance(value["sanitized_inspection"], Mapping):
            raise ValueError("Malformed sanitized inspection evidence.")
        if value["verification"] is not None and not isinstance(value["verification"], Mapping):
            raise ValueError("Malformed verification evidence.")
        return cls(
            operation_id=value["operation_id"], created_at=created_at,
            source_file=FileEvidence.from_dict(value["source_file"]), initial_inspection=dict(value["initial_inspection"]),
            sanitization_actions=actions, sanitized_file=sanitized_file,
            sanitized_inspection=None if value["sanitized_inspection"] is None else dict(value["sanitized_inspection"]),
            verification=None if value["verification"] is None else dict(value["verification"]),
            schema_version=value["schema_version"], canonicalization_version=value["canonicalization_version"],
            ghostframe_version=value["ghostframe_version"],
        )


def build_inspection_evidence(
    result: InspectionResult,
    *,
    operation_id: str | None = None,
    created_at: datetime | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        operation_id=operation_id or new_operation_id(),
        created_at=created_at or datetime.now(timezone.utc),
        source_file=FileEvidence.from_inspection(result),
        initial_inspection=project_inspection(result),
    )


def complete_lifecycle_evidence(
    record: EvidenceRecord,
    sanitized_result: InspectionResult,
    verification: VerificationReport,
    actions: list[str] | tuple[str, ...],
) -> EvidenceRecord:
    if record.is_complete:
        raise ValueError("Evidence lifecycle is already complete.")
    expected_original = (record.source_file.sha256, record.source_file.size, record.source_file.file_type)
    reported_original = (verification.original_sha256, verification.original_size, verification.original_type)
    if expected_original != reported_original:
        raise ValueError("Verification report does not match the evidence source file.")
    output = FileEvidence.from_inspection(sanitized_result)
    reported_output = (verification.sanitized_sha256, verification.sanitized_size, verification.sanitized_type)
    if (output.sha256, output.size, output.file_type) != reported_output:
        raise ValueError("Verification report does not match the sanitized evidence file.")
    return replace(
        record,
        sanitization_actions=tuple(sorted(set(actions))),
        sanitized_file=output,
        sanitized_inspection=project_inspection(sanitized_result),
        verification=project_verification(verification),
    )
