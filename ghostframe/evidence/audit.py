from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .canonical import normalize_utc_timestamp
from .errors import MalformedEvidenceError
from .hashing import AUDIT_EVENT_DOMAIN, commit_canonical


AUDIT_FORMAT_VERSION = "ghostframe-audit/1.0"
GENESIS_PREVIOUS_HASH = "0" * 64
MAX_AUDIT_EVENTS = 256
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EVENT_TYPES = frozenset({
    "INSPECTION_COMPLETED", "EVIDENCE_CREATED", "SANITIZATION_STARTED", "SANITIZATION_COMPLETED",
    "REINSPECTION_COMPLETED", "VERIFICATION_COMPLETED", "INSPECTION_ANCHORED", "VERIFICATION_ANCHORED",
})


@dataclass(frozen=True)
class AuditEvent:
    index: int
    event_type: str
    operation_commitment: str
    timestamp: datetime
    payload_commitment: str | None
    previous_event_hash: str
    event_hash: str
    audit_version: str = AUDIT_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.audit_version != AUDIT_FORMAT_VERSION:
            raise ValueError("Unsupported audit-event format.")
        if not isinstance(self.index, int) or isinstance(self.index, bool) or self.index < 0:
            raise ValueError("Audit-event index must be a non-negative integer.")
        if self.event_type not in EVENT_TYPES:
            raise ValueError("Unsupported audit-event type.")
        if not SHA256_RE.fullmatch(self.operation_commitment):
            raise ValueError("Audit event requires a valid operation commitment.")
        normalize_utc_timestamp(self.timestamp)
        if self.payload_commitment is not None and not SHA256_RE.fullmatch(self.payload_commitment):
            raise ValueError("Audit event requires a valid payload commitment.")
        if not SHA256_RE.fullmatch(self.previous_event_hash) or not SHA256_RE.fullmatch(self.event_hash):
            raise ValueError("Audit event requires valid chain hashes.")

    def hash_projection(self) -> dict[str, Any]:
        return {
            "audit_version": self.audit_version,
            "event_type": self.event_type,
            "index": self.index,
            "operation_commitment": self.operation_commitment,
            "payload_commitment": self.payload_commitment,
            "previous_event_hash": self.previous_event_hash,
            "timestamp": normalize_utc_timestamp(self.timestamp),
        }

    def calculated_hash(self) -> str:
        return commit_canonical(AUDIT_EVENT_DOMAIN, self.hash_projection())

    def to_dict(self) -> dict[str, Any]:
        return {**self.hash_projection(), "event_hash": self.event_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> AuditEvent:
        expected = {"audit_version", "event_hash", "event_type", "index", "operation_commitment", "payload_commitment", "previous_event_hash", "timestamp"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise MalformedEvidenceError("Malformed audit-event fields.")
        try:
            timestamp = datetime.strptime(value["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            return cls(
                index=value["index"], event_type=value["event_type"], operation_commitment=value["operation_commitment"],
                timestamp=timestamp, payload_commitment=value["payload_commitment"],
                previous_event_hash=value["previous_event_hash"], event_hash=value["event_hash"],
                audit_version=value["audit_version"],
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise MalformedEvidenceError("Malformed audit event.") from exc


@dataclass(frozen=True)
class AuditChainVerification:
    valid: bool
    event_count: int
    head_hash: str | None
    tail_bound: bool
    detail: str


@dataclass(frozen=True)
class AuditChain:
    operation_commitment: str
    events: tuple[AuditEvent, ...] = ()
    audit_version: str = AUDIT_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.audit_version != AUDIT_FORMAT_VERSION:
            raise ValueError("Unsupported audit-chain format.")
        if not SHA256_RE.fullmatch(self.operation_commitment):
            raise ValueError("Audit chain requires a valid operation commitment.")

    @property
    def head_hash(self) -> str | None:
        return self.events[-1].event_hash if self.events else None

    def append(
        self,
        event_type: str,
        *,
        payload_commitment: str | None = None,
        timestamp: datetime | None = None,
    ) -> AuditChain:
        if len(self.events) >= MAX_AUDIT_EVENTS:
            raise ValueError(f"Audit chain cannot exceed {MAX_AUDIT_EVENTS} events.")
        index = len(self.events)
        previous = self.events[-1].event_hash if self.events else GENESIS_PREVIOUS_HASH
        provisional = AuditEvent(
            index=index, event_type=event_type, operation_commitment=self.operation_commitment,
            timestamp=timestamp or datetime.now(timezone.utc), payload_commitment=payload_commitment,
            previous_event_hash=previous, event_hash=GENESIS_PREVIOUS_HASH,
        )
        event = AuditEvent(**{**provisional.__dict__, "event_hash": provisional.calculated_hash()})
        return AuditChain(self.operation_commitment, self.events + (event,))

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_version": self.audit_version,
            "events": [event.to_dict() for event in self.events],
            "operation_commitment": self.operation_commitment,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> AuditChain:
        if not isinstance(value, Mapping) or set(value) != {"audit_version", "events", "operation_commitment"}:
            raise MalformedEvidenceError("Malformed audit-chain fields.")
        if not isinstance(value["events"], list):
            raise MalformedEvidenceError("Malformed audit-chain events.")
        if len(value["events"]) > MAX_AUDIT_EVENTS:
            raise MalformedEvidenceError(f"Audit chain cannot exceed {MAX_AUDIT_EVENTS} events.")
        try:
            return cls(value["operation_commitment"], tuple(AuditEvent.from_dict(item) for item in value["events"]), value["audit_version"])
        except (ValueError, TypeError) as exc:
            raise MalformedEvidenceError("Malformed audit chain.") from exc


def verify_audit_chain(
    chain: AuditChain | Sequence[AuditEvent],
    *,
    expected_operation_commitment: str | None = None,
    expected_head: str | None = None,
) -> AuditChainVerification:
    events = chain.events if isinstance(chain, AuditChain) else tuple(chain)
    declared_operation = chain.operation_commitment if isinstance(chain, AuditChain) else expected_operation_commitment
    if not events:
        return AuditChainVerification(False, 0, None, False, "Audit chain contains no events.")
    operation = expected_operation_commitment or declared_operation or events[0].operation_commitment
    previous = GENESIS_PREVIOUS_HASH
    for index, event in enumerate(events):
        if event.index != index:
            return AuditChainVerification(False, len(events), events[-1].event_hash, False, f"Audit sequence discontinuity at index {index}.")
        if event.operation_commitment != operation or (declared_operation is not None and event.operation_commitment != declared_operation):
            return AuditChainVerification(False, len(events), events[-1].event_hash, False, f"Wrong operation commitment at index {index}.")
        if event.previous_event_hash != previous:
            return AuditChainVerification(False, len(events), events[-1].event_hash, False, f"Previous-event hash mismatch at index {index}.")
        if event.event_hash != event.calculated_hash():
            return AuditChainVerification(False, len(events), events[-1].event_hash, False, f"Invalid audit-event hash at index {index}.")
        previous = event.event_hash
    if expected_head is not None and previous != expected_head:
        return AuditChainVerification(False, len(events), previous, True, "Audit-chain head does not match the externally retained expected head.")
    if expected_head is not None:
        return AuditChainVerification(True, len(events), previous, True, "Audit chain and externally retained head are verified.")
    return AuditChainVerification(
        True, len(events), previous, False,
        "Internal audit links are valid, but tail truncation cannot be excluded without an externally retained expected head.",
    )
