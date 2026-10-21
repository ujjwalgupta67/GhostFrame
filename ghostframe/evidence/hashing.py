from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Any, BinaryIO

from .canonical import canonical_json_bytes


INSPECTION_DOMAIN = "GhostFrame/inspection/v1"
VERIFICATION_DOMAIN = "GhostFrame/verification/v1"
LIFECYCLE_DOMAIN = "GhostFrame/lifecycle/v1"
AUDIT_EVENT_DOMAIN = "GhostFrame/audit-event/v1"
FILE_DOMAIN = "GhostFrame/file/v1"
OPERATION_DOMAIN = "GhostFrame/operation/v1"
BLOCKCHAIN_SCHEMA_DOMAIN = "GhostFrame/blockchain-schema/v1"
ALLOWED_DOMAINS = frozenset({INSPECTION_DOMAIN, VERIFICATION_DOMAIN, LIFECYCLE_DOMAIN, AUDIT_EVENT_DOMAIN, FILE_DOMAIN, OPERATION_DOMAIN, BLOCKCHAIN_SCHEMA_DOMAIN})
DEFAULT_CHUNK_SIZE = 1024 * 1024


def _commitment_input(domain: str, payload: bytes) -> bytes:
    if domain not in ALLOWED_DOMAINS:
        raise ValueError(f"Unregistered commitment domain: {domain!r}")
    domain_bytes = domain.encode("ascii")
    return b"GhostFrame-Commitment\x00" + len(domain_bytes).to_bytes(2, "big") + domain_bytes + len(payload).to_bytes(8, "big") + payload


def commit_bytes(domain: str, payload: bytes) -> str:
    """Return SHA-256 over an unambiguous, versioned domain and payload."""

    if not isinstance(payload, bytes):
        raise TypeError("Commitment payload must be bytes.")
    return hashlib.sha256(_commitment_input(domain, payload)).hexdigest()


def commit_canonical(domain: str, value: Any) -> str:
    return commit_bytes(domain, canonical_json_bytes(value))


def new_operation_id() -> str:
    """Return a cryptographically random UUIDv4 internal operation ID."""

    return str(uuid.uuid4())


def operation_commitment(operation_id: str) -> str:
    """Commit to an internal UUID without exposing its textual value."""

    try:
        parsed = uuid.UUID(operation_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("Operation ID must be a valid UUID.") from exc
    if parsed.version != 4:
        raise ValueError("Operation ID must be a UUIDv4 value.")
    return commit_bytes(OPERATION_DOMAIN, parsed.bytes)


def hash_stream(stream: BinaryIO, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Calculate a conventional file SHA-256 using bounded sequential reads."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive.")
    digest = hashlib.sha256()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise TypeError("Binary stream returned a non-bytes chunk.")
        digest.update(chunk)
    return digest.hexdigest()


def file_sha256(path: str | Path, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    with Path(path).open("rb") as stream:
        return hash_stream(stream, chunk_size=chunk_size)
