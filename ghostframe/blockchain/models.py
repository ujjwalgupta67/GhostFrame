from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse


BYTES32_RE = re.compile(r"^0x[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TX_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
RECEIPT_FORMAT_VERSION = "ghostframe-blockchain-receipt/1.0"
CONTRACT_INTERFACE_VERSION = "ghostframe-anchor/1.0"


class AnchorState(str, Enum):
    DISABLED = "DISABLED"
    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"


class AnchorStage(str, Enum):
    INSPECTION = "INSPECTION"
    VERIFICATION = "VERIFICATION"


class FailureCategory(str, Enum):
    DISABLED = "DISABLED"
    RPC_UNAVAILABLE = "RPC_UNAVAILABLE"
    RPC_TIMEOUT = "RPC_TIMEOUT"
    WRONG_CHAIN = "WRONG_CHAIN"
    MISSING_CONTRACT = "MISSING_CONTRACT"
    WRONG_CONTRACT = "WRONG_CONTRACT"
    WRONG_CODE = "WRONG_CODE"
    TRANSACTION_REJECTED = "TRANSACTION_REJECTED"
    TRANSACTION_REVERTED = "TRANSACTION_REVERTED"
    MISSING_RECEIPT = "MISSING_RECEIPT"
    MALFORMED_RECEIPT = "MALFORMED_RECEIPT"
    UNEXPECTED_EVENT = "UNEXPECTED_EVENT"
    EVENT_MISMATCH = "EVENT_MISMATCH"
    STATE_MISMATCH = "STATE_MISMATCH"
    INSUFFICIENT_CONFIRMATIONS = "INSUFFICIENT_CONFIRMATIONS"
    INVALID_REQUEST = "INVALID_REQUEST"


def _bytes32(value: str, label: str) -> None:
    if not isinstance(value, str) or not BYTES32_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase 0x-prefixed bytes32 value.")
    if value == "0x" + "0" * 64:
        raise ValueError(f"{label} cannot be zero.")


def _address(value: str, label: str = "Address") -> None:
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
        raise ValueError(f"{label} must be a 20-byte hexadecimal address.")


@dataclass(frozen=True)
class InspectionAnchorRequest:
    operation_commitment: str
    source_file_hash: str
    inspection_commitment: str
    schema_commitment: str

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            _bytes32(value, name.replace("_", " ").title())

    def to_dict(self) -> dict[str, str]:
        return {
            "operation_commitment": self.operation_commitment,
            "source_file_hash": self.source_file_hash,
            "inspection_commitment": self.inspection_commitment,
            "schema_commitment": self.schema_commitment,
        }


@dataclass(frozen=True)
class VerificationAnchorRequest:
    operation_commitment: str
    sanitized_file_hash: str
    verification_commitment: str
    final_lifecycle_commitment: str

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            _bytes32(value, name.replace("_", " ").title())

    def to_dict(self) -> dict[str, str]:
        return {
            "operation_commitment": self.operation_commitment,
            "sanitized_file_hash": self.sanitized_file_hash,
            "verification_commitment": self.verification_commitment,
            "final_lifecycle_commitment": self.final_lifecycle_commitment,
        }


AnchorRequest = InspectionAnchorRequest | VerificationAnchorRequest


@dataclass(frozen=True)
class AnchorRecord:
    operation_commitment: str
    inspection_submitter: str
    inspection_timestamp: int
    source_file_hash: str
    inspection_commitment: str
    schema_commitment: str
    verification_timestamp: int = 0
    sanitized_file_hash: str | None = None
    verification_commitment: str | None = None
    final_lifecycle_commitment: str | None = None

    def __post_init__(self) -> None:
        _bytes32(self.operation_commitment, "Operation commitment")
        _address(self.inspection_submitter, "Inspection submitter")
        if self.inspection_timestamp <= 0 or self.verification_timestamp < 0:
            raise ValueError("Anchor timestamps must be non-negative blockchain timestamps.")
        for label, value in (
            ("Source file hash", self.source_file_hash),
            ("Inspection commitment", self.inspection_commitment),
            ("Schema commitment", self.schema_commitment),
        ):
            _bytes32(value, label)
        verification_values = (self.sanitized_file_hash, self.verification_commitment, self.final_lifecycle_commitment)
        if self.verification_timestamp == 0 and any(value is not None for value in verification_values):
            raise ValueError("Unverified records cannot contain verification commitments.")
        if self.verification_timestamp > 0 and not all(value is not None for value in verification_values):
            raise ValueError("Verified records require all verification commitments.")
        for label, value in zip(
            ("Sanitized file hash", "Verification commitment", "Final lifecycle commitment"), verification_values
        ):
            if value is not None:
                _bytes32(value, label)

    @property
    def inspection_exists(self) -> bool:
        return True

    @property
    def verification_exists(self) -> bool:
        return self.verification_timestamp > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_commitment": self.operation_commitment,
            "inspection_submitter": self.inspection_submitter,
            "inspection_timestamp": self.inspection_timestamp,
            "source_file_hash": self.source_file_hash,
            "inspection_commitment": self.inspection_commitment,
            "schema_commitment": self.schema_commitment,
            "verification_timestamp": self.verification_timestamp,
            "sanitized_file_hash": self.sanitized_file_hash,
            "verification_commitment": self.verification_commitment,
            "final_lifecycle_commitment": self.final_lifecycle_commitment,
        }


@dataclass(frozen=True)
class AnchorReceipt:
    state: AnchorState
    stage: AnchorStage
    operation_commitment: str
    chain_id: int | None = None
    contract_address: str | None = None
    contract_code_hash: str | None = None
    contract_version: str | None = None
    transaction_hash: str | None = None
    block_number: int | None = None
    block_hash: str | None = None
    log_index: int | None = None
    confirmations: int = 0
    submitter_address: str | None = None
    failure_category: FailureCategory | None = None
    detail: str = ""
    receipt_version: str = RECEIPT_FORMAT_VERSION

    def __post_init__(self) -> None:
        _bytes32(self.operation_commitment, "Operation commitment")
        if self.chain_id is not None and self.chain_id <= 0:
            raise ValueError("Chain ID must be positive.")
        if self.contract_address is not None:
            _address(self.contract_address, "Contract address")
        if self.submitter_address is not None:
            _address(self.submitter_address, "Submitter address")
        for value, label in ((self.contract_code_hash, "Contract code hash"), (self.transaction_hash, "Transaction hash"), (self.block_hash, "Block hash")):
            if value is not None and not TX_HASH_RE.fullmatch(value):
                raise ValueError(f"{label} must be a lowercase 32-byte hexadecimal value.")
        if self.confirmations < 0:
            raise ValueError("Confirmations cannot be negative.")
        if self.block_number is not None and self.block_number < 0:
            raise ValueError("Block number cannot be negative.")
        if self.log_index is not None and self.log_index < 0:
            raise ValueError("Log index cannot be negative.")
        if self.state == AnchorState.FAILED and self.failure_category is None:
            raise ValueError("Failed receipts require a failure category.")
        allowed_nonfailure = {None, FailureCategory.INSUFFICIENT_CONFIRMATIONS}
        if self.state == AnchorState.DISABLED:
            allowed_nonfailure.add(FailureCategory.DISABLED)
        if self.state != AnchorState.FAILED and self.failure_category not in allowed_nonfailure:
            raise ValueError("Only failed receipts may contain a failure category.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_version": self.receipt_version,
            "state": self.state.value,
            "stage": self.stage.value,
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "contract_code_hash": self.contract_code_hash,
            "contract_version": self.contract_version,
            "transaction_hash": self.transaction_hash,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "log_index": self.log_index,
            "confirmations": self.confirmations,
            "submitter_address": self.submitter_address,
            "operation_commitment": self.operation_commitment,
            "failure_category": self.failure_category.value if self.failure_category else None,
            "detail": self.detail,
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AnchorReceipt:
        expected = {
            "receipt_version", "state", "stage", "chain_id", "contract_address", "contract_code_hash",
            "contract_version", "transaction_hash", "block_number", "block_hash", "log_index",
            "confirmations", "submitter_address", "operation_commitment", "failure_category", "detail",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("Malformed blockchain receipt fields.")
        if value["receipt_version"] != RECEIPT_FORMAT_VERSION:
            raise ValueError("Unsupported blockchain receipt version.")
        integer_fields = ("chain_id", "block_number", "log_index")
        if any(value[name] is not None and (not isinstance(value[name], int) or isinstance(value[name], bool)) for name in integer_fields):
            raise ValueError("Malformed blockchain receipt numeric values.")
        if not isinstance(value["confirmations"], int) or isinstance(value["confirmations"], bool):
            raise ValueError("Malformed blockchain receipt confirmation count.")
        if not isinstance(value["detail"], str):
            raise ValueError("Malformed blockchain receipt detail.")
        for name in ("contract_address", "contract_code_hash", "contract_version", "transaction_hash", "block_hash", "submitter_address"):
            if value[name] is not None and not isinstance(value[name], str):
                raise ValueError("Malformed blockchain receipt text values.")
        try:
            state = AnchorState(value["state"])
            stage = AnchorStage(value["stage"])
            category = None if value["failure_category"] is None else FailureCategory(value["failure_category"])
        except (TypeError, ValueError) as exc:
            raise ValueError("Malformed blockchain receipt state.") from exc
        return cls(
            state=state, stage=stage, operation_commitment=value["operation_commitment"],
            chain_id=value["chain_id"], contract_address=value["contract_address"],
            contract_code_hash=value["contract_code_hash"], contract_version=value["contract_version"],
            transaction_hash=value["transaction_hash"], block_number=value["block_number"],
            block_hash=value["block_hash"], log_index=value["log_index"],
            confirmations=value["confirmations"], submitter_address=value["submitter_address"],
            failure_category=category, detail=value["detail"], receipt_version=value["receipt_version"],
        )


@dataclass(frozen=True)
class AnchorVerification:
    state: AnchorState
    detail: str
    stage: AnchorStage
    operation_commitment: str
    record: AnchorRecord | None = None
    receipt: AnchorReceipt | None = None


@dataclass(frozen=True)
class AnchorHealth:
    state: AnchorState
    detail: str
    chain_id: int | None = None
    contract_address: str | None = None
    contract_code_hash: str | None = None
    contract_version: str | None = None


@dataclass(frozen=True)
class BlockchainConfig:
    enabled: bool = False
    rpc_url: str | None = None
    expected_chain_id: int | None = None
    contract_address: str | None = None
    expected_code_hash: str | None = None
    expected_contract_version: str = CONTRACT_INTERFACE_VERSION
    confirmations_required: int = 1
    receipt_timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if self.confirmations_required < 1:
            raise ValueError("At least one confirmation is required.")
        if self.receipt_timeout_seconds < 1 or self.receipt_timeout_seconds > 300:
            raise ValueError("Receipt timeout must be between 1 and 300 seconds.")
        if self.enabled:
            if not self.rpc_url or self.expected_chain_id is None or not self.contract_address or not self.expected_code_hash:
                raise ValueError("Enabled blockchain configuration requires RPC, chain, contract, and code identity.")
            parsed = urlparse(self.rpc_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("RPC URL must be an HTTP(S) URL.")
            if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
                raise ValueError("Phase 5 RPC URLs cannot contain credentials, paths, queries, or fragments.")
            if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("Phase 5 only permits a loopback local-EVM RPC endpoint.")
            if self.expected_chain_id <= 0:
                raise ValueError("Expected chain ID must be positive.")
            _address(self.contract_address, "Contract address")
            _bytes32(self.expected_code_hash, "Expected contract code hash")
