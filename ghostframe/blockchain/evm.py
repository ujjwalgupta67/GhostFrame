from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from .interface import BlockchainAnchor
from .models import (
    AnchorHealth,
    AnchorReceipt,
    AnchorRecord,
    AnchorRequest,
    AnchorStage,
    AnchorState,
    AnchorVerification,
    BlockchainConfig,
    FailureCategory,
    InspectionAnchorRequest,
    VerificationAnchorRequest,
)


ZERO_BYTES32 = "0x" + "0" * 64


def _artifact() -> dict[str, Any]:
    path = Path(__file__).with_name("contracts") / "GhostFrameAnchor.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    required = {"abi", "bytecode", "deployed_bytecode", "deployed_code_sha256", "contract_version"}
    if not required.issubset(value):
        raise RuntimeError("GhostFrame anchor contract artifact is incomplete.")
    return value


def _hex(value: Any) -> str:
    if isinstance(value, str):
        return value.lower()
    return "0x" + bytes(value).hex()


def _code_hash(code: bytes) -> str:
    return "0x" + hashlib.sha256(bytes(code)).hexdigest()


def _stage(request: AnchorRequest) -> AnchorStage:
    return AnchorStage.INSPECTION if isinstance(request, InspectionAnchorRequest) else AnchorStage.VERIFICATION


class EvmAnchor(BlockchainAnchor):
    """Commitment adapter for a configured local EVM and known contract code."""

    def __init__(self, config: BlockchainConfig, *, web3: Any | None = None, submitter: str | None = None):
        if not config.enabled:
            raise ValueError("EVM adapter requires enabled blockchain configuration.")
        if web3 is None:
            try:
                from web3 import HTTPProvider, Web3
            except ImportError as exc:
                raise RuntimeError("Install requirements-blockchain.txt to use the EVM adapter.") from exc
            web3 = Web3(HTTPProvider(config.rpc_url, request_kwargs={"timeout": config.receipt_timeout_seconds}))
        self.web3 = web3
        self.config = config
        self.submitter = submitter
        artifact = _artifact()
        self.contract = self.web3.eth.contract(address=self.web3.to_checksum_address(config.contract_address), abi=artifact["abi"])
        self.deployment_receipt: Any | None = None

    @classmethod
    def deploy(cls, web3: Any, *, submitter: str | None = None, confirmations_required: int = 1) -> EvmAnchor:
        artifact = _artifact()
        sender = submitter or web3.eth.accounts[0]
        factory = web3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
        tx_hash = factory.constructor().transact({"from": sender})
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        if int(receipt["status"]) != 1:
            raise RuntimeError("Local GhostFrame anchor contract deployment reverted.")
        address = receipt["contractAddress"]
        code_hash = _code_hash(web3.eth.get_code(address))
        config = BlockchainConfig(
            enabled=True,
            rpc_url="http://127.0.0.1:8545",
            expected_chain_id=int(web3.eth.chain_id),
            contract_address=address,
            expected_code_hash=code_hash,
            expected_contract_version=artifact["contract_version"],
            confirmations_required=confirmations_required,
        )
        adapter = cls(config, web3=web3, submitter=sender)
        adapter.deployment_receipt = receipt
        return adapter

    def _failure_health(self, category: FailureCategory, detail: str) -> AnchorHealth:
        return AnchorHealth(AnchorState.FAILED, f"{category.value}: {detail}")

    def health(self) -> AnchorHealth:
        try:
            if hasattr(self.web3, "is_connected") and not self.web3.is_connected():
                return self._failure_health(FailureCategory.RPC_UNAVAILABLE, "Configured local RPC is unavailable.")
            chain_id = int(self.web3.eth.chain_id)
            if chain_id != self.config.expected_chain_id:
                return AnchorHealth(AnchorState.FAILED, "Configured RPC returned the wrong chain ID.", chain_id=chain_id)
            code = bytes(self.web3.eth.get_code(self.config.contract_address))
            if not code:
                return AnchorHealth(AnchorState.FAILED, "No contract is deployed at the configured address.", chain_id, self.config.contract_address)
            code_hash = _code_hash(code)
            if code_hash != self.config.expected_code_hash:
                return AnchorHealth(AnchorState.FAILED, "Deployed contract bytecode identity does not match.", chain_id, self.config.contract_address, code_hash)
            version = self.contract.functions.CONTRACT_VERSION().call()
            if version != self.config.expected_contract_version:
                return AnchorHealth(AnchorState.FAILED, "Contract interface version does not match.", chain_id, self.config.contract_address, code_hash, str(version))
            return AnchorHealth(AnchorState.CONFIRMED, "Expected local chain and GhostFrame anchor contract are available.", chain_id, self.config.contract_address, code_hash, version)
        except TimeoutError:
            return self._failure_health(FailureCategory.RPC_TIMEOUT, "Configured local RPC timed out.")
        except Exception:
            return self._failure_health(FailureCategory.RPC_UNAVAILABLE, "Configured local RPC could not be verified.")

    def _base_failure(self, request: AnchorRequest, category: FailureCategory, detail: str) -> AnchorReceipt:
        return AnchorReceipt(
            AnchorState.FAILED, _stage(request), request.operation_commitment,
            failure_category=category, detail=detail,
        )

    def _preflight(self, request: AnchorRequest) -> AnchorReceipt | None:
        health = self.health()
        if health.state == AnchorState.CONFIRMED:
            return None
        detail = health.detail
        if "chain ID" in detail:
            category = FailureCategory.WRONG_CHAIN
        elif "No contract" in detail:
            category = FailureCategory.MISSING_CONTRACT
        elif "bytecode" in detail:
            category = FailureCategory.WRONG_CODE
        elif "version" in detail:
            category = FailureCategory.WRONG_CONTRACT
        elif "timed out" in detail:
            category = FailureCategory.RPC_TIMEOUT
        else:
            category = FailureCategory.RPC_UNAVAILABLE
        return self._base_failure(request, category, detail)

    def anchor_inspection(self, request: InspectionAnchorRequest) -> AnchorReceipt:
        function = self.contract.functions.anchorInspection(
            request.operation_commitment, request.source_file_hash,
            request.inspection_commitment, request.schema_commitment,
        )
        return self._submit(request, function)

    def anchor_verification(self, request: VerificationAnchorRequest) -> AnchorReceipt:
        function = self.contract.functions.anchorVerification(
            request.operation_commitment, request.sanitized_file_hash,
            request.verification_commitment, request.final_lifecycle_commitment,
        )
        return self._submit(request, function)

    def _submit(self, request: AnchorRequest, function: Any) -> AnchorReceipt:
        failed = self._preflight(request)
        if failed:
            return failed
        sender = self.submitter
        if sender is None:
            try:
                sender = self.web3.eth.accounts[0]
            except Exception:
                return self._base_failure(request, FailureCategory.TRANSACTION_REJECTED, "No local development account is available.")
        try:
            tx_hash = function.transact({"from": sender})
        except Exception as exc:
            reverted = exc.__class__.__name__ in {"ContractLogicError", "TransactionFailed"}
            category = FailureCategory.TRANSACTION_REVERTED if reverted else FailureCategory.TRANSACTION_REJECTED
            detail = "Local EVM reverted the anchor transaction." if reverted else "Local EVM rejected the anchor transaction submission."
            return self._base_failure(request, category, detail)
        try:
            raw = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=self.config.receipt_timeout_seconds)
        except Exception as exc:
            if not isinstance(exc, TimeoutError) and exc.__class__.__name__ != "TimeExhausted":
                return self._base_failure(request, FailureCategory.MISSING_RECEIPT, "Transaction receipt could not be retrieved.")
            return AnchorReceipt(
                AnchorState.PENDING, _stage(request), request.operation_commitment,
                chain_id=self.config.expected_chain_id, contract_address=self.config.contract_address,
                contract_code_hash=self.config.expected_code_hash,
                contract_version=self.config.expected_contract_version,
                transaction_hash=_hex(tx_hash), submitter_address=sender,
                failure_category=FailureCategory.INSUFFICIENT_CONFIRMATIONS,
                detail="Transaction was submitted but a receipt was not available before timeout.",
            )
        return self._evaluate_receipt(request, raw)

    def _event_values(self, request: AnchorRequest, raw: Any) -> tuple[dict[str, Any] | None, int | None]:
        event = self.contract.events.InspectionAnchored if isinstance(request, InspectionAnchorRequest) else self.contract.events.VerificationAnchored
        logs = event().process_receipt(raw)
        if len(logs) != 1:
            return None, None
        return dict(logs[0]["args"]), int(logs[0]["logIndex"])

    def _expected_event(self, request: AnchorRequest, submitter: str, timestamp: int) -> dict[str, Any]:
        if isinstance(request, InspectionAnchorRequest):
            return {
                "operationCommitment": request.operation_commitment,
                "submitter": submitter,
                "sourceFileHash": request.source_file_hash,
                "inspectionCommitment": request.inspection_commitment,
                "schemaCommitment": request.schema_commitment,
                "timestamp": timestamp,
            }
        return {
            "operationCommitment": request.operation_commitment,
            "submitter": submitter,
            "sanitizedFileHash": request.sanitized_file_hash,
            "verificationCommitment": request.verification_commitment,
            "finalLifecycleCommitment": request.final_lifecycle_commitment,
            "timestamp": timestamp,
        }

    def _event_matches(self, actual: dict[str, Any], expected: dict[str, Any]) -> bool:
        normalized = {key: (_hex(value) if key != "timestamp" and key != "submitter" else value) for key, value in actual.items()}
        return all(
            (str(normalized[key]).lower() == str(value).lower()) if key != "timestamp" else int(normalized[key]) == int(value)
            for key, value in expected.items()
        )

    def _evaluate_receipt(self, request: AnchorRequest, raw: Any) -> AnchorReceipt:
        try:
            if int(raw["status"]) != 1:
                return self._base_failure(request, FailureCategory.TRANSACTION_REVERTED, "Anchor transaction reverted.")
            block_number = int(raw["blockNumber"])
            current_block = int(self.web3.eth.block_number)
            confirmations = max(0, current_block - block_number + 1)
            submitter = str(self.web3.eth.get_transaction(raw["transactionHash"])["from"])
            event_values, log_index = self._event_values(request, raw)
            if event_values is None:
                return self._base_failure(request, FailureCategory.UNEXPECTED_EVENT, "Expected anchor event was not emitted exactly once.")
            record = self.get_anchor(request.operation_commitment)
            if record is None:
                return self._base_failure(request, FailureCategory.STATE_MISMATCH, "Contract state is missing after the transaction.")
            timestamp = record.inspection_timestamp if isinstance(request, InspectionAnchorRequest) else record.verification_timestamp
            if not self._event_matches(event_values, self._expected_event(request, submitter, timestamp)):
                return self._base_failure(request, FailureCategory.EVENT_MISMATCH, "Anchor event arguments do not match the requested commitments.")
            verified = self._record_matches(request, record)
            if not verified:
                return self._base_failure(request, FailureCategory.STATE_MISMATCH, "Stored contract state does not match the requested commitments.")
            state = AnchorState.CONFIRMED if confirmations >= self.config.confirmations_required else AnchorState.PENDING
            category = None if state == AnchorState.CONFIRMED else FailureCategory.INSUFFICIENT_CONFIRMATIONS
            detail = "Anchor transaction, event, and stored state are confirmed." if state == AnchorState.CONFIRMED else "Anchor transaction is valid but requires more confirmations."
            return AnchorReceipt(
                state, _stage(request), request.operation_commitment,
                chain_id=self.config.expected_chain_id, contract_address=self.config.contract_address,
                contract_code_hash=self.config.expected_code_hash,
                contract_version=self.config.expected_contract_version,
                transaction_hash=_hex(raw["transactionHash"]), block_number=block_number,
                block_hash=_hex(raw["blockHash"]), log_index=log_index,
                confirmations=confirmations, submitter_address=submitter,
                failure_category=category, detail=detail,
            )
        except Exception:
            return self._base_failure(request, FailureCategory.MALFORMED_RECEIPT, "Transaction receipt could not be validated safely.")

    def get_anchor(self, operation_commitment: str) -> AnchorRecord | None:
        try:
            value = self.contract.functions.getRecord(operation_commitment).call()
        except Exception:
            return None
        if int(value[1]) == 0:
            return None
        return AnchorRecord(
            operation_commitment=operation_commitment,
            inspection_submitter=str(value[0]), inspection_timestamp=int(value[1]),
            source_file_hash=_hex(value[2]), inspection_commitment=_hex(value[3]), schema_commitment=_hex(value[4]),
            verification_timestamp=int(value[5]),
            sanitized_file_hash=None if _hex(value[6]) == ZERO_BYTES32 else _hex(value[6]),
            verification_commitment=None if _hex(value[7]) == ZERO_BYTES32 else _hex(value[7]),
            final_lifecycle_commitment=None if _hex(value[8]) == ZERO_BYTES32 else _hex(value[8]),
        )

    def _record_matches(self, request: AnchorRequest, record: AnchorRecord) -> bool:
        if isinstance(request, InspectionAnchorRequest):
            return (
                record.source_file_hash == request.source_file_hash
                and record.inspection_commitment == request.inspection_commitment
                and record.schema_commitment == request.schema_commitment
            )
        return record.verification_exists and (
            record.sanitized_file_hash == request.sanitized_file_hash
            and record.verification_commitment == request.verification_commitment
            and record.final_lifecycle_commitment == request.final_lifecycle_commitment
        )

    def verify_anchor(self, request: AnchorRequest, receipt: AnchorReceipt | None = None) -> AnchorVerification:
        stage = _stage(request)
        health = self.health()
        if health.state != AnchorState.CONFIRMED:
            return AnchorVerification(AnchorState.FAILED, health.detail, stage, request.operation_commitment, receipt=receipt)
        if receipt is not None:
            if (
                receipt.chain_id != self.config.expected_chain_id
                or receipt.contract_address is None
                or receipt.contract_address.lower() != self.config.contract_address.lower()
                or receipt.contract_code_hash != self.config.expected_code_hash
                or receipt.contract_version != self.config.expected_contract_version
                or receipt.stage != stage
                or receipt.operation_commitment != request.operation_commitment
                or not receipt.transaction_hash
            ):
                return AnchorVerification(AnchorState.FAILED, "Receipt domain identity does not match the configured chain and contract.", stage, request.operation_commitment, receipt=receipt)
            try:
                raw = self.web3.eth.get_transaction_receipt(receipt.transaction_hash)
            except Exception:
                return AnchorVerification(AnchorState.FAILED, "Receipt transaction is unavailable from the configured RPC.", stage, request.operation_commitment, receipt=receipt)
            refreshed = self._evaluate_receipt(request, raw)
            immutable_matches = (
                refreshed.transaction_hash == receipt.transaction_hash
                and refreshed.block_number == receipt.block_number
                and refreshed.block_hash == receipt.block_hash
                and refreshed.log_index == receipt.log_index
                and refreshed.submitter_address is not None
                and receipt.submitter_address is not None
                and refreshed.submitter_address.lower() == receipt.submitter_address.lower()
            )
            if not immutable_matches:
                return AnchorVerification(
                    AnchorState.FAILED,
                    "Recorded receipt identity does not match the configured RPC transaction and event.",
                    stage,
                    request.operation_commitment,
                    self.get_anchor(request.operation_commitment),
                    refreshed,
                )
            if refreshed.state != AnchorState.CONFIRMED:
                return AnchorVerification(refreshed.state, refreshed.detail, stage, request.operation_commitment, self.get_anchor(request.operation_commitment), refreshed)
            receipt = refreshed
        record = self.get_anchor(request.operation_commitment)
        matches = record is not None and self._record_matches(request, record)
        return AnchorVerification(
            AnchorState.CONFIRMED if matches else AnchorState.FAILED,
            "Configured local-EVM state matches the expected commitments." if matches else "Configured local-EVM state does not match the expected commitments.",
            stage, request.operation_commitment, record, receipt,
        )
