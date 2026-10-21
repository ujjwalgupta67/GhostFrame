from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from ghostframe.blockchain.models import AnchorReceipt, AnchorStage, AnchorState, FailureCategory

from .audit import AUDIT_FORMAT_VERSION, AuditChain, verify_audit_chain
from .canonical import CanonicalizationError, canonical_json_bytes
from .crypto import GFE_FORMAT_VERSION, MAX_GFE_SIZE, decrypt_evidence, encrypt_evidence
from .errors import EvidenceResourceLimitError, MalformedPackageError, UnsupportedEvidenceError, VerificationMismatchError
from .models import EvidenceRecord


GFP_FORMAT_VERSION_V1 = "ghostframe-gfp/1.0"
GFP_FORMAT_VERSION_V2 = "ghostframe-gfp/2.0"
RECEIPTS_FORMAT_VERSION_V1 = "ghostframe-receipts/1.0"
RECEIPTS_FORMAT_VERSION_V2 = "ghostframe-receipts/2.0"
# Backward-compatible names continue to identify the immutable default format.
GFP_FORMAT_VERSION = GFP_FORMAT_VERSION_V1
RECEIPTS_FORMAT_VERSION = RECEIPTS_FORMAT_VERSION_V1
MANIFEST_NAME = "manifest.json"
EVIDENCE_NAME = "evidence.gfe"
RECEIPTS_NAME = "receipts.json"
REQUIRED_MEMBERS = frozenset({MANIFEST_NAME, EVIDENCE_NAME, RECEIPTS_NAME})
MAX_PACKAGE_COMPRESSED_SIZE = 36 * 1024 * 1024
MAX_PACKAGE_EXPANDED_SIZE = 34 * 1024 * 1024
MAX_ENTRY_COUNT = 3
MAX_COMPRESSION_RATIO = 100
RATIO_CHECK_THRESHOLD = 1024 * 1024
MEMBER_LIMITS = {MANIFEST_NAME: 32 * 1024, EVIDENCE_NAME: MAX_GFE_SIZE, RECEIPTS_NAME: 2 * 1024 * 1024}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ParsedEvidencePackage:
    manifest: Mapping[str, Any]
    encrypted_evidence: bytes
    receipts: Mapping[str, Any]
    audit_chain: AuditChain
    package_version: str = GFP_FORMAT_VERSION_V1
    inspection_receipt: AnchorReceipt | None = None
    verification_receipt: AnchorReceipt | None = None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_object(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in values:
            if key in output:
                raise MalformedPackageError(f"Duplicate key in {label}.")
            output[key] = value
        return output

    def reject_number(value: str) -> Any:
        raise MalformedPackageError(f"Unsupported numeric value in {label}.")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=reject_number, parse_constant=reject_number)
    except MalformedPackageError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedPackageError(f"Malformed {label} JSON.") from exc
    if not isinstance(value, dict):
        raise MalformedPackageError(f"{label} root must be an object.")
    try:
        if canonical_json_bytes(value) != raw:
            raise MalformedPackageError(f"{label} must use canonical JSON.")
    except CanonicalizationError as exc:
        raise MalformedPackageError(f"Invalid {label} values.") from exc
    return value


def _receipts_v1(chain: AuditChain) -> dict[str, Any]:
    return {
        "audit_chain": chain.to_dict(),
        "blockchain": {
            "inspection_anchor": {"state": "NOT_APPLICABLE"},
            "verification_anchor": {"state": "NOT_APPLICABLE"},
        },
        "receipts_version": RECEIPTS_FORMAT_VERSION,
    }


def _receipts_v2(chain: AuditChain, inspection: AnchorReceipt, verification: AnchorReceipt) -> dict[str, Any]:
    return {
        "audit_chain": chain.to_dict(),
        "blockchain": {
            "inspection_anchor": inspection.to_dict(),
            "verification_anchor": verification.to_dict(),
        },
        "receipts_version": RECEIPTS_FORMAT_VERSION_V2,
    }


def _member_descriptor(name: str, data: bytes, format_version: str) -> dict[str, Any]:
    return {"format_version": format_version, "name": name, "sha256": _sha256(data), "size": len(data)}


def create_evidence_package(
    record: EvidenceRecord,
    passphrase: str,
    audit_chain: AuditChain,
    *,
    encrypted_evidence: bytes | None = None,
    inspection_receipt: AnchorReceipt | None = None,
    verification_receipt: AnchorReceipt | None = None,
) -> bytes:
    if not record.is_complete:
        raise ValueError("Evidence package requires a completed sanitization lifecycle.")
    audit_result = verify_audit_chain(audit_chain, expected_operation_commitment=record.public_operation_commitment)
    if not audit_result.valid:
        raise VerificationMismatchError("Audit chain cannot be packaged because it is invalid.")
    if encrypted_evidence is None:
        encrypted = encrypt_evidence(record, passphrase)
    else:
        if not isinstance(encrypted_evidence, bytes):
            raise TypeError("Encrypted evidence must be bytes.")
        authenticated_record = decrypt_evidence(encrypted_evidence, passphrase)
        if authenticated_record.to_dict() != record.to_dict():
            raise VerificationMismatchError("Encrypted evidence does not match the package evidence record.")
        encrypted = encrypted_evidence
    blockchain_receipts = (inspection_receipt, verification_receipt)
    if all(item is None for item in blockchain_receipts):
        package_version = GFP_FORMAT_VERSION_V1
        receipts_version = RECEIPTS_FORMAT_VERSION_V1
        receipts_payload = _receipts_v1(audit_chain)
    elif all(item is not None for item in blockchain_receipts):
        assert inspection_receipt is not None and verification_receipt is not None
        operation = "0x" + record.public_operation_commitment
        if inspection_receipt.stage != AnchorStage.INSPECTION or verification_receipt.stage != AnchorStage.VERIFICATION:
            raise VerificationMismatchError("Blockchain receipt stages do not match the package lifecycle.")
        if inspection_receipt.operation_commitment != operation or verification_receipt.operation_commitment != operation:
            raise VerificationMismatchError("Blockchain receipts do not match the package operation commitment.")
        _validate_recorded_receipt(inspection_receipt)
        _validate_recorded_receipt(verification_receipt)
        package_version = GFP_FORMAT_VERSION_V2
        receipts_version = RECEIPTS_FORMAT_VERSION_V2
        receipts_payload = _receipts_v2(audit_chain, inspection_receipt, verification_receipt)
    else:
        raise ValueError("Blockchain-aware packages require both lifecycle receipts.")
    receipts_bytes = canonical_json_bytes(receipts_payload)
    if len(receipts_bytes) > MEMBER_LIMITS[RECEIPTS_NAME]:
        raise EvidenceResourceLimitError("Receipts exceed the package size limit.")
    manifest = {
        "inspection_commitment": record.inspection_commitment(),
        "members": {
            EVIDENCE_NAME: _member_descriptor(EVIDENCE_NAME, encrypted, GFE_FORMAT_VERSION),
            RECEIPTS_NAME: _member_descriptor(RECEIPTS_NAME, receipts_bytes, receipts_version),
        },
        "operation_commitment": record.public_operation_commitment,
        "package_version": package_version,
        "verification_commitment": record.verification_commitment(),
    }
    manifest_bytes = canonical_json_bytes(manifest)
    if len(manifest_bytes) > MEMBER_LIMITS[MANIFEST_NAME]:
        raise EvidenceResourceLimitError("Manifest exceeds the package size limit.")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data, compression in (
            (MANIFEST_NAME, manifest_bytes, zipfile.ZIP_DEFLATED),
            (EVIDENCE_NAME, encrypted, zipfile.ZIP_STORED),
            (RECEIPTS_NAME, receipts_bytes, zipfile.ZIP_DEFLATED),
        ):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = compression
            info.external_attr = 0o100600 << 16
            archive.writestr(info, data)
    packaged = output.getvalue()
    if len(packaged) > MAX_PACKAGE_COMPRESSED_SIZE:
        raise EvidenceResourceLimitError("Evidence package exceeds the compressed-size limit.")
    return packaged


def _validate_member_path(name: str) -> None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if name != normalized or path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", normalized):
        raise MalformedPackageError("Evidence package contains an unsafe member path.")


def _validate_info(info: zipfile.ZipInfo) -> None:
    _validate_member_path(info.filename)
    if info.flag_bits & 0x1:
        raise MalformedPackageError("Encrypted ZIP members are not supported in evidence packages.")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in {0, stat.S_IFREG}:
        raise MalformedPackageError("Evidence package contains a non-regular member.")
    limit = MEMBER_LIMITS.get(info.filename)
    if limit is None:
        raise MalformedPackageError("Evidence package contains an unexpected member.")
    if info.file_size > limit:
        raise EvidenceResourceLimitError(f"Evidence package member {info.filename} exceeds its size limit.")
    if info.file_size and info.compress_size == 0:
        raise MalformedPackageError("Evidence package member has an invalid compressed size.")
    if info.file_size >= RATIO_CHECK_THRESHOLD and info.file_size / max(info.compress_size, 1) > MAX_COMPRESSION_RATIO:
        raise EvidenceResourceLimitError("Evidence package compression ratio exceeds the safety limit.")


def _validate_manifest(manifest: Mapping[str, Any]) -> str:
    expected = {"inspection_commitment", "members", "operation_commitment", "package_version", "verification_commitment"}
    if set(manifest) != expected:
        raise MalformedPackageError("Evidence-package manifest fields are invalid.")
    package_version = manifest["package_version"]
    if package_version not in {GFP_FORMAT_VERSION_V1, GFP_FORMAT_VERSION_V2}:
        raise UnsupportedEvidenceError("Unsupported evidence-package version.")
    for key in ("inspection_commitment", "operation_commitment", "verification_commitment"):
        if not isinstance(manifest[key], str) or not SHA256_RE.fullmatch(manifest[key]):
            raise MalformedPackageError("Evidence-package manifest contains an invalid commitment.")
    members = manifest["members"]
    if not isinstance(members, Mapping) or set(members) != {EVIDENCE_NAME, RECEIPTS_NAME}:
        raise MalformedPackageError("Evidence-package manifest member declarations are invalid.")
    receipt_version = RECEIPTS_FORMAT_VERSION_V1 if package_version == GFP_FORMAT_VERSION_V1 else RECEIPTS_FORMAT_VERSION_V2
    expected_formats = {EVIDENCE_NAME: GFE_FORMAT_VERSION, RECEIPTS_NAME: receipt_version}
    for name, descriptor in members.items():
        if not isinstance(descriptor, Mapping) or set(descriptor) != {"format_version", "name", "sha256", "size"}:
            raise MalformedPackageError("Evidence-package member descriptor is invalid.")
        if descriptor["name"] != name or descriptor["format_version"] != expected_formats[name]:
            raise UnsupportedEvidenceError("Evidence-package member format is unsupported.")
        if (
            not isinstance(descriptor["size"], int)
            or isinstance(descriptor["size"], bool)
            or descriptor["size"] < 0
            or descriptor["size"] > MEMBER_LIMITS[name]
        ):
            raise EvidenceResourceLimitError("Evidence-package declared member size is outside the safety limit.")
        if not isinstance(descriptor["sha256"], str) or not SHA256_RE.fullmatch(descriptor["sha256"]):
            raise MalformedPackageError("Evidence-package member hash is invalid.")
    return package_version


def _validate_recorded_receipt(receipt: AnchorReceipt) -> None:
    """Enforce state-specific v2 receipt invariants without inventing chain facts."""

    identity = (
        receipt.chain_id, receipt.contract_address, receipt.contract_code_hash,
        receipt.contract_version, receipt.transaction_hash, receipt.submitter_address,
    )
    block = (receipt.block_number, receipt.block_hash, receipt.log_index)
    if receipt.state == AnchorState.DISABLED:
        raise ValueError("Disabled placeholders belong to immutable v1 packages, not v2 receipts.")
    if receipt.state == AnchorState.NOT_REQUESTED:
        if any(value is not None for value in identity + block) or receipt.confirmations != 0 or receipt.failure_category is not None:
            raise ValueError("A not-requested receipt cannot contain blockchain identity fields.")
    elif receipt.state == AnchorState.CONFIRMED:
        if any(value is None for value in identity + block) or receipt.confirmations < 1 or receipt.failure_category is not None:
            raise ValueError("A confirmed receipt requires complete transaction identity and observed confirmations.")
    elif receipt.state == AnchorState.PENDING:
        if any(value is None for value in identity) or receipt.failure_category != FailureCategory.INSUFFICIENT_CONFIRMATIONS:
            raise ValueError("A pending receipt requires transaction identity and an insufficient-confirmations category.")
        if any(value is not None for value in block) and any(value is None for value in block):
            raise ValueError("A pending receipt contains an incomplete block identity.")
    elif receipt.state == AnchorState.FAILED:
        if receipt.failure_category is None:
            raise ValueError("A failed receipt requires a failure category.")
        if any(value is not None for value in block) and any(value is None for value in block):
            raise ValueError("A failed receipt contains an incomplete block identity.")


def _validate_receipts(receipts: Mapping[str, Any], package_version: str) -> tuple[AuditChain, AnchorReceipt | None, AnchorReceipt | None]:
    if set(receipts) != {"audit_chain", "blockchain", "receipts_version"}:
        raise MalformedPackageError("Evidence-package receipts fields are invalid.")
    expected_version = RECEIPTS_FORMAT_VERSION_V1 if package_version == GFP_FORMAT_VERSION_V1 else RECEIPTS_FORMAT_VERSION_V2
    if receipts["receipts_version"] != expected_version:
        raise UnsupportedEvidenceError("Unsupported evidence-package receipts version.")
    blockchain = receipts["blockchain"]
    if package_version == GFP_FORMAT_VERSION_V1:
        expected = {"inspection_anchor": {"state": "NOT_APPLICABLE"}, "verification_anchor": {"state": "NOT_APPLICABLE"}}
        if blockchain != expected:
            raise MalformedPackageError("Version 1 packages cannot contain blockchain receipts.")
        return AuditChain.from_dict(receipts["audit_chain"]), None, None
    if not isinstance(blockchain, Mapping) or set(blockchain) != {"inspection_anchor", "verification_anchor"}:
        raise MalformedPackageError("Version 2 blockchain receipt fields are invalid.")
    try:
        inspection = AnchorReceipt.from_dict(dict(blockchain["inspection_anchor"]))
        verification = AnchorReceipt.from_dict(dict(blockchain["verification_anchor"]))
        _validate_recorded_receipt(inspection)
        _validate_recorded_receipt(verification)
    except (TypeError, ValueError) as exc:
        raise MalformedPackageError("Version 2 contains a malformed blockchain receipt.") from exc
    if inspection.stage != AnchorStage.INSPECTION or verification.stage != AnchorStage.VERIFICATION:
        raise MalformedPackageError("Version 2 blockchain receipt stages are invalid.")
    return AuditChain.from_dict(receipts["audit_chain"]), inspection, verification


def parse_evidence_package(package: bytes) -> ParsedEvidencePackage:
    if not isinstance(package, bytes):
        raise TypeError("Evidence package must be bytes.")
    if len(package) > MAX_PACKAGE_COMPRESSED_SIZE:
        raise EvidenceResourceLimitError("Evidence package exceeds the compressed-size limit.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(package))
    except (zipfile.BadZipFile, OSError) as exc:
        raise MalformedPackageError("Evidence package is not a readable ZIP container.") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRY_COUNT:
            raise EvidenceResourceLimitError("Evidence package contains too many members.")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise MalformedPackageError("Evidence package contains duplicate members.")
        for info in infos:
            _validate_info(info)
        if set(names) != REQUIRED_MEMBERS:
            raise MalformedPackageError("Evidence package is missing required members or contains unexpected members.")
        if sum(info.compress_size for info in infos) > MAX_PACKAGE_COMPRESSED_SIZE:
            raise EvidenceResourceLimitError("Evidence package compressed members exceed the safety limit.")
        if sum(info.file_size for info in infos) > MAX_PACKAGE_EXPANDED_SIZE:
            raise EvidenceResourceLimitError("Evidence package expanded size exceeds the safety limit.")
        try:
            payloads = {info.filename: archive.read(info) for info in infos}
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise MalformedPackageError("Evidence package member data is damaged.") from exc
    manifest = _canonical_json_object(payloads[MANIFEST_NAME], "manifest")
    package_version = _validate_manifest(manifest)
    for name in (EVIDENCE_NAME, RECEIPTS_NAME):
        descriptor = manifest["members"][name]
        if len(payloads[name]) != descriptor["size"] or _sha256(payloads[name]) != descriptor["sha256"]:
            raise VerificationMismatchError(f"Evidence package member {name} does not match its manifest commitment.")
    receipts = _canonical_json_object(payloads[RECEIPTS_NAME], "receipts")
    chain, inspection, verification = _validate_receipts(receipts, package_version)
    operation = "0x" + manifest["operation_commitment"]
    if inspection is not None and (inspection.operation_commitment != operation or verification is None or verification.operation_commitment != operation):
        raise VerificationMismatchError("Blockchain receipts do not match the package operation commitment.")
    return ParsedEvidencePackage(manifest, payloads[EVIDENCE_NAME], receipts, chain, package_version, inspection, verification)
