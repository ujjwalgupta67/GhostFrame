from __future__ import annotations

import hashlib
import io
import json
import random
import stat
import zipfile

import pytest

from ghostframe.evidence import (
    EvidenceError,
    EvidenceResourceLimitError,
    MalformedPackageError,
    UnsupportedEvidenceError,
    VerificationMismatchError,
    VerificationState,
    canonical_json_bytes,
    create_evidence_package,
    parse_evidence_package,
    verify_evidence_package,
)
from ghostframe.evidence.package import EVIDENCE_NAME, MANIFEST_NAME, RECEIPTS_NAME
from tests.evidence_support import PASSPHRASE, SANITIZED_BYTES, SOURCE_BYTES, completed_record, valid_audit_chain


def package_bytes():
    record = completed_record()
    return create_evidence_package(record, PASSPHRASE, valid_audit_chain(record)), record


def read_members(package: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        return {info.filename: archive.read(info) for info in archive.infolist()}


def write_members(members: list[tuple[str, bytes, int | None]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = ((mode if mode is not None else 0o100600) << 16)
            archive.writestr(info, data)
    return output.getvalue()


def rebuild(package: bytes, replacements: dict[str, bytes], *, update_manifest_hashes: bool = False) -> bytes:
    members = read_members(package)
    members.update(replacements)
    if update_manifest_hashes:
        manifest = json.loads(members[MANIFEST_NAME])
        for name in (EVIDENCE_NAME, RECEIPTS_NAME):
            manifest["members"][name]["size"] = len(members[name])
            manifest["members"][name]["sha256"] = hashlib.sha256(members[name]).hexdigest()
        members[MANIFEST_NAME] = canonical_json_bytes(manifest)
    return write_members([(name, data, None) for name, data in members.items()])


@pytest.fixture(scope="module")
def valid_package():
    return package_bytes()


def test_package_round_trip_exact_members_and_public_manifest_privacy(valid_package):
    package, record = valid_package
    parsed = parse_evidence_package(package)
    assert set(read_members(package)) == {MANIFEST_NAME, EVIDENCE_NAME, RECEIPTS_NAME}
    assert parsed.manifest["operation_commitment"] == record.public_operation_commitment
    public = read_members(package)[MANIFEST_NAME] + read_members(package)[RECEIPTS_NAME]
    assert b"Synthetic Person" not in public and b"docProps" not in public
    assert parsed.receipts["blockchain"]["inspection_anchor"]["state"] == "NOT_APPLICABLE"


def test_package_accepts_one_pre_authenticated_gfe_without_reencrypting():
    from ghostframe.evidence import encrypt_evidence

    record = completed_record()
    encrypted = encrypt_evidence(record, PASSPHRASE)
    package = create_evidence_package(
        record,
        PASSPHRASE,
        valid_audit_chain(record),
        encrypted_evidence=encrypted,
    )
    assert parse_evidence_package(package).encrypted_evidence == encrypted


def test_missing_extra_and_duplicate_members_rejected(valid_package):
    package, _ = valid_package; members = read_members(package)
    missing = write_members([(name, data, None) for name, data in members.items() if name != RECEIPTS_NAME])
    with pytest.raises(MalformedPackageError):
        parse_evidence_package(missing)
    extra = write_members([(name, data, None) for name, data in members.items()] + [("extra.txt", b"x", None)])
    with pytest.raises(EvidenceError):
        parse_evidence_package(extra)
    with pytest.warns(UserWarning, match="Duplicate name"):
        duplicate = write_members([(name, data, None) for name, data in members.items()] + [(MANIFEST_NAME, members[MANIFEST_NAME], None)])
    with pytest.raises(EvidenceError):
        parse_evidence_package(duplicate)


@pytest.mark.parametrize("unsafe", ["/manifest.json", "../manifest.json", "C:/manifest.json", "folder\\manifest.json"])
def test_absolute_traversal_drive_and_separator_paths_rejected(valid_package, unsafe):
    package, _ = valid_package; members = read_members(package)
    crafted = write_members([
        (unsafe if name == MANIFEST_NAME else name, data, None) for name, data in members.items()
    ])
    with pytest.raises(MalformedPackageError, match="unsafe"):
        parse_evidence_package(crafted)


def test_symlink_member_rejected(valid_package):
    package, _ = valid_package; members = read_members(package)
    crafted = write_members([
        (name, data, stat.S_IFLNK | 0o777 if name == MANIFEST_NAME else None) for name, data in members.items()
    ])
    with pytest.raises(MalformedPackageError, match="non-regular"):
        parse_evidence_package(crafted)


def test_oversized_member_archive_and_compression_ratio_rejected(valid_package, monkeypatch):
    package, _ = valid_package
    monkeypatch.setitem(__import__("ghostframe.evidence.package", fromlist=["MEMBER_LIMITS"]).MEMBER_LIMITS, EVIDENCE_NAME, 10)
    with pytest.raises(EvidenceResourceLimitError, match="member"):
        parse_evidence_package(package)
    monkeypatch.undo()
    monkeypatch.setattr("ghostframe.evidence.package.MAX_PACKAGE_COMPRESSED_SIZE", len(package) - 1)
    with pytest.raises(EvidenceResourceLimitError, match="compressed-size"):
        parse_evidence_package(package)
    monkeypatch.undo()
    monkeypatch.setattr("ghostframe.evidence.package.MAX_PACKAGE_EXPANDED_SIZE", 1)
    with pytest.raises(EvidenceResourceLimitError, match="expanded size"):
        parse_evidence_package(package)
    monkeypatch.undo()
    monkeypatch.setattr("ghostframe.evidence.package.RATIO_CHECK_THRESHOLD", 1)
    monkeypatch.setattr("ghostframe.evidence.package.MAX_COMPRESSION_RATIO", 1)
    with pytest.raises(EvidenceResourceLimitError, match="ratio"):
        parse_evidence_package(package)


def test_malformed_manifest_and_unsupported_package_version(valid_package):
    package, _ = valid_package
    with pytest.raises(MalformedPackageError):
        parse_evidence_package(rebuild(package, {MANIFEST_NAME: b"not json"}))
    manifest = json.loads(read_members(package)[MANIFEST_NAME]); manifest["package_version"] = "ghostframe-gfp/9.0"
    with pytest.raises(UnsupportedEvidenceError):
        parse_evidence_package(rebuild(package, {MANIFEST_NAME: canonical_json_bytes(manifest)}))


def test_substituted_encrypted_evidence_and_receipts_rejected(valid_package):
    package, _ = valid_package; members = read_members(package)
    for name in (EVIDENCE_NAME, RECEIPTS_NAME):
        changed = bytearray(members[name]); changed[-1] ^= 1
        with pytest.raises(VerificationMismatchError):
            parse_evidence_package(rebuild(package, {name: bytes(changed)}))


def test_verification_correct_incorrect_and_absent_artifacts(valid_package, tmp_path):
    package, _ = valid_package
    verified = verify_evidence_package(package, PASSPHRASE, source_file=SOURCE_BYTES, sanitized_file=SANITIZED_BYTES)
    assert verified.locally_verified
    assert verified.source_file.state == VerificationState.VERIFIED
    assert verified.sanitized_file.state == VerificationState.VERIFIED
    source_path = tmp_path / "source.bin"; source_path.write_bytes(SOURCE_BYTES)
    assert verify_evidence_package(package, PASSPHRASE, source_file=source_path).source_file.state == VerificationState.VERIFIED
    incorrect = verify_evidence_package(package, PASSPHRASE, source_file=b"wrong", sanitized_file=b"wrong")
    assert incorrect.source_file.state == VerificationState.FAILED
    assert incorrect.sanitized_file.state == VerificationState.FAILED
    absent = verify_evidence_package(package, PASSPHRASE)
    assert absent.source_file.state == VerificationState.NOT_PROVIDED
    assert absent.sanitized_file.state == VerificationState.NOT_PROVIDED


def test_verification_wrong_password_expected_operation_and_blockchain_state(valid_package):
    package, record = valid_package
    wrong_password = verify_evidence_package(package, "different synthetic passphrase")
    assert wrong_password.encrypted_evidence_authenticity.state == VerificationState.FAILED
    assert wrong_password.evidence_commitment.state == VerificationState.NOT_CHECKED
    wrong_operation = verify_evidence_package(package, PASSPHRASE, expected_operation_commitment="f" * 64)
    assert wrong_operation.evidence_commitment.state == VerificationState.FAILED
    assert wrong_operation.inspection_blockchain_anchor.state == VerificationState.NOT_APPLICABLE
    assert wrong_operation.verification_blockchain_anchor.state == VerificationState.NOT_APPLICABLE
    assert record.public_operation_commitment != "f" * 64


def test_verification_short_passphrase_is_a_structured_failure(valid_package):
    package, _ = valid_package
    result = verify_evidence_package(package, "short")
    assert result.encrypted_evidence_authenticity.state == VerificationState.FAILED
    assert result.evidence_commitment.state == VerificationState.NOT_CHECKED


def test_verification_detects_manifest_evidence_mismatch_and_audit_failure(valid_package):
    package, _ = valid_package; members = read_members(package)
    manifest = json.loads(members[MANIFEST_NAME]); manifest["inspection_commitment"] = "f" * 64
    mismatch = rebuild(package, {MANIFEST_NAME: canonical_json_bytes(manifest)})
    assert verify_evidence_package(mismatch, PASSPHRASE).evidence_commitment.state == VerificationState.FAILED

    receipts = json.loads(members[RECEIPTS_NAME]); receipts["audit_chain"]["events"][1]["event_type"] = "EVIDENCE_CREATED"
    bad_audit = rebuild(package, {RECEIPTS_NAME: canonical_json_bytes(receipts)}, update_manifest_hashes=True)
    result = verify_evidence_package(bad_audit, PASSPHRASE)
    assert result.package_structure.state == VerificationState.VERIFIED
    assert result.audit_chain.state == VerificationState.FAILED


def test_package_malformed_input_fuzz_style_controlled():
    generator = random.Random(20260926)
    for size in range(0, 1025, 31):
        try:
            parse_evidence_package(generator.randbytes(size))
        except EvidenceError:
            pass
        else:
            pytest.fail("Arbitrary malformed package unexpectedly parsed")
