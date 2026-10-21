from __future__ import annotations

import copy
import hashlib
import io
import json
import zipfile
from dataclasses import fields, replace

import pikepdf
import pytest
from PIL import Image, PngImagePlugin

from ghostframe import SanitizationOutcome, inspect_file, sanitize_with_verification
from ghostframe.evidence import (
    EvidenceLifecycleResult,
    EvidenceLifecycleService,
    LifecycleExecutionError,
    LifecycleFailureCode,
    LifecycleState,
    VerificationCheck,
    VerificationState,
    create_evidence_package,
    parse_evidence_package,
    lifecycle_commitment,
    run_evidence_lifecycle,
    verify_audit_chain,
    verify_evidence_package,
)
from tests.evidence_support import FIXED_TIME, OPERATION_ID, PASSPHRASE


def _jpeg() -> tuple[bytes, str]:
    image = Image.new("RGB", (8, 8), "red")
    exif = Image.Exif()
    exif[0x010F] = "Synthetic Camera"
    output = io.BytesIO()
    image.save(output, "JPEG", exif=exif)
    return output.getvalue(), "synthetic.jpg"


def _png() -> tuple[bytes, str]:
    image = Image.new("RGBA", (8, 8), (10, 20, 30, 100))
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Author", "Synthetic Author")
    output = io.BytesIO()
    image.save(output, "PNG", pnginfo=metadata)
    return output.getvalue(), "synthetic.png"


def _pdf() -> tuple[bytes, str]:
    output = io.BytesIO()
    with pikepdf.Pdf.new() as pdf:
        page = pdf.add_blank_page(page_size=(100, 100))
        pdf.docinfo["/Author"] = "Synthetic Author"
        page["/Annots"] = pikepdf.Array([
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=pikepdf.Name.Link,
                Rect=pikepdf.Array([0, 0, 10, 10]),
                A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI="https://example.invalid/synthetic"),
            )
        ])
        pdf.save(output)
    return output.getvalue(), "synthetic.pdf"


def _docx() -> tuple[bytes, str]:
    parts = {
        "[Content_Types].xml": b'''<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>''',
        "word/document.xml": b'''<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:hyperlink r:id="rId9"><w:r><w:t>Synthetic visible text</w:t></w:r></w:hyperlink></w:p></w:body></w:document>''',
        "word/_rels/document.xml.rels": b'''<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.invalid/synthetic" TargetMode="External"/></Relationships>''',
        "docProps/core.xml": b'''<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Synthetic Author</dc:creator></cp:coreProperties>''',
        "word/comments.xml": b'''<?xml version="1.0"?><w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="0" w:author="Synthetic Reviewer"><w:p><w:r><w:t>Synthetic note user@example.invalid 12.3456,78.9012</w:t></w:r></w:p></w:comment></w:comments>''',
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in parts.items():
            archive.writestr(name, value)
    return output.getvalue(), "synthetic.docx"


FIXTURES = [_jpeg, _png, _pdf, _docx]


@pytest.mark.parametrize("fixture", FIXTURES, ids=["jpeg", "png", "pdf", "docx"])
def test_real_file_lifecycle_end_to_end(fixture, tmp_path, monkeypatch):
    source, name = fixture()
    monkeypatch.chdir(tmp_path)
    before_names = set(tmp_path.iterdir())
    result = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False)

    assert result.state == LifecycleState.PACKAGED
    assert result.original_inspection.file_sha256 == hashlib.sha256(source).hexdigest()
    assert result.original_inspection.file_size == len(source)
    assert result.original_inspection.findings
    assert result.sanitization_outcome.data != source
    assert result.sanitization_outcome.after.file_sha256 == hashlib.sha256(result.sanitization_outcome.data).hexdigest()
    assert result.sanitization_outcome.after.file_size == len(result.sanitization_outcome.data)
    assert result.sanitization_outcome.verification.original_sha256 == result.original_inspection.file_sha256
    assert result.sanitization_outcome.verification.sanitized_sha256 == result.sanitization_outcome.after.file_sha256
    assert result.evidence_record.is_complete
    assert result.evidence_record.source_file.sha256 == hashlib.sha256(source).hexdigest()
    assert result.evidence_record.sanitized_file.sha256 == hashlib.sha256(result.sanitization_outcome.data).hexdigest()
    assert verify_audit_chain(result.audit_chain, expected_head=result.expected_audit_head).valid
    assert parse_evidence_package(result.evidence_package).encrypted_evidence == result.encrypted_evidence
    checks = result.local_verification
    assert checks.package_structure.state == VerificationState.VERIFIED
    assert checks.encrypted_evidence_authenticity.state == VerificationState.VERIFIED
    assert checks.evidence_commitment.state == VerificationState.VERIFIED
    assert checks.audit_chain.state == VerificationState.VERIFIED
    assert checks.source_file.state == VerificationState.VERIFIED
    assert checks.sanitized_file.state == VerificationState.VERIFIED
    assert checks.inspection_blockchain_anchor.state == VerificationState.NOT_APPLICABLE
    assert checks.verification_blockchain_anchor.state == VerificationState.NOT_APPLICABLE
    assert set(tmp_path.iterdir()) == before_names

    public = parse_evidence_package(result.evidence_package)
    serialized_public = json.dumps(public.manifest, sort_keys=True) + json.dumps(public.receipts, sort_keys=True)
    assert name not in serialized_public
    assert "Synthetic Author" not in serialized_public


def test_inspection_commitment_exists_before_sanitization_and_never_changes():
    source, name = _png()
    service = EvidenceLifecycleService(source, name, use_exiftool=False)
    inspection_record = service.inspect()
    initial_commitment = service.inspection_commitment
    assert service.state == LifecycleState.INSPECTED
    assert initial_commitment == inspection_record.inspection_commitment()
    service.sanitize_and_complete()
    assert service.inspection_commitment == initial_commitment
    assert service.evidence_record.inspection_commitment() == initial_commitment
    assert service.verification_commitment != initial_commitment


def test_same_inspection_snapshot_has_the_same_inspection_commitment():
    source, name = _png()
    first = EvidenceLifecycleService(
        source,
        name,
        use_exiftool=False,
        operation_id=OPERATION_ID,
        created_at=FIXED_TIME,
    )
    second = EvidenceLifecycleService(
        source,
        name,
        use_exiftool=False,
        operation_id=OPERATION_ID,
        created_at=FIXED_TIME,
    )
    first.inspect(); second.inspect()
    assert first.evidence_record.to_dict() == second.evidence_record.to_dict()
    assert first.inspection_commitment == second.inspection_commitment


def test_required_audit_flow_and_lifecycle_commitment_bind_final_head():
    source, name = _jpeg()
    result = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False)
    assert [event.event_type for event in result.audit_chain.events] == [
        "INSPECTION_COMPLETED",
        "EVIDENCE_CREATED",
        "SANITIZATION_STARTED",
        "SANITIZATION_COMPLETED",
        "REINSPECTION_COMPLETED",
        "VERIFICATION_COMPLETED",
    ]
    assert "ANCHORED" not in " ".join(event.event_type for event in result.audit_chain.events)
    assert result.expected_audit_head == result.audit_chain.head_hash
    assert len(result.lifecycle_commitment) == 64
    assert result.lifecycle_commitment == lifecycle_commitment(
        operation_commitment=result.public_operation_commitment,
        inspection_commitment=result.inspection_commitment,
        evidence_verification_commitment=result.verification_commitment,
        audit_head=result.expected_audit_head,
    )
    assert result.lifecycle_commitment != lifecycle_commitment(
        operation_commitment=result.public_operation_commitment,
        inspection_commitment=result.inspection_commitment,
        evidence_verification_commitment=result.verification_commitment,
        audit_head="0" * 64,
    )
    assert result.audit_chain.events[-1].payload_commitment == result.verification_commitment


def test_expected_head_detects_valid_but_truncated_package_chain():
    source, name = _png()
    result = run_evidence_lifecycle(source, name, PASSPHRASE, use_exiftool=False)
    truncated = result.audit_chain.__class__(result.audit_chain.operation_commitment, result.audit_chain.events[:-1])
    package = create_evidence_package(result.evidence_record, PASSPHRASE, truncated)
    unbound = verify_evidence_package(package, PASSPHRASE, source_file=source, sanitized_file=result.sanitization_outcome.data)
    bound = verify_evidence_package(
        package,
        PASSPHRASE,
        source_file=source,
        sanitized_file=result.sanitization_outcome.data,
        expected_audit_head=result.expected_audit_head,
    )
    assert unbound.audit_chain.state == VerificationState.VERIFIED
    assert bound.audit_chain.state == VerificationState.FAILED


def test_invalid_transitions_and_duplicate_completion_fail_closed():
    source, name = _jpeg()
    service = EvidenceLifecycleService(source, name, use_exiftool=False)
    with pytest.raises(LifecycleExecutionError) as caught:
        service.sanitize_and_complete()
    assert caught.value.code == LifecycleFailureCode.INVALID_TRANSITION
    assert service.state == LifecycleState.FAILED

    service = EvidenceLifecycleService(source, name, use_exiftool=False)
    service.inspect()
    service.sanitize_and_complete()
    with pytest.raises(LifecycleExecutionError) as caught:
        service.sanitize_and_complete()
    assert caught.value.code == LifecycleFailureCode.INVALID_TRANSITION


@pytest.mark.parametrize("source,name", [(b"unknown", "unknown.bin"), (b"%PDF-1.7\nmalformed", "broken.pdf")])
def test_unsupported_and_malformed_sources_are_structured_failures(source, name):
    service = EvidenceLifecycleService(source, name, use_exiftool=False)
    with pytest.raises(LifecycleExecutionError) as caught:
        service.inspect()
    assert caught.value.code == LifecycleFailureCode.INITIAL_INSPECTION_FAILED
    assert service.state == LifecycleState.FAILED


def test_injected_inspection_and_sanitization_failures_are_structured():
    source, name = _jpeg()

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic internal failure")

    inspection_service = EvidenceLifecycleService(source, name, inspector=fail)
    with pytest.raises(LifecycleExecutionError) as caught:
        inspection_service.inspect()
    assert caught.value.code == LifecycleFailureCode.INITIAL_INSPECTION_FAILED

    sanitization_service = EvidenceLifecycleService(source, name, sanitizer=fail)
    sanitization_service.inspect()
    with pytest.raises(LifecycleExecutionError) as caught:
        sanitization_service.sanitize_and_complete()
    assert caught.value.code == LifecycleFailureCode.SANITIZATION_FAILED


def test_source_before_output_after_and_verification_mismatches_fail_closed():
    source, name = _png()

    def wrong_source_inspector(data, filename, **kwargs):
        result = inspect_file(data, filename, **kwargs)
        result.file_sha256 = "0" * 64
        return result

    service = EvidenceLifecycleService(source, name, inspector=wrong_source_inspector)
    with pytest.raises(LifecycleExecutionError) as caught:
        service.inspect()
    assert caught.value.code == LifecycleFailureCode.SOURCE_BINDING_MISMATCH

    real_before = inspect_file(source, name, use_exiftool=False)

    def outcome_variant(kind):
        def sanitizer(data, filename, before, **kwargs):
            outcome = sanitize_with_verification(data, filename, before, **kwargs)
            if kind == "before":
                changed = copy.deepcopy(outcome.before)
                changed.notes.append("synthetic mismatch")
                return replace(outcome, before=changed)
            if kind == "bytes":
                return replace(outcome, data=outcome.data + b"x")
            if kind == "after":
                changed = copy.deepcopy(outcome.after)
                changed.notes.append("synthetic mismatch")
                return replace(outcome, after=changed)
            changed = copy.deepcopy(outcome.verification)
            changed.message = "synthetic mismatch"
            return replace(outcome, verification=changed)
        return sanitizer

    expectations = {
        "before": LifecycleFailureCode.BEFORE_INSPECTION_MISMATCH,
        "bytes": LifecycleFailureCode.SANITIZED_BINDING_MISMATCH,
        "after": LifecycleFailureCode.AFTER_INSPECTION_MISMATCH,
        "verification": LifecycleFailureCode.VERIFICATION_MISMATCH,
    }
    for kind, expected in expectations.items():
        service = EvidenceLifecycleService(source, name, sanitizer=outcome_variant(kind), use_exiftool=False)
        service.inspect()
        with pytest.raises(LifecycleExecutionError) as caught:
            service.sanitize_and_complete()
        assert caught.value.code == expected
        assert service.state == LifecycleState.FAILED
    assert real_before.file_sha256 == hashlib.sha256(source).hexdigest()


def test_reinspection_encryption_package_and_self_verification_failures():
    source, name = _jpeg()

    class FailSecondInspection:
        def __init__(self):
            self.calls = 0

        def __call__(self, data, filename, **kwargs):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("synthetic reinspection failure")
            return inspect_file(data, filename, **kwargs)

    service = EvidenceLifecycleService(source, name, inspector=FailSecondInspection())
    service.inspect()
    with pytest.raises(LifecycleExecutionError) as caught:
        service.sanitize_and_complete()
    assert caught.value.code == LifecycleFailureCode.REINSPECTION_FAILED

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic failure")

    service = EvidenceLifecycleService(source, name, evidence_completer=fail)
    service.inspect()
    with pytest.raises(LifecycleExecutionError) as caught:
        service.sanitize_and_complete()
    assert caught.value.code == LifecycleFailureCode.EVIDENCE_COMPLETION_FAILED

    service = EvidenceLifecycleService(source, name, encryptor=fail)
    service.inspect(); service.sanitize_and_complete()
    with pytest.raises(LifecycleExecutionError) as caught:
        service.package(PASSPHRASE)
    assert caught.value.code == LifecycleFailureCode.ENCRYPTION_FAILED

    service = EvidenceLifecycleService(source, name, package_creator=fail)
    service.inspect(); service.sanitize_and_complete()
    with pytest.raises(LifecycleExecutionError) as caught:
        service.package(PASSPHRASE)
    assert caught.value.code == LifecycleFailureCode.PACKAGE_CREATION_FAILED

    def failed_verifier(*args, **kwargs):
        valid = verify_evidence_package(*args, **kwargs)
        return replace(valid, package_structure=VerificationCheck(VerificationState.FAILED, "Synthetic failure."))

    service = EvidenceLifecycleService(source, name, package_verifier=failed_verifier)
    service.inspect(); service.sanitize_and_complete()
    with pytest.raises(LifecycleExecutionError) as caught:
        service.package(PASSPHRASE)
    assert caught.value.code == LifecycleFailureCode.SELF_VERIFICATION_FAILED


def test_passphrase_is_not_retained_or_returned():
    source, name = _jpeg()
    service = EvidenceLifecycleService(source, name)
    result = service.run(PASSPHRASE)
    assert "passphrase" not in vars(service)
    assert "passphrase" not in {field.name for field in fields(EvidenceLifecycleResult)}
    assert PASSPHRASE.encode() not in result.encrypted_evidence
    assert PASSPHRASE.encode() not in result.evidence_package
