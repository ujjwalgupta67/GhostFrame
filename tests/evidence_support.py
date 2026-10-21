from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from ghostframe.comparison import compare_results
from ghostframe.evidence import AuditChain, build_inspection_evidence, complete_lifecycle_evidence
from ghostframe.inspectors.common import make_finding
from ghostframe.models import InspectionResult


SOURCE_BYTES = b"synthetic source artifact"
SANITIZED_BYTES = b"synthetic sanitized artifact"
PASSPHRASE = "correct synthetic passphrase"
OPERATION_ID = "b5a7e6ce-620a-4fa7-af5f-13ced9c3998f"
FIXED_TIME = datetime(2026, 1, 2, 3, 4, 5, 6000, tzinfo=timezone.utc)


def completed_record(*, author: str = "Synthetic Person"):
    finding = make_finding(
        "docx", "Document properties", "Creator", author, "docProps/core.xml/creator",
        overrides={"severity": "High", "risk_group": "direct_identity", "subcategory": "identity"},
    )
    before = InspectionResult(
        "DOCX", findings=[finding], file_sha256=hashlib.sha256(SOURCE_BYTES).hexdigest(),
        file_size=len(SOURCE_BYTES), verified_extension="docx",
    )
    after = InspectionResult(
        "DOCX", file_sha256=hashlib.sha256(SANITIZED_BYTES).hexdigest(),
        file_size=len(SANITIZED_BYTES), verified_extension="docx",
    )
    record = build_inspection_evidence(before, operation_id=OPERATION_ID, created_at=FIXED_TIME)
    report = compare_results(before, after, ["Remove synthetic metadata."])
    return complete_lifecycle_evidence(record, after, report, ["Remove synthetic metadata."])


def valid_audit_chain(record=None) -> AuditChain:
    record = record or completed_record()
    chain = AuditChain(record.public_operation_commitment)
    chain = chain.append("INSPECTION_COMPLETED", payload_commitment=record.inspection_commitment(), timestamp=FIXED_TIME)
    chain = chain.append("SANITIZATION_STARTED", timestamp=FIXED_TIME)
    chain = chain.append("SANITIZATION_COMPLETED", payload_commitment=record.sanitized_file.sha256, timestamp=FIXED_TIME)
    chain = chain.append("VERIFICATION_COMPLETED", payload_commitment=record.verification_commitment(), timestamp=FIXED_TIME)
    return chain
