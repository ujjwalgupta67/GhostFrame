from __future__ import annotations

import hashlib
import io
import math
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from ghostframe.comparison import compare_results
from ghostframe.evidence import (
    FILE_DOMAIN,
    INSPECTION_DOMAIN,
    OPERATION_DOMAIN,
    VERIFICATION_DOMAIN,
    CanonicalizationError,
    build_inspection_evidence,
    canonical_json_bytes,
    commit_bytes,
    commit_canonical,
    complete_lifecycle_evidence,
    file_sha256,
    hash_stream,
    new_operation_id,
    operation_commitment,
    project_inspection,
)
from ghostframe.inspectors.common import make_finding
from ghostframe.models import InspectionResult


FIXED_OPERATION_ID = "b5a7e6ce-620a-4fa7-af5f-13ced9c3998f"
FIXED_TIME = datetime(2026, 1, 2, 3, 4, 5, 6000, tzinfo=timezone.utc)


def _result(*, reverse: bool = False, author: str = "Example Person") -> InspectionResult:
    findings = [
        make_finding("docx", "Document properties", "Creator", author, "docProps/core.xml/creator"),
        make_finding("docx", "Application properties", "Application", "Example Editor", "docProps/app.xml/Application"),
    ]
    if reverse:
        findings.reverse()
    return InspectionResult(
        "DOCX",
        findings=findings,
        notes=["Second note", "First note"] if reverse else ["First note", "Second note"],
        limitations=["Visible content is not inspected.", "Synthetic fixture."],
        file_sha256=hashlib.sha256(b"source").hexdigest(),
        file_size=6,
        verified_extension="docx",
    )


def test_canonical_known_answer_vector_and_nested_key_order():
    first = {"z": [3, "café"], "a": {"time": FIXED_TIME, "ok": True}}
    second = {"a": {"ok": True, "time": FIXED_TIME}, "z": [3, "cafe\u0301"]}
    expected = b'{"a":{"ok":true,"time":"2026-01-02T03:04:05.006000Z"},"z":[3,"caf\xc3\xa9"]}'
    assert canonical_json_bytes(first) == expected
    assert canonical_json_bytes(second) == expected
    assert commit_canonical(INSPECTION_DOMAIN, first) == "5cef1c81e2f6e58df557186d3fd44981f4beb359ee316cb25836916ae75f848a"


def test_timestamp_normalization_represents_same_instant_identically():
    offset = timezone(timedelta(hours=5, minutes=30))
    local = datetime(2026, 1, 2, 8, 34, 5, 6000, tzinfo=offset)
    assert canonical_json_bytes({"time": local}) == canonical_json_bytes({"time": FIXED_TIME})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 1.25])
def test_floating_point_values_are_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes({"number": value})


def test_integers_outside_the_portable_range_are_rejected():
    assert canonical_json_bytes({"maximum": 2**63 - 1})
    with pytest.raises(CanonicalizationError, match="64-bit"):
        canonical_json_bytes({"too_large": 2**63})


@pytest.mark.parametrize("value", [{"bad": b"bytes"}, {"bad": {1, 2}}, {1: "non-string key"}])
def test_unsupported_types_are_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes(value)


def test_naive_timestamp_and_normalized_duplicate_keys_are_rejected():
    with pytest.raises(CanonicalizationError, match="timezone"):
        canonical_json_bytes({"time": datetime(2026, 1, 1)})
    with pytest.raises(CanonicalizationError, match="duplicate"):
        canonical_json_bytes({"café": 1, "cafe\u0301": 2})


def test_lists_preserve_semantic_order_while_inspection_projection_sorts_sets():
    assert canonical_json_bytes(["second", "first"]) != canonical_json_bytes(["first", "second"])
    forward = project_inspection(_result())
    reverse = project_inspection(_result(reverse=True))
    assert forward == reverse
    assert [item["finding_id"] for item in forward["findings"]] == sorted(item["finding_id"] for item in forward["findings"])


def test_projection_excludes_transient_verification_status():
    result = _result()
    before = project_inspection(result)
    result.findings[0].verification_status = "Verified removed"
    after = project_inspection(result)
    assert before == after
    assert all("verification_status" not in item for item in after["findings"])


def test_domain_separation_and_one_field_change_modify_commitment():
    payload = {"field": "synthetic"}
    inspection = commit_canonical(INSPECTION_DOMAIN, payload)
    assert inspection != commit_canonical(VERIFICATION_DOMAIN, payload)
    assert inspection != commit_canonical(FILE_DOMAIN, payload)
    assert inspection != commit_bytes(INSPECTION_DOMAIN, b'{"field":"synthetiD"}')
    with pytest.raises(ValueError, match="Unregistered"):
        commit_bytes("unregistered", b"value")


def test_operation_ids_are_random_and_public_commitment_is_deterministic():
    identifiers = {new_operation_id() for _ in range(50)}
    assert len(identifiers) == 50
    assert all(uuid.UUID(value).version == 4 for value in identifiers)
    assert operation_commitment(FIXED_OPERATION_ID) == "319655c6634b950103071ab88a20a75cd4852a0c05c1faf3cca877f30eee6741"
    assert operation_commitment(FIXED_OPERATION_ID) != operation_commitment(new_operation_id())
    assert operation_commitment(FIXED_OPERATION_ID) != commit_bytes(OPERATION_DOMAIN, FIXED_OPERATION_ID.encode())
    with pytest.raises(ValueError, match="UUIDv4"):
        operation_commitment(str(uuid.uuid1()))


class RecordingStream(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.requests: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.requests.append(size)
        return super().read(size)


def test_streaming_hash_empty_file_chunk_boundaries_and_path(tmp_path):
    assert hash_stream(io.BytesIO(b"")) == hashlib.sha256(b"").hexdigest()
    payload = bytes(range(251)) * 19
    stream = RecordingStream(payload)
    assert hash_stream(stream, chunk_size=127) == hashlib.sha256(payload).hexdigest()
    assert stream.requests and set(stream.requests) == {127}
    path = tmp_path / "synthetic.bin"
    path.write_bytes(payload)
    assert file_sha256(path, chunk_size=128) == hashlib.sha256(payload).hexdigest()
    with pytest.raises(ValueError, match="positive"):
        hash_stream(io.BytesIO(payload), chunk_size=0)


def test_inspection_evidence_projection_and_commitment_are_deterministic(capsys):
    first = build_inspection_evidence(_result(), operation_id=FIXED_OPERATION_ID, created_at=FIXED_TIME)
    second = build_inspection_evidence(_result(reverse=True), operation_id=FIXED_OPERATION_ID, created_at=FIXED_TIME)
    assert first.to_dict() == second.to_dict()
    assert first.inspection_commitment() == second.inspection_commitment()
    assert first.public_operation_commitment == operation_commitment(FIXED_OPERATION_ID)
    assert not first.is_complete
    assert capsys.readouterr().out == ""


def test_evidence_record_is_an_immutable_snapshot():
    result = _result()
    record = build_inspection_evidence(result, operation_id=FIXED_OPERATION_ID, created_at=FIXED_TIME)
    original = record.inspection_commitment()
    result.findings[0].raw_value = "Changed after projection"
    exported = record.to_dict()
    exported["initial_inspection"]["findings"][0]["raw_value"] = "Changed exported copy"
    assert record.inspection_commitment() == original
    with pytest.raises(TypeError):
        record.initial_inspection["file_type"] = "PDF"


def test_one_evidence_field_change_changes_inspection_commitment():
    first = build_inspection_evidence(_result(author="Example Person"), operation_id=FIXED_OPERATION_ID, created_at=FIXED_TIME)
    second = build_inspection_evidence(_result(author="Different Example"), operation_id=FIXED_OPERATION_ID, created_at=FIXED_TIME)
    assert first.inspection_commitment() != second.inspection_commitment()


def test_completed_lifecycle_projection_and_verification_commitment():
    before = _result()
    record = build_inspection_evidence(before, operation_id=FIXED_OPERATION_ID, created_at=FIXED_TIME)
    after = InspectionResult(
        "DOCX",
        file_sha256=hashlib.sha256(b"sanitized").hexdigest(),
        file_size=9,
        verified_extension="docx",
    )
    report = compare_results(before, after, ["Remove synthetic metadata."])
    completed = complete_lifecycle_evidence(record, after, report, ["Remove synthetic metadata.", "Remove synthetic metadata."])
    assert completed.is_complete
    assert completed.sanitization_actions == ("Remove synthetic metadata.",)
    assert completed.verification_commitment() == completed.verification_commitment()
    assert len(completed.verification_commitment()) == 64
    with pytest.raises(ValueError, match="already complete"):
        complete_lifecycle_evidence(completed, after, report, [])


def test_lifecycle_completion_rejects_mismatched_file_evidence():
    before = _result()
    record = build_inspection_evidence(before, operation_id=FIXED_OPERATION_ID, created_at=FIXED_TIME)
    after = InspectionResult("DOCX", file_sha256=hashlib.sha256(b"sanitized").hexdigest(), file_size=9, verified_extension="docx")
    report = compare_results(before, after, [])
    report.sanitized_sha256 = hashlib.sha256(b"substituted").hexdigest()
    with pytest.raises(ValueError, match="sanitized evidence file"):
        complete_lifecycle_evidence(record, after, report, [])


def test_incomplete_record_has_no_verification_commitment():
    record = build_inspection_evidence(_result(), operation_id=FIXED_OPERATION_ID, created_at=FIXED_TIME)
    with pytest.raises(ValueError, match="completed"):
        record.verification_commitment()
    with pytest.raises(ValueError, match="together"):
        replace(record, sanitized_file=record.source_file)
