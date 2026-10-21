from __future__ import annotations

from dataclasses import dataclass

from .comparison import compare_results
from .correlation import build_correlations, build_timeline
from .inspectors.common import make_finding
from .inspectors.docx import inspect_docx
from .inspectors.image import inspect_image
from .inspectors.pdf import inspect_pdf
from .models import BackendStatus, Finding, InspectionResult, VerificationReport
from .misuse import build_misuse_scenarios
from .normalization import compact_text, sha256_bytes
from .planning import build_sanitization_plan
from .readiness import evaluate_share_readiness
from .recommendations import build_recommendations
from .sanitizers.docx import sanitize_docx
from .sanitizers.image import sanitize_image
from .sanitizers.pdf import sanitize_pdf
from .scoring import calculate_exposure_score
from .security import (
    MAX_DOCX_EXPANDED_SIZE,
    MAX_DOCX_FILES,
    MAX_FILE_SIZE,
    MAX_IMAGE_PIXELS,
    UnsafeFileError,
    UnsupportedFileError,
    detect_file_type,
    exiftool_status,
    run_exiftool,
    safe_display_name,
)


@dataclass
class SanitizationOutcome:
    data: bytes
    filename: str
    before: InspectionResult
    after: InspectionResult
    verification: VerificationReport
    actions: list[str]


def _enrich_with_exiftool(result: InspectionResult, data: bytes, file_type: str) -> None:
    available, version, availability_detail = exiftool_status()
    if not available:
        result.backend_status.append(BackendStatus("ExifTool", False, "unavailable", version, availability_detail))
        return
    records, status, detail = run_exiftool(data, file_type)
    result.backend_status.append(BackendStatus("ExifTool", status == "available", status, version, detail))
    if not records:
        if status == "failed":
            result.partial_analysis = True
        return
    ignored = {
        "SourceFile", "ExifTool:ExifToolVersion", "System:FileName", "System:Directory", "System:FileSize",
        "System:FilePermissions", "File:FileType", "File:FileTypeExtension", "File:MIMEType",
    }
    existing = {(item.field_name.casefold(), item.normalized_value.casefold()) for item in result.findings}
    for key, value in sorted(records[0].items()):
        if key in ignored or (isinstance(value, (dict, list)) and len(compact_text(value)) > 800):
            continue
        field_name = key.split(":", 1)[-1]
        normalized = compact_text(value)
        if (field_name.casefold(), normalized.casefold()) in existing:
            continue
        category = key.split(":", 1)[0] if ":" in key else "ExifTool"
        finding = make_finding(
            file_type, f"ExifTool {category}", field_name, value, f"ExifTool/{key}", backend=f"ExifTool {version}",
            sanitizable=False, sanitization_action="Built-in sanitizer support is not confirmed for this enrichment-only field.",
            confidence="High", limitations="ExifTool enrichment is independently observed; removal is not promised unless a built-in inspector also recognizes the field.",
        )
        result.findings.append(finding); existing.add((field_name.casefold(), normalized.casefold()))


def _finalize(result: InspectionResult, data: bytes, file_type: str, use_exiftool: bool) -> InspectionResult:
    result.file_sha256 = sha256_bytes(data); result.file_size = len(data); result.verified_extension = file_type
    result.backend_status.insert(0, BackendStatus("Built-in parser", True, "available", detail=f"Native {result.file_type} inspection completed locally."))
    if use_exiftool:
        _enrich_with_exiftool(result, data, file_type)
    else:
        result.backend_status.append(BackendStatus("ExifTool", False, "disabled", detail="Optional enrichment was disabled for this scan."))
    result.findings.sort(key=lambda item: (item.category, item.source, item.field_name, item.finding_id))
    result.correlations = build_correlations(result.findings)
    by_id = {item.finding_id: item for item in result.findings}
    for correlation in result.correlations:
        for finding_id in correlation.evidence_finding_ids:
            finding = by_id.get(finding_id)
            if finding is not None:
                finding.related_finding_ids = sorted(set(finding.related_finding_ids + [item for item in correlation.evidence_finding_ids if item != finding_id]))
    result.timeline = build_timeline(result.findings)
    result.misuse_scenarios = build_misuse_scenarios(result.findings)
    result.exposure_score = calculate_exposure_score(result.findings, result.correlations)
    result.sanitization_plan = build_sanitization_plan(result.file_type, result.findings)
    result.recommendations = build_recommendations(result.findings)
    result.limitations.extend([
        "GhostFrame analyzes supported metadata and structures; it does not determine identity, ownership, intent, or whether content is malicious.",
        "Visible text, faces, image content, writing style, and unsupported proprietary structures may still reveal information.",
        "Metadata can be stale, copied, edited, or generated by software defaults; findings are evidence clues, not forensic certainty.",
    ])
    if not result.findings:
        result.notes.append("No supported metadata evidence was found.")
    result.share_readiness = evaluate_share_readiness(result)
    return result


def inspect_file(data: bytes, filename: str, *, use_exiftool: bool = True) -> InspectionResult:
    safe_name = safe_display_name(filename)
    file_type = detect_file_type(data, safe_name)
    if file_type in {"jpg", "png"}:
        result = inspect_image(data, file_type)
    elif file_type == "pdf":
        result = inspect_pdf(data)
    else:
        result = inspect_docx(data)
    return _finalize(result, data, file_type, use_exiftool)


def _sanitize(data: bytes, file_type: str) -> tuple[bytes, list[str]]:
    if file_type in {"jpg", "png"}:
        return sanitize_image(data, file_type)
    if file_type == "pdf":
        return sanitize_pdf(data)
    return sanitize_docx(data)


def sanitize_file(data: bytes, filename: str) -> tuple[bytes, str]:
    safe_name = safe_display_name(filename); file_type = detect_file_type(data, safe_name)
    cleaned, _ = _sanitize(data, file_type)
    return cleaned, f"{safe_name.rsplit('.', 1)[0]}_sanitized.{file_type}"


def sanitize_with_verification(data: bytes, filename: str, before: InspectionResult | None = None, *, use_exiftool: bool = True) -> SanitizationOutcome:
    safe_name = safe_display_name(filename); file_type = detect_file_type(data, safe_name)
    before = before or inspect_file(data, safe_name, use_exiftool=use_exiftool)
    cleaned, actions = _sanitize(data, file_type)
    cleaned_name = f"{safe_name.rsplit('.', 1)[0]}_sanitized.{file_type}"
    after = inspect_file(cleaned, cleaned_name, use_exiftool=use_exiftool)
    verification = compare_results(before, after, actions)
    return SanitizationOutcome(cleaned, cleaned_name, before, after, verification, actions)


__all__ = [
    "MAX_FILE_SIZE", "MAX_IMAGE_PIXELS", "MAX_DOCX_FILES", "MAX_DOCX_EXPANDED_SIZE",
    "Finding", "InspectionResult", "SanitizationOutcome", "UnsafeFileError", "UnsupportedFileError",
    "detect_file_type", "inspect_file", "safe_display_name", "sanitize_file", "sanitize_with_verification",
]
