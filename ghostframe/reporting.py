from __future__ import annotations

import html
import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .masking import mask_value, masked_finding
from .models import InspectionResult, VerificationReport
from .security import safe_display_name
from .version import __version__


SCHEMA_VERSION = "2.1"
GHOSTFRAME_VERSION = __version__
SAFETY_STATEMENT = "Potential misuse explanations describe plausible privacy consequences, not proof that exploitation occurred or that the file is malicious."


def _inspection_data(result: InspectionResult, full_evidence: bool) -> dict[str, Any]:
    data = result.to_dict()
    if not full_evidence:
        data["findings"] = [masked_finding(item).to_dict() for item in result.findings]
    return data


def _masked_verification(report: VerificationReport, original: InspectionResult, sanitized: InspectionResult | None, full_evidence: bool) -> dict[str, Any]:
    data = deepcopy(report.to_dict())
    if full_evidence:
        return data
    lookup = {item.finding_id: item for item in original.findings}
    if sanitized:
        lookup.update({item.finding_id: item for item in sanitized.findings})
    for section in ("removed", "remaining", "changed", "introduced"):
        for change in data.get(section, []):
            finding = lookup.get(change.get("finding_id", ""))
            if finding:
                if change.get("before_value"):
                    change["before_value"] = mask_value(finding, change["before_value"])
                if change.get("after_value"):
                    change["after_value"] = mask_value(finding, change["after_value"])
    return data


def _summary(result: InspectionResult) -> dict[str, Any]:
    return {
        "file_type": result.file_type,
        "size": result.file_size,
        "sha256": result.file_sha256,
        "meaningful_findings": result.risk_count,
        "high_priority_findings": result.high_count,
        "exposure_score": result.exposure_score.to_dict(),
        "share_readiness": result.share_readiness.to_dict(),
        "partial_analysis": result.partial_analysis,
        "backend_status": [item.to_dict() for item in result.backend_status],
    }


def build_report_data(
    filename: str,
    result: InspectionResult,
    verification: VerificationReport | None = None,
    *,
    sanitized_result: InspectionResult | None = None,
    full_evidence: bool = False,
) -> dict[str, Any]:
    filename = safe_display_name(filename)
    return {
        "report_schema_version": SCHEMA_VERSION,
        "ghostframe_version": GHOSTFRAME_VERSION,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "original_filename": filename,
        "masking_status": "full evidence" if full_evidence else "masked",
        "safety_statement": SAFETY_STATEMENT,
        "original_inspection_summary": _summary(result),
        "sanitized_inspection_summary": _summary(sanitized_result) if sanitized_result else None,
        "original_inspection": _inspection_data(result, full_evidence),
        "sanitized_inspection": _inspection_data(sanitized_result, full_evidence) if sanitized_result else None,
        "before_after_comparison": _masked_verification(verification, result, sanitized_result, full_evidence) if verification else None,
    }


def json_report(
    filename: str,
    result: InspectionResult,
    verification: VerificationReport | None = None,
    *,
    sanitized_result: InspectionResult | None = None,
    full_evidence: bool = False,
) -> bytes:
    return json.dumps(build_report_data(filename, result, verification, sanitized_result=sanitized_result, full_evidence=full_evidence), indent=2, ensure_ascii=False).encode("utf-8")


def html_report(
    filename: str,
    result: InspectionResult,
    verification: VerificationReport | None = None,
    *,
    sanitized_result: InspectionResult | None = None,
    full_evidence: bool = False,
) -> bytes:
    data = build_report_data(filename, result, verification, sanitized_result=sanitized_result, full_evidence=full_evidence)
    e = lambda value: html.escape(str(value), quote=True)
    findings = data["original_inspection"]["findings"]
    finding_rows = "".join(
        f"<tr><td>{e(item['finding_id'])}</td><td>{e(item['severity'])}</td><td>{e(item['field_name'])}</td><td>{e(item['normalized_value'])}</td><td>{e(item['source'])}</td><td>{e(item['meaning'])}</td></tr>"
        for item in findings
    ) or '<tr><td colspan="6">No supported metadata findings.</td></tr>'
    scenario_cards = "".join(
        f"<article><h3>{e(item.title)}</h3><p><strong>Found:</strong> {e(item.summary)}</p><p><strong>Possible misuse:</strong> {e(item.possible_misuse)}</p><p><strong>Conditions:</strong> {e('; '.join(item.required_conditions))}</p><p><strong>Likelihood / impact / confidence:</strong> {e(item.likelihood)} / {e(item.impact)} / {e(item.confidence)}</p><p><strong>Protect yourself:</strong> {e('; '.join(item.recommended_protection))}</p><p><strong>What this does not prove:</strong> {e(item.not_proven)}</p><p><strong>Evidence:</strong> <code>{e(', '.join(item.evidence_finding_ids))}</code></p></article>"
        for item in result.misuse_scenarios
    ) or "<p>No deterministic potential-misuse scenario met its evidence requirements.</p>"
    mitigations = ""
    if verification:
        mitigations = "".join(
            f"<li><strong>{e(item.title)}:</strong> {e(item.status)} — {e(item.detail)}</li>"
            for item in verification.scenario_mitigations
        ) or "<li>No original scenario required mitigation.</li>"
    readiness = verification.share_readiness if verification else result.share_readiness
    comparison = "Not sanitized during this report." if verification is None else f"{e(verification.status)} — {e(verification.message)}"
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GhostFrame privacy report</title><style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033;line-height:1.5}}h1,h2,h3{{color:#10233f}}.score{{font-size:2rem;font-weight:700}}.note,.readiness{{padding:1rem;background:#fff5d8;border-left:5px solid #9a6700}}article{{border:1px solid #ccd5e0;border-radius:10px;padding:1rem;margin:1rem 0;break-inside:avoid}}table{{border-collapse:collapse;width:100%;font-size:.9rem}}th,td{{border:1px solid #ccd5e0;padding:.55rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}}th{{background:#eef3f8}}code{{overflow-wrap:anywhere}}@media print{{body{{margin:0;max-width:none}}article{{break-inside:avoid}}table{{font-size:.75rem}}}}</style></head><body><h1>GhostFrame metadata privacy report</h1><h2>Executive summary</h2><p><strong>File:</strong> {e(data['original_filename'])}<br><strong>Type:</strong> {e(result.file_type)}<br><strong>Report evidence:</strong> {e(data['masking_status'])}<br><strong>Generated:</strong> {e(data['scan_timestamp'])}</p><div class="readiness"><strong>{e(readiness.state)}</strong><br>{e(readiness.summary)}</div><p class="score">{result.exposure_score.score}/100 — {e(result.exposure_score.rating)} exposure</p><p>{e(result.risk_count)} meaningful finding(s), including {e(result.high_count)} high-priority finding(s).</p><p class="note">{e(SAFETY_STATEMENT)}</p><h2>Potential misuse</h2>{scenario_cards}<h2>Recommended protection</h2><ul>{''.join(f'<li><strong>{e(item.title)}:</strong> {e(item.detail)} Evidence: {e(", ".join(item.finding_ids) or "manual review")}</li>' for item in result.recommendations)}</ul><h2>Sanitization and verification</h2><p>{comparison}</p>{f'<ul>{mitigations}</ul>' if verification else ''}<h2>Raw evidence</h2><p>Sensitive values are {'shown in full by explicit export choice' if full_evidence else 'masked by default'}.</p><table><thead><tr><th>ID</th><th>Severity</th><th>Field</th><th>Value</th><th>Source</th><th>Meaning</th></tr></thead><tbody>{finding_rows}</tbody></table><h2>Limitations</h2><ul>{''.join(f'<li>{e(item)}</li>' for item in result.limitations)}</ul><p class="note">Visible content and unsupported structures still require review. GhostFrame does not claim complete anonymity or malware detection.</p></body></html>"""
    return document.encode("utf-8")
