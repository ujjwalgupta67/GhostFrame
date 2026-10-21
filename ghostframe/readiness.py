from __future__ import annotations

from .models import InspectionResult, ShareReadiness, VerificationReport


def evaluate_share_readiness(result: InspectionResult, verification: VerificationReport | None = None) -> ShareReadiness:
    high = [item for item in result.findings if item.severity in {"High", "Critical"}]
    manual_high = [item for item in high if not item.sanitizable]
    medium = [item for item in result.findings if item.severity == "Medium"]
    reasons: list[str] = []
    evidence: set[str] = set()
    if result.partial_analysis:
        reasons.append("Analysis was partial, so some supported evidence may not have been fully inspected.")
    if high:
        reasons.append(f"{len(high)} high-priority finding(s) remain in this version of the file.")
        evidence.update(item.finding_id for item in high)
    if manual_high:
        reasons.append(f"{len(manual_high)} high-priority finding(s) require manual review or unsupported handling.")
    if verification is not None:
        if verification.status == "Verification incomplete":
            reasons.append("Sanitization verification was incomplete.")
        if verification.introduced:
            reasons.append(f"{len(verification.introduced)} finding(s) were unexpectedly introduced.")
            evidence.update(item.finding_id for item in verification.introduced)
    if result.partial_analysis or high or manual_high or (verification and (verification.status == "Verification incomplete" or verification.introduced)):
        return ShareReadiness(
            "Do not share yet",
            "Resolve the remaining high-priority or incomplete-analysis issues before sharing this version.",
            reasons, sorted(evidence),
        )
    if medium or (verification is not None and verification.status == "Verified with residual findings"):
        evidence.update(item.finding_id for item in medium)
        reasons.append("Medium-priority or residual evidence still needs review.")
        return ShareReadiness(
            "Review recommended",
            "Review the remaining metadata and visible content before sharing.", reasons, sorted(evidence),
        )
    return ShareReadiness(
        "Ready for supported-metadata sharing",
        "GhostFrame found no remaining supported high-priority metadata, but visible and unsupported content still requires your review.",
        ["Visible text, faces, screenshots, filenames, and unsupported structures are outside complete automatic verification."],
        [],
    )
