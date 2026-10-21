from __future__ import annotations

from .models import FindingChange, InspectionResult, VerificationReport
from .mitigation import evaluate_scenario_mitigation
from .readiness import evaluate_share_readiness


def compare_results(before: InspectionResult, after: InspectionResult, actions: list[str] | None = None) -> VerificationReport:
    old = {item.finding_id: item for item in before.findings}
    new = {item.finding_id: item for item in after.findings}
    removed: list[FindingChange] = []
    remaining: list[FindingChange] = []
    changed: list[FindingChange] = []
    introduced: list[FindingChange] = []
    for finding_id, item in sorted(old.items()):
        newer = new.get(finding_id)
        if newer is None:
            item.verification_status = "Verified removed"
            removed.append(FindingChange(finding_id, item.field_name, item.source, item.raw_value, "", "Removed"))
        elif newer.raw_value != item.raw_value:
            successful_change = item.sanitization_action.lower().startswith("regenerate")
            item.verification_status = "Verified changed" if successful_change else "Changed; review required"
            changed.append(FindingChange(finding_id, item.field_name, item.source, item.raw_value, newer.raw_value, item.verification_status))
        else:
            item.verification_status = "Preserved or requires manual review" if not item.sanitizable else "Still present"
            remaining.append(FindingChange(finding_id, item.field_name, item.source, item.raw_value, newer.raw_value, item.verification_status))
    for finding_id, item in sorted(new.items()):
        if finding_id not in old:
            introduced.append(FindingChange(finding_id, item.field_name, item.source, "", item.raw_value, "Unexpectedly introduced"))
    expected = [item for item in before.findings if item.sanitizable]
    unresolved_ids = {item.finding_id for item in remaining}
    unresolved_ids.update(item.finding_id for item in changed if item.status != "Verified changed")
    unresolved = any(item.finding_id in unresolved_ids for item in expected)
    residual_privacy = any(old[item.finding_id].severity != "Informational" for item in remaining if item.finding_id in old)
    if before.file_type != after.file_type:
        status = "Verification incomplete"
    elif unresolved or residual_privacy or introduced:
        status = "Verified with residual findings"
    else:
        status = "Verified"
    message = (
        "GhostFrame verified that the metadata and active references supported by this version were removed. "
        "Visible content and unsupported structures may still reveal information."
        if status == "Verified" else
        "The sanitized file was re-inspected, but residual, changed, or newly observed evidence requires review."
    )
    report = VerificationReport(
        status=status, removed=removed, remaining=remaining, changed=changed, introduced=introduced,
        actions_performed=sorted(set(actions or [item.sanitization_action for item in before.findings if item.sanitizable])),
        original_sha256=before.file_sha256, sanitized_sha256=after.file_sha256,
        original_size=before.file_size, sanitized_size=after.file_size,
        original_type=before.file_type, sanitized_type=after.file_type, message=message,
    )
    report.scenario_mitigations = evaluate_scenario_mitigation(before, after, report)
    report.share_readiness = evaluate_share_readiness(after, report)
    return report
