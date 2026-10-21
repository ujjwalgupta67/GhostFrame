from __future__ import annotations

from .models import InspectionResult, ScenarioMitigation, VerificationReport


def evaluate_scenario_mitigation(before: InspectionResult, after: InspectionResult, verification: VerificationReport) -> list[ScenarioMitigation]:
    removed = {item.finding_id for item in verification.removed}
    changed_unverified = {item.finding_id for item in verification.changed if item.status != "Verified changed"}
    after_categories = {item.category for item in after.misuse_scenarios}
    results: list[ScenarioMitigation] = []
    for scenario in before.misuse_scenarios:
        required = set(scenario.required_evidence_ids)
        if before.partial_analysis or after.partial_analysis or verification.status == "Verification incomplete":
            status = "Verification unavailable"
            detail = "The scenario could not be fully evaluated because inspection or verification was incomplete."
        elif scenario.category not in after_categories and required.issubset(removed | {item.finding_id for item in verification.changed if item.status == "Verified changed"}):
            status = "Mitigated"
            detail = "All required supported evidence was removed or successfully regenerated, and no equivalent scenario was detected in the sanitized copy."
        elif scenario.category not in after_categories:
            status = "Mitigated"
            detail = "No equivalent evidence combination was detected in the sanitized copy."
        elif required & removed:
            status = "Partially mitigated"
            detail = "Some supporting evidence was removed, but equivalent or remaining evidence still supports this scenario."
        else:
            status = "Not mitigated"
            detail = "Required evidence or an equivalent evidence combination remains in the sanitized copy."
        if required & changed_unverified:
            status = "Partially mitigated"
            detail = "Required evidence changed, but the change was not a verified removal."
        results.append(ScenarioMitigation(scenario.scenario_id, scenario.title, status, scenario.evidence_finding_ids, detail))
    return results
