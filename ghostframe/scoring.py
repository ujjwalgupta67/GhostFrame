from __future__ import annotations

from .models import Correlation, ExposureScore, Finding, ScoreContribution, SEVERITY_ORDER


GROUP_CAPS = {
    "precise_location": 30,
    "direct_identity": 24,
    "device_identifiers": 20,
    "collaboration_history": 16,
    "hidden_embedded_content": 18,
    "active_external_behavior": 24,
    "timeline_provenance": 10,
    "software_fingerprint": 6,
    "technical": 2,
}
SEVERITY_POINTS = {"Informational": 0, "Low": 2, "Medium": 6, "High": 12, "Critical": 20}


def _deduplicate_group(group: str, items: list[Finding]) -> list[Finding]:
    ordered = sorted(items, key=lambda item: (-SEVERITY_ORDER.get(item.severity, 0), item.finding_id))
    if group == "precise_location":
        derived = [item for item in ordered if item.field_name in {"GPSLatitudeDecimal", "GPSLongitudeDecimal"}]
        if derived:
            return sorted(derived, key=lambda item: item.finding_id)
        return ordered[:1]
    seen: set[str] = set()
    output: list[Finding] = []
    for item in ordered:
        if group in {"direct_identity", "software_fingerprint", "device_identifiers"}:
            key = item.normalized_value.strip().casefold()
        else:
            key = f"{item.field_name.casefold()}\x1f{item.normalized_value.strip().casefold()}"
        if not key or key in seen:
            continue
        seen.add(key); output.append(item)
    return sorted(output, key=lambda item: item.finding_id)


def calculate_exposure_score(findings: list[Finding], correlations: list[Correlation] | None = None) -> ExposureScore:
    grouped: dict[str, list[Finding]] = {}
    for finding in sorted(findings, key=lambda item: item.finding_id):
        grouped.setdefault(finding.risk_group, []).append(finding)
    contributions: list[ScoreContribution] = []
    for group in GROUP_CAPS:
        items = _deduplicate_group(group, grouped.get(group, []))
        if not items:
            continue
        cap = GROUP_CAPS[group]
        raw_points = sum(SEVERITY_POINTS.get(item.severity, 0) for item in items)
        points = min(cap, raw_points)
        if points == 0:
            continue
        highest = max(items, key=lambda item: SEVERITY_ORDER.get(item.severity, 0))
        contributions.append(ScoreContribution(
            group=group,
            points=points,
            cap=cap,
            finding_ids=[item.finding_id for item in items],
            explanation=f"{len(items)} item(s); strongest evidence is {highest.field_name} ({highest.severity}). The {group.replace('_', ' ')} group is capped at {cap} points.",
        ))
    base_points = sum(item.points for item in contributions)
    known_ids = {item.finding_id for item in findings}
    correlation_bonus = 0
    context_adjustment = 0
    bonus_ids: set[str] = set()
    context_ids: set[str] = set()
    seen_evidence: set[tuple[str, ...]] = set()
    for correlation in sorted(correlations or [], key=lambda item: item.correlation_id):
        cited = tuple(sorted(set(correlation.evidence_finding_ids)))
        if not cited or not set(cited).issubset(known_ids) or cited in seen_evidence:
            continue
        seen_evidence.add(cited)
        if correlation.title in {"Location and time combination", "Identity and organization clue"}:
            context_adjustment = min(4, context_adjustment + 2); context_ids.update(cited)
        else:
            bonus = 3 if correlation.severity == "High" else 2 if correlation.severity == "Medium" else 1
            correlation_bonus = min(10, correlation_bonus + bonus); bonus_ids.update(cited)
    if correlation_bonus:
        contributions.append(ScoreContribution("correlation_bonus", correlation_bonus, 10, sorted(bonus_ids), "Evidence-backed correlations add limited context without recounting their base fields."))
    if context_adjustment:
        contributions.append(ScoreContribution("context_adjustment", context_adjustment, 4, sorted(context_ids), "Specific evidence combinations add a small, capped context adjustment."))
    score = min(100, base_points + correlation_bonus + context_adjustment)
    rating = "Minimal" if score <= 5 else "Low" if score <= 20 else "Moderate" if score <= 45 else "High" if score <= 70 else "Severe"
    return ExposureScore(score=score, rating=rating, contributions=contributions, base_points=base_points, correlation_bonus=correlation_bonus, context_adjustment=context_adjustment)
