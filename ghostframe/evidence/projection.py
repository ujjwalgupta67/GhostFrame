from __future__ import annotations

from copy import deepcopy
from typing import Any

from ghostframe.models import InspectionResult, VerificationReport


def _sorted_ids(values: list[str]) -> list[str]:
    return sorted(set(values))


def _project_finding(value: dict[str, Any]) -> dict[str, Any]:
    projected = deepcopy(value)
    projected.pop("verification_status", None)
    projected["related_finding_ids"] = _sorted_ids(projected.get("related_finding_ids", []))
    return projected


def _project_readiness(value: dict[str, Any]) -> dict[str, Any]:
    projected = deepcopy(value)
    projected["reasons"] = sorted(projected.get("reasons", []))
    projected["finding_ids"] = _sorted_ids(projected.get("finding_ids", []))
    return projected


def project_inspection(result: InspectionResult) -> dict[str, Any]:
    """Create the deterministic evidence projection of an inspection result.

    The adapter deliberately excludes ``Finding.verification_status`` because
    comparison mutates that transient UI state after the initial inspection.
    Lists with set-like semantics are sorted here; chronological timeline order
    and other meaningful sequences receive explicit stable sort keys.
    """

    data = result.to_dict()
    data["findings"] = sorted((_project_finding(item) for item in data["findings"]), key=lambda item: item["finding_id"])
    for finding in data["findings"]:
        finding["related_finding_ids"] = _sorted_ids(finding.get("related_finding_ids", []))
    data["correlations"] = sorted(data["correlations"], key=lambda item: item["correlation_id"])
    for correlation in data["correlations"]:
        correlation["evidence_finding_ids"] = _sorted_ids(correlation.get("evidence_finding_ids", []))
    data["timeline"] = sorted(data["timeline"], key=lambda item: (item["normalized_time"], item["source_finding_id"], item["event_type"]))
    contributions = data["exposure_score"].get("contributions", [])
    for contribution in contributions:
        contribution["finding_ids"] = _sorted_ids(contribution.get("finding_ids", []))
    data["exposure_score"]["contributions"] = sorted(contributions, key=lambda item: (item["group"], item["points"], item["cap"]))
    plan_items = data["sanitization_plan"].get("items", [])
    for item in plan_items:
        item["finding_ids"] = _sorted_ids(item.get("finding_ids", []))
    data["sanitization_plan"]["items"] = sorted(plan_items, key=lambda item: (item["section"], item["title"], item["detail"], item["finding_ids"]))
    data["backend_status"] = sorted(data["backend_status"], key=lambda item: (item["name"], item["status"], item.get("version", ""), item.get("detail", "")))
    data["notes"] = sorted(data["notes"])
    data["limitations"] = sorted(data["limitations"])
    scenarios = data.get("potential_misuse_scenarios", [])
    for scenario in scenarios:
        scenario["evidence_finding_ids"] = _sorted_ids(scenario.get("evidence_finding_ids", []))
        scenario["required_evidence_ids"] = _sorted_ids(scenario.get("required_evidence_ids", []))
        scenario["required_conditions"] = sorted(scenario.get("required_conditions", []))
        scenario["recommended_protection"] = sorted(scenario.get("recommended_protection", []))
    data["potential_misuse_scenarios"] = sorted(scenarios, key=lambda item: item["scenario_id"])
    recommendations = data.get("recommendations", [])
    for recommendation in recommendations:
        recommendation["finding_ids"] = _sorted_ids(recommendation.get("finding_ids", []))
    data["recommendations"] = sorted(recommendations, key=lambda item: item["recommendation_id"])
    data["share_readiness"] = _project_readiness(data["share_readiness"])
    return data


def _project_change(value: dict[str, Any]) -> dict[str, Any]:
    return deepcopy(value)


def project_verification(report: VerificationReport) -> dict[str, Any]:
    data = report.to_dict()
    for section in ("removed", "remaining", "changed", "introduced"):
        data[section] = sorted((_project_change(item) for item in data[section]), key=lambda item: (item["finding_id"], item["status"]))
    data["actions_performed"] = sorted(set(data["actions_performed"]))
    for mitigation in data.get("scenario_mitigations", []):
        mitigation["evidence_finding_ids"] = _sorted_ids(mitigation.get("evidence_finding_ids", []))
    data["scenario_mitigations"] = sorted(data.get("scenario_mitigations", []), key=lambda item: item["scenario_id"])
    data["share_readiness"] = _project_readiness(data["share_readiness"])
    return data
