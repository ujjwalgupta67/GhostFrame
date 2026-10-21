from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CONFIDENCE_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Confirmed": 3}
ACTIONABILITY_VALUES = {"No action needed", "Review", "Remove before sharing", "Do not share until resolved"}
LIKELIHOOD_VALUES = {"Unlikely", "Possible", "Likely"}
IMPACT_VALUES = {"Low", "Moderate", "High", "Severe"}
SHARE_READINESS_VALUES = {"Ready for supported-metadata sharing", "Review recommended", "Do not share yet"}
MITIGATION_VALUES = {"Mitigated", "Partially mitigated", "Not mitigated", "Verification unavailable"}


@dataclass
class Finding:
    finding_id: str
    category: str
    subcategory: str
    field_name: str
    raw_value: str
    normalized_value: str
    meaning: str
    source: str
    privacy_impact: str
    exposure_scenario: str
    severity: str = "Low"
    confidence: str = "Confirmed"
    evidence_type: str = "direct metadata"
    sanitizable: bool = True
    sanitization_action: str = "Remove the containing metadata field."
    verification_status: str = "Not yet sanitized"
    related_finding_ids: list[str] = field(default_factory=list)
    limitations: str = ""
    backend: str = "built-in"
    risk_group: str = "timeline_provenance"
    page_number: int | None = None
    actionability: str = "Review"

    # Compatibility with the original UI/tests.
    @property
    def name(self) -> str:
        return self.field_name

    @property
    def value(self) -> str:
        return self.raw_value

    @property
    def risk(self) -> str:
        return self.privacy_impact

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Correlation:
    correlation_id: str
    title: str
    explanation: str
    confidence: str
    evidence_finding_ids: list[str]
    alternative_interpretation: str
    severity: str = "Medium"
    evidence_type: str = "derived correlation"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEvent:
    event_type: str
    normalized_time: str
    raw_time: str
    source_finding_id: str
    source: str
    timezone_note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScoreContribution:
    group: str
    points: int
    cap: int
    finding_ids: list[str]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExposureScore:
    score: int = 0
    rating: str = "Minimal"
    contributions: list[ScoreContribution] = field(default_factory=list)
    base_points: int = 0
    correlation_bonus: int = 0
    context_adjustment: int = 0
    note: str = "This score estimates metadata exposure; it does not indicate whether a file is malicious."

    def to_dict(self) -> dict[str, Any]:
        return {"score": self.score, "rating": self.rating, "base_points": self.base_points, "correlation_bonus": self.correlation_bonus, "context_adjustment": self.context_adjustment, "contributions": [item.to_dict() for item in self.contributions], "note": self.note}


@dataclass
class MisuseScenario:
    scenario_id: str
    title: str
    category: str
    summary: str
    possible_misuse: str
    exposed_asset: str
    required_conditions: list[str]
    likelihood: str
    impact: str
    confidence: str
    evidence_finding_ids: list[str]
    why_it_matters: str
    recommended_protection: list[str]
    alternative_explanation: str
    not_proven: str
    required_evidence_ids: list[str] = field(default_factory=list)
    actionability: str = "Review"

    def __post_init__(self) -> None:
        if self.likelihood not in LIKELIHOOD_VALUES:
            raise ValueError(f"Invalid likelihood: {self.likelihood}")
        if self.impact not in IMPACT_VALUES:
            raise ValueError(f"Invalid impact: {self.impact}")
        if self.confidence not in CONFIDENCE_ORDER:
            raise ValueError(f"Invalid confidence: {self.confidence}")
        if self.actionability not in ACTIONABILITY_VALUES:
            raise ValueError(f"Invalid actionability: {self.actionability}")
        if not self.evidence_finding_ids:
            raise ValueError("A misuse scenario requires cited evidence.")
        if not self.required_evidence_ids:
            self.required_evidence_ids = list(self.evidence_finding_ids)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Recommendation:
    recommendation_id: str
    title: str
    detail: str
    priority: str
    finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ShareReadiness:
    state: str
    summary: str
    reasons: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.state not in SHARE_READINESS_VALUES:
            raise ValueError(f"Invalid share-readiness state: {self.state}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScenarioMitigation:
    scenario_id: str
    title: str
    status: str
    evidence_finding_ids: list[str]
    detail: str

    def __post_init__(self) -> None:
        if self.status not in MITIGATION_VALUES:
            raise ValueError(f"Invalid mitigation status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlanItem:
    section: str
    title: str
    detail: str
    finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SanitizationPlan:
    items: list[PlanItem] = field(default_factory=list)

    def in_section(self, section: str) -> list[PlanItem]:
        return [item for item in self.items if item.section == section]

    def to_dict(self) -> dict[str, Any]:
        return {"items": [item.to_dict() for item in self.items]}


@dataclass
class BackendStatus:
    name: str
    available: bool
    status: str
    version: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InspectionResult:
    file_type: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    exposure_score: ExposureScore = field(default_factory=ExposureScore)
    sanitization_plan: SanitizationPlan = field(default_factory=SanitizationPlan)
    backend_status: list[BackendStatus] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    file_sha256: str = ""
    file_size: int = 0
    verified_extension: str = ""
    partial_analysis: bool = False
    misuse_scenarios: list[MisuseScenario] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    share_readiness: ShareReadiness = field(default_factory=lambda: ShareReadiness("Review recommended", "Complete the analysis before sharing."))

    @property
    def risk_count(self) -> int:
        return sum(item.severity != "Informational" for item in self.findings)

    @property
    def high_count(self) -> int:
        return sum(SEVERITY_ORDER.get(item.severity, 0) >= SEVERITY_ORDER["High"] for item in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_type": self.file_type,
            "verified_extension": self.verified_extension,
            "size": self.file_size,
            "sha256": self.file_sha256,
            "findings": [item.to_dict() for item in self.findings],
            "correlations": [item.to_dict() for item in self.correlations],
            "timeline": [item.to_dict() for item in self.timeline],
            "exposure_score": self.exposure_score.to_dict(),
            "sanitization_plan": self.sanitization_plan.to_dict(),
            "backend_status": [item.to_dict() for item in self.backend_status],
            "notes": list(self.notes),
            "limitations": list(self.limitations),
            "partial_analysis": self.partial_analysis,
            "potential_misuse_scenarios": [item.to_dict() for item in self.misuse_scenarios],
            "recommendations": [item.to_dict() for item in self.recommendations],
            "share_readiness": self.share_readiness.to_dict(),
        }


@dataclass
class FindingChange:
    finding_id: str
    field_name: str
    source: str
    before_value: str = ""
    after_value: str = ""
    status: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationReport:
    status: str
    removed: list[FindingChange]
    remaining: list[FindingChange]
    changed: list[FindingChange]
    introduced: list[FindingChange]
    actions_performed: list[str]
    original_sha256: str
    sanitized_sha256: str
    original_size: int
    sanitized_size: int
    original_type: str
    sanitized_type: str
    message: str
    scenario_mitigations: list[ScenarioMitigation] = field(default_factory=list)
    share_readiness: ShareReadiness = field(default_factory=lambda: ShareReadiness("Review recommended", "Verification is not complete."))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data
