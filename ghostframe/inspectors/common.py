from __future__ import annotations

from typing import Any

from ..models import Finding
from ..normalization import compact_text, stable_finding_id


IDENTITY_FIELDS = {"author", "artist", "creator", "lastmodifiedby", "cameraownername", "ownername", "company", "manager"}
SERIAL_MARKERS = ("serial", "uniqueid", "unique id")
SOFTWARE_FIELDS = {"software", "producer", "creator tool", "application", "appversion", "applicationversion"}
TIME_MARKERS = ("date", "time", "created", "modified", "printed")


def classify_field(name: str, raw: Any, category: str = "Metadata") -> dict[str, str | bool]:
    lower = name.lower()
    value = compact_text(raw)
    if "gps" in lower or lower in {"latitude", "longitude"}:
        return dict(subcategory="location component", meaning="A recorded GPS component. It is not treated as a complete coordinate unless the required companion fields validate.", privacy_impact="May contribute to a location disclosure when complete and valid.", exposure_scenario="A recipient could combine it with the other GPS components if they are present.", severity="Medium", risk_group="precise_location")
    if any(marker in lower for marker in SERIAL_MARKERS):
        return dict(subcategory="device identifier", meaning="A device-specific identifier.", privacy_impact="Can create a persistent fingerprint across files.", exposure_scenario="Several files with the same identifier could be linked to one device.", severity="High", risk_group="device_identifiers")
    if lower in IDENTITY_FIELDS or any(key in lower for key in ("author", "owner")):
        severity = "High" if value and value.lower() not in {"unknown", "user", "none"} else "Low"
        return dict(subcategory="identity", meaning="A person or organization label stored by the creating application.", privacy_impact="May expose a name or organizational clue.", exposure_scenario="A recipient could associate the file with the recorded label.", severity=severity, risk_group="direct_identity")
    if lower in SOFTWARE_FIELDS or any(key in lower for key in ("software", "producer", "application", "version")):
        return dict(subcategory="software", meaning="Identifies software involved in creating or exporting the file.", privacy_impact="Provides a low-risk editing-environment fingerprint.", exposure_scenario="A recipient could infer the application or library used.", severity="Low", risk_group="software_fingerprint")
    if any(marker in lower for marker in TIME_MARKERS):
        return dict(subcategory="timeline", meaning="A timestamp recorded in file metadata.", privacy_impact="May reveal when capture, editing, printing, or review occurred.", exposure_scenario="A recipient could reconstruct parts of the file's timeline.", severity="Medium", risk_group="timeline_provenance")
    if any(key in lower for key in ("width", "height", "orientation", "resolution", "profile", "color", "pages", "count")):
        return dict(subcategory="technical", meaning="A technical rendering or structure value.", privacy_impact="Usually low privacy impact by itself.", exposure_scenario="It mainly helps software render or describe the file.", severity="Informational", risk_group="technical")
    return dict(subcategory=category.lower(), meaning="A value stored outside the main visible content.", privacy_impact="May reveal provenance or contextual information depending on its value.", exposure_scenario="A recipient inspecting metadata could read this value.", severity="Low", risk_group="timeline_provenance")


def make_finding(file_type: str, category: str, field_name: str, raw_value: Any, source: str, *, normalized_value: Any | None = None, backend: str = "built-in", sanitizable: bool = True, sanitization_action: str = "Remove the containing metadata field.", confidence: str = "Confirmed", evidence_type: str = "direct metadata", limitations: str = "", page_number: int | None = None, overrides: dict[str, Any] | None = None) -> Finding:
    info = classify_field(field_name, raw_value, category)
    if overrides:
        info.update(overrides)
    raw = compact_text(raw_value)
    normalized = compact_text(raw if normalized_value is None else normalized_value)
    severity = str(info["severity"])
    if severity == "Informational":
        actionability = "No action needed"
    elif severity in {"High", "Critical"} and not sanitizable:
        actionability = "Do not share until resolved"
    elif severity in {"High", "Critical"}:
        actionability = "Remove before sharing"
    else:
        actionability = "Review"
    return Finding(
        finding_id=stable_finding_id(file_type, category, field_name, source),
        category=category, subcategory=str(info["subcategory"]), field_name=field_name,
        raw_value=raw, normalized_value=normalized, meaning=str(info["meaning"]), source=source,
        privacy_impact=str(info["privacy_impact"]), exposure_scenario=str(info["exposure_scenario"]),
        severity=severity, confidence=confidence, evidence_type=evidence_type,
        sanitizable=sanitizable, sanitization_action=sanitization_action, limitations=limitations,
        backend=backend, risk_group=str(info["risk_group"]), page_number=page_number,
        actionability=str(info.get("actionability", actionability)),
    )
