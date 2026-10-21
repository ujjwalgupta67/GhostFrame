from __future__ import annotations

from .models import Finding, Recommendation
from .normalization import stable_finding_id


PRIORITY_ORDER = {"Do not share until resolved": 0, "Remove before sharing": 1, "Review": 2, "No action needed": 3}


def build_recommendations(findings: list[Finding]) -> list[Recommendation]:
    groups: dict[str, tuple[str, str, list[str]]] = {}
    mapping = {
        "precise_location": ("Remove location metadata", "Create a sanitized copy and confirm that valid coordinate evidence is gone."),
        "direct_identity": ("Clear identity and organization fields", "Remove author, owner, company, manager, comment-author, and revision identity metadata before sharing."),
        "device_identifiers": ("Remove device identifiers", "Remove camera, lens, and unique-device serial values that could link files."),
        "collaboration_history": ("Remove comments and tracked changes", "Remove comments and collaboration-person data, then accept or reject tracked changes appropriately."),
        "active_external_behavior": ("Remove external resources and actions", "Remove external templates, linked resources, form actions, and other supported external behavior."),
        "hidden_embedded_content": ("Review hidden and embedded content", "Remove supported attachments and hidden package data; manually review hidden text and unsupported embedded content."),
        "timeline_provenance": ("Review timeline and provenance metadata", "Remove nonessential dates and provenance fields if they should not accompany the shared copy."),
        "software_fingerprint": ("Review software fingerprints", "Remove application and producer fields when the editing environment should remain private."),
    }
    for finding in findings:
        if finding.severity == "Informational" or finding.risk_group not in mapping:
            continue
        title, detail = mapping[finding.risk_group]
        current = groups.setdefault(finding.risk_group, (title, detail, []))
        current[2].append(finding.finding_id)
    output: list[Recommendation] = []
    by_id = {item.finding_id: item for item in findings}
    for group, (title, detail, ids) in groups.items():
        ids = sorted(set(ids))
        priorities = [by_id[item].actionability for item in ids]
        priority = min(priorities, key=lambda value: PRIORITY_ORDER[value])
        output.append(Recommendation(stable_finding_id("REC", group, title, "|".join(ids)), title, detail, priority, ids))
    output.append(Recommendation(
        stable_finding_id("REC", "visible", "Review visible content", "manual"),
        "Review visible content and the filename",
        "Check visible text, faces, screenshots, landmarks, filenames, and document content. Metadata sanitization does not redact them.",
        "Review", [],
    ))
    return sorted(output, key=lambda item: (PRIORITY_ORDER[item.priority], item.title))
