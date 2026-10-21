from __future__ import annotations

from .models import Finding, PlanItem, SanitizationPlan


def build_sanitization_plan(file_type: str, findings: list[Finding]) -> SanitizationPlan:
    items: list[PlanItem] = []
    removable = [item for item in findings if item.sanitizable]
    manual = [item for item in findings if not item.sanitizable and item.severity != "Informational"]
    if removable:
        actions: dict[str, list[str]] = {}
        for item in removable:
            actions.setdefault(item.sanitization_action, []).append(item.finding_id)
        for action, ids in sorted(actions.items()):
            items.append(PlanItem("Will remove", action, f"Applies to {len(ids)} observed finding(s).", ids))
    items.append(PlanItem("Will preserve", "Original file", "The uploaded file is never overwritten; GhostFrame creates a separate copy."))
    if file_type in {"JPG", "PNG"}:
        items.append(PlanItem("Will preserve", "Rendered image", "Pixel dimensions and visible pixels are preserved where the format permits."))
        items.append(PlanItem("Cannot automatically remove", "Visible content", "Faces, text, reflections, and other visible details are not redacted."))
        items.append(PlanItem("May affect document features", "Lossy JPEG re-encoding", "JPEG output is re-encoded at high quality and may not be byte-for-byte identical."))
    elif file_type == "PDF":
        items.append(PlanItem("Will preserve", "Ordinary page content", "Visible page content is preserved where practical."))
        items.append(PlanItem("May affect document features", "Interactive behavior", "Forms, actions, attachments, or external behaviors may be removed or altered."))
    else:
        items.append(PlanItem("Will preserve", "Ordinary document text", "Visible Word document text is retained where practical."))
        items.append(PlanItem("May affect document features", "Review and linked features", "Comments, tracked changes, links, macros, embedded objects, or linked resources may be removed."))
    for item in manual:
        items.append(PlanItem("Requires manual review", item.field_name, item.limitations or item.privacy_impact, [item.finding_id]))
    items.append(PlanItem("Requires manual review", "Unsupported and visible structures", "Review the sanitized file visually. Unsupported structures may still reveal information."))
    return SanitizationPlan(items)
