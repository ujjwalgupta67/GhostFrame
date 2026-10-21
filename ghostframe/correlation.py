from __future__ import annotations

from datetime import datetime

from .models import Correlation, Finding, TimelineEvent
from .normalization import normalize_datetime, stable_finding_id


def _matching(findings: list[Finding], *names: str) -> list[Finding]:
    wanted = {name.lower() for name in names}
    return [item for item in findings if item.field_name.lower() in wanted]


def build_correlations(findings: list[Finding]) -> list[Correlation]:
    results: list[Correlation] = []

    def add(title: str, items: list[Finding], explanation: str, alternative: str, severity: str = "Medium", confidence: str = "High") -> None:
        ids = sorted({item.finding_id for item in items})
        if len(ids) < 2:
            return
        results.append(Correlation(
            correlation_id=stable_finding_id("CORR", "correlation", title, "|".join(ids)),
            title=title, explanation=explanation, confidence=confidence,
            evidence_finding_ids=ids, alternative_interpretation=alternative, severity=severity,
        ))

    creators = _matching(findings, "Creator", "Author")
    modifiers = _matching(findings, "LastModifiedBy", "lastModifiedBy")
    if creators and modifiers:
        distinct = {item.normalized_value.casefold() for item in creators + modifiers if item.normalized_value}
        add("Possible document handoff", creators + modifiers,
            "Creator and last-editor fields expose collaboration identities" + (" with different recorded values." if len(distinct) > 1 else "."),
            "Applications can copy, default, or preserve stale identity fields; the values do not prove who personally edited the file.",
            "High" if len(distinct) > 1 else "Medium")
    companies = _matching(findings, "Company")
    if creators and companies:
        add("Identity and organization clue", creators + companies,
            "An author-like value appears together with an organization field, strengthening an affiliation clue.",
            "The organization may be a software default, former employer, or template value rather than a current affiliation.", "High")
    lat = _matching(findings, "GPSLatitudeDecimal")
    lon = _matching(findings, "GPSLongitudeDecimal")
    times = [item for item in findings if "time" in item.field_name.lower() or "date" in item.field_name.lower()]
    if lat and lon and times:
        add("Location and time combination", lat + lon + times[:2],
            "Coordinates and a recorded timestamp together can reveal where and when the file was captured or edited.",
            "Camera clocks may be wrong and metadata can be edited; this does not establish who was present.", "High")
    models = _matching(findings, "Model", "CameraModel", "LensModel")
    serials = [item for item in findings if "serial" in item.field_name.lower()]
    if models and serials:
        add("Strong device fingerprint", models + serials,
            "A device model combined with a serial-like value can link files produced by the same equipment.",
            "Metadata can be copied or altered, so this is a file-linking clue rather than proof of device ownership.", "High")
    software = _matching(findings, "Software", "Creator", "Producer", "Application", "AppVersion")
    if len(software) >= 2:
        add("Editing environment fingerprint", software[:4],
            "Application and version-related fields can reveal the editing environment.",
            "Values may describe an export library or template rather than the user's main software.", "Low")
    comments = [item for item in findings if item.subcategory == "comment"]
    revisions = [item for item in findings if item.subcategory == "tracked change"]
    if comments and revisions:
        add("Collaboration history", comments + revisions,
            "Comments or revisions contain multiple collaboration records that may expose reviewer identities and activity.",
            "Names may be aliases or application defaults and do not prove real-world identity.", "High")
    originals = _matching(findings, "DateTimeOriginal", "CreateDate", "Created", "CreationDate")
    modifications = _matching(findings, "DateTime", "ModifyDate", "Modified", "ModificationDate")
    if originals and modifications:
        add("Possible editing activity", originals[:2] + modifications[:2],
            "Creation/capture and modification fields record more than one stage in the file timeline.",
            "Different times are normal after saving, exporting, copying, clock changes, or metadata edits; they do not prove tampering.", "Medium")
        try:
            created_value, _ = normalize_datetime(originals[0].raw_value)
            modified_value, _ = normalize_datetime(modifications[0].raw_value)
            created = datetime.fromisoformat(created_value)
            modified = datetime.fromisoformat(modified_value)
            if created.tzinfo is None and modified.tzinfo is None and created > modified:
                add("Possible timeline inconsistency", [originals[0], modifications[0]],
                    "The recorded creation/capture time sorts after the recorded modification time.",
                    "Clock errors, missing timezones, exports, copied metadata, or later metadata edits are common alternatives; this does not prove tampering.", "Medium", "Medium")
        except (ValueError, TypeError):
            pass
    return sorted(results, key=lambda item: item.correlation_id)


def build_timeline(findings: list[Finding]) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    keywords = ("date", "time", "created", "modified", "printed")
    for finding in findings:
        if not any(word in finding.field_name.lower() for word in keywords):
            continue
        normalized, note = normalize_datetime(finding.raw_value)
        if not normalized:
            continue
        events.append(TimelineEvent(
            event_type=finding.field_name,
            normalized_time=normalized,
            raw_time=finding.raw_value,
            source_finding_id=finding.finding_id,
            source=finding.source,
            timezone_note=note,
        ))
    return sorted(events, key=lambda item: (item.normalized_time, item.source_finding_id))
