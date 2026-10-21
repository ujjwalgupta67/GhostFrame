from __future__ import annotations

import re
from dataclasses import replace
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import Finding


EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
URL_RE = re.compile(r"https?://[^\s;]+", re.IGNORECASE)
SENSITIVE_NAMES = {
    "author", "artist", "creator", "lastmodifiedby", "cameraownername", "ownername", "company", "manager",
    "gpslatitudedecimal", "gpslongitudedecimal", "comment", "insertion", "deletion", "movefrom", "moveto",
}


def _mask_words(value: str) -> str:
    words = value.split()
    return " ".join((word[:1] + "…") if word else "" for word in words) or "[masked]"


def mask_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return "[external target masked]"
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
        user_safe_netloc = host + port
        masked_query = urlencode([(key, "***") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, user_safe_netloc, parts.path, masked_query, ""))
    except (ValueError, TypeError):
        return "[external target masked]"


def is_sensitive_finding(finding: Finding) -> bool:
    name = finding.field_name.lower()
    source = finding.source.lower()
    return (
        name in SENSITIVE_NAMES
        or finding.risk_group in {"precise_location", "direct_identity", "device_identifiers", "collaboration_history"}
        or finding.subcategory in {"hidden value", "hidden text", "tracked change", "comment", "identity", "external reference"}
        or "serial" in name
        or "document variable" in finding.category.lower()
        or bool(EMAIL_RE.search(finding.raw_value))
        or bool(URL_RE.search(finding.raw_value))
        or "comments.xml" in source
    )


def mask_value(finding: Finding, value: str | None = None) -> str:
    text = finding.normalized_value if value is None else str(value)
    if not is_sensitive_finding(finding):
        return text
    name = finding.field_name.lower()
    if URL_RE.fullmatch(text.strip()):
        return mask_url(text.strip())
    if URL_RE.search(text):
        return URL_RE.sub(lambda match: mask_url(match.group(0)), text)
    if EMAIL_RE.search(text):
        return EMAIL_RE.sub(lambda match: f"{match.group(1)[:1]}***@{match.group(2).split('.')[0][:1]}***.{match.group(2).rsplit('.', 1)[-1]}", text)
    if "gps" in name or finding.risk_group == "precise_location":
        return "[exact coordinate masked]"
    if "serial" in name or finding.risk_group == "device_identifiers":
        compact = re.sub(r"\s+", "", text)
        return f"••••{compact[-4:]}" if len(compact) >= 4 else "[serial masked]"
    if finding.subcategory in {"comment", "tracked change", "hidden value", "hidden text"} or "document variable" in finding.category.lower():
        return "[sensitive content masked]"
    if finding.risk_group == "direct_identity" or name in SENSITIVE_NAMES:
        return _mask_words(text)
    return "[sensitive value masked]"


def masked_finding(finding: Finding) -> Finding:
    if not is_sensitive_finding(finding):
        return replace(finding)
    return replace(finding, raw_value=mask_value(finding, finding.raw_value), normalized_value=mask_value(finding, finding.normalized_value))
