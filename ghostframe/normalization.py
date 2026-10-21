from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact_text(value: Any, limit: int = 800) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    elif isinstance(value, (list, tuple)):
        text = ", ".join(compact_text(item, 200) for item in value)
    else:
        text = str(value)
    text = " ".join(text.replace("\x00", "").split())
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def stable_finding_id(file_type: str, category: str, field_name: str, source: str) -> str:
    key = "\x1f".join((file_type.lower(), category.lower(), field_name.lower(), source.lower()))
    return f"GF-{file_type.upper()}-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:12].upper()}"


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def normalize_datetime(raw: Any) -> tuple[str, str]:
    text = compact_text(raw)
    if not text:
        return "", "No timestamp value"
    # PDF: D:YYYYMMDDHHmmSSOHH'mm'
    match = re.fullmatch(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}'?\d{2}'?)?", text)
    if match:
        parts = match.groups()
        year = int(parts[0]); month = int(parts[1] or 1); day = int(parts[2] or 1)
        hour = int(parts[3] or 0); minute = int(parts[4] or 0); second = int(parts[5] or 0)
        zone = parts[6]
        tz = None
        note = "Timezone not present; none was inferred."
        if zone == "Z":
            tz = timezone.utc; note = "UTC timezone explicitly present."
        elif zone:
            sign = 1 if zone[0] == "+" else -1
            digits = zone[1:].replace("'", "")
            tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4])))
            note = f"Original timezone offset preserved: {zone}."
        try:
            return datetime(year, month, day, hour, minute, second, tzinfo=tz).isoformat(), note
        except ValueError:
            return text, "Timestamp has an invalid date component."
    iso_candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso_candidate)
        note = "UTC timezone explicitly present." if text.endswith("Z") else (
            f"Original timezone offset preserved: {parsed.strftime('%z')}." if parsed.tzinfo else "Timezone not present; none was inferred."
        )
        return parsed.isoformat(), note
    except ValueError:
        for pattern in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(text, pattern).isoformat(), "Timezone not present; none was inferred."
            except ValueError:
                pass
    return text, "Timestamp could not be normalized; the raw value is preserved."


def _rational(value: Any) -> float:
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        return float(value.numerator) / float(value.denominator)
    return float(Decimal(str(value)))


def gps_dms_to_decimal(value: Any, reference: Any) -> tuple[float | None, str]:
    try:
        if not isinstance(value, (list, tuple)) or len(value) != 3:
            return None, "GPS coordinate is incomplete; degrees, minutes, and seconds are required."
        degrees, minutes, seconds = (_rational(item) for item in value)
        if degrees < 0 or not (0 <= minutes < 60) or not (0 <= seconds < 60):
            return None, "GPS coordinate contains an invalid degrees, minutes, or seconds value."
        ref = compact_text(reference).upper()
        if ref not in {"N", "S", "E", "W"}:
            return None, "GPS direction reference is missing or invalid."
        decimal = degrees + minutes / 60 + seconds / 3600
        maximum = 90 if ref in {"N", "S"} else 180
        if decimal > maximum:
            return None, f"GPS coordinate is outside the valid {maximum}-degree range."
        if ref in {"S", "W"}:
            decimal = -decimal
        return round(decimal, 7), "Coordinate converted from DMS while preserving its direction reference."
    except (TypeError, ValueError, InvalidOperation, ZeroDivisionError):
        return None, "GPS coordinate could not be decoded safely."
