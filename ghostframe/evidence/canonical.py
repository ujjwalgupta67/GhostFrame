from __future__ import annotations

import json
import math
import unicodedata
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by the evidence contract."""


def normalize_utc_timestamp(value: datetime) -> str:
    """Return one fixed-width UTC representation for an aware timestamp."""

    if not isinstance(value, datetime):
        raise CanonicalizationError("Evidence timestamps must be datetime values.")
    if value.tzinfo is None or value.utcoffset() is None:
        raise CanonicalizationError("Evidence timestamps must include a timezone.")
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize_string(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _normalize(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _normalize_string(value)
    if isinstance(value, int) and not isinstance(value, bool):
        if value < -(2**63) or value > 2**63 - 1:
            raise CanonicalizationError(f"Integer at {path} is outside the signed 64-bit evidence range.")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(f"Non-finite number at {path} is not allowed.")
        raise CanonicalizationError(f"Floating-point value at {path} is not supported; normalize it explicitly.")
    if isinstance(value, datetime):
        return normalize_utc_timestamp(value)
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"Object key at {path} must be a string.")
            normalized_key = _normalize_string(key)
            if normalized_key in normalized:
                raise CanonicalizationError(f"Unicode-normalized duplicate object key at {path}: {normalized_key!r}")
            normalized[normalized_key] = _normalize(item, f"{path}.{normalized_key}")
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, (list, tuple)):
        return [_normalize(item, f"{path}[{index}]") for index, item in enumerate(value)]
    raise CanonicalizationError(f"Unsupported evidence value at {path}: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize the supported evidence subset as deterministic UTF-8 JSON.

    Contract ``ghostframe-canonical-json/1`` supports null, booleans, integers,
    NFC-normalized strings, timezone-aware datetimes, string-keyed mappings,
    and ordered lists/tuples. Floats and all implicit object conversions are
    rejected. List ordering is preserved; projection adapters must sort lists
    whose domain semantics are set-like.
    """

    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
