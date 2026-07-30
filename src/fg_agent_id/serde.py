"""Minimal validation/serialization helpers for the wire dataclasses.

These give the frozen dataclasses a pydantic-compatible surface
(``model_dump`` / ``model_validate`` / ``model_copy``) without a pydantic
dependency, so embedding protocols can keep their existing call sites.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def require_str(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    return value


def require_datetime(name: str, value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware (naive datetimes are ambiguous)")
    return value


def normalize_timestamp(name: str, value: Any) -> datetime:
    """Coerce to the precision the wire format carries: UTC, milliseconds.

    Signed payloads render timestamps with :func:`canonical_timestamp`, which
    truncates to milliseconds. Normalizing at construction keeps the in-memory
    value byte-identical to what was (or will be) signed, so a round-trip
    through JSON never changes a signature's meaning.
    """
    dt = require_datetime(name, value)
    dt = dt.astimezone(UTC)
    return dt.replace(microsecond=(dt.microsecond // 1000) * 1000)


def canonical_timestamp(value: datetime) -> str:
    """RFC 3339 UTC with exactly three fractional digits and a ``Z`` suffix.

    Pinned precisely because these strings land inside signed payloads:
    Python's ``isoformat()`` varies its output (offset spelling, presence and
    width of fractional seconds), so two implementations signing "the same"
    instant would produce different bytes. One spelling, always.
    """
    dt = value.astimezone(UTC)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{dt.microsecond // 1000:03d}Z"


def parse_datetime(name: str, value: Any) -> datetime:
    """Accept a datetime or an RFC 3339 / ISO-8601 string (``Z`` suffix ok)."""
    if isinstance(value, datetime):
        return normalize_timestamp(name, value)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"{name} is not a valid ISO-8601 datetime: {value!r}") from exc
        if parsed.tzinfo is None:
            raise ValueError(f"{name} must carry a timezone offset: {value!r}")
        return normalize_timestamp(name, parsed)
    raise TypeError(f"{name} must be a datetime or ISO-8601 string")


def require_mapping(name: str, value: Any) -> dict:
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be a mapping, got {type(value).__name__}")
    return value
