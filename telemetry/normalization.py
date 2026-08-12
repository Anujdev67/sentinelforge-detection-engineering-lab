"""Source adapters for turning synthetic source records into canonical events."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from telemetry.models import EventSource, NormalizedEvent


def normalize_synthetic_record(record: dict[str, Any]) -> NormalizedEvent:
    """Normalize a trusted synthetic record and reject missing canonical fields."""

    source_value = record.get("event_source")
    if not isinstance(source_value, str):
        raise ValueError("event_source is required")
    source = EventSource(source_value)

    timestamp_value = record.get("timestamp")
    if isinstance(timestamp_value, str):
        timestamp: datetime | str = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
    elif isinstance(timestamp_value, datetime):
        timestamp = timestamp_value
    else:
        raise ValueError("timestamp must be an ISO 8601 string or datetime")

    normalized = dict(record.get("normalized", {}))
    return NormalizedEvent(
        event_id=str(record["event_id"]),
        timestamp=timestamp,
        event_source=source,
        event_type=str(record["event_type"]),
        host=str(record["host"]),
        user=str(record["user"]),
        source_ip=str(record["source_ip"]) if record.get("source_ip") else None,
        destination_ip=(str(record["destination_ip"]) if record.get("destination_ip") else None),
        action=str(record["action"]),
        result=str(record["result"]),
        correlation_id=str(record["correlation_id"]),
        raw_event_ref=str(record["raw_event_ref"]),
        normalized=normalized,
    )
