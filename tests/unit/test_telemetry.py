"""Contract and determinism tests for synthetic telemetry."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from telemetry.generators import generate_baseline
from telemetry.models import EventSource, NormalizedEvent
from telemetry.normalization import normalize_synthetic_record


def test_baseline_covers_every_source_and_is_deterministic() -> None:
    first = generate_baseline(events_per_source=2)
    second = generate_baseline(events_per_source=2)

    assert first == second
    assert len(first) == len(EventSource) * 2
    assert {event.event_source for event in first} == set(EventSource)
    assert all(event.raw_event_ref.startswith("synthetic://") for event in first)
    assert all(event.correlation_id.startswith("corr-") for event in first)
    assert all(event.host and event.user for event in first)


def test_normalizer_accepts_complete_synthetic_record() -> None:
    event = normalize_synthetic_record(
        {
            "event_id": "evt-example-0001",
            "timestamp": "2026-01-15T09:00:00Z",
            "event_source": "SigninLogs",
            "event_type": "interactive_sign_in",
            "host": "ws-104.sentinelforge.test",
            "user": "maya.chen@example.test",
            "source_ip": "198.51.100.12",
            "destination_ip": "203.0.113.10",
            "action": "authenticate",
            "result": "success",
            "correlation_id": "corr-example-0001",
            "raw_event_ref": "synthetic://test/signin-0001",
            "normalized": {"country": "US"},
        }
    )

    assert event.timestamp == datetime(2026, 1, 15, 9, 0, tzinfo=UTC)
    assert event.event_source is EventSource.SIGNIN_LOGS


def test_public_non_documentation_address_is_rejected() -> None:
    with pytest.raises(ValidationError, match="documentation, private, or loopback"):
        NormalizedEvent(
            event_id="evt-example-0002",
            timestamp=datetime.now(UTC),
            event_source=EventSource.SIGNIN_LOGS,
            event_type="interactive_sign_in",
            host="ws-104.sentinelforge.test",
            user="maya.chen@example.test",
            source_ip=".".join(["8"] * 4),
            destination_ip="203.0.113.10",
            action="authenticate",
            result="success",
            correlation_id="corr-example-0002",
            raw_event_ref="synthetic://test/signin-0002",
        )


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        NormalizedEvent(
            event_id="evt-example-0003",
            timestamp=datetime(2026, 1, 15, 9, 0),  # noqa: DTZ001 - rejection fixture
            event_source=EventSource.SIGNIN_LOGS,
            event_type="interactive_sign_in",
            host="ws-104.sentinelforge.test",
            user="maya.chen@example.test",
            action="authenticate",
            result="success",
            correlation_id="corr-example-0003",
            raw_event_ref="synthetic://test/signin-0003",
        )
