"""Deterministic positive and negative security scenarios for every rule."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from telemetry.models import EventSource, NormalizedEvent

SCENARIO_TIME = datetime(2026, 2, 3, 14, 0, tzinfo=UTC)


def _event(
    rule_number: int,
    fixture: str,
    sequence: int,
    *,
    source: EventSource,
    event_type: str,
    action: str,
    result: str,
    minute: int = 0,
    second: int = 0,
    host: str = "ws-417.sentinelforge.test",
    user: str = "alex.morgan@example.test",
    source_ip: str | None = "198.51.100.77",
    destination_ip: str | None = "203.0.113.44",
    normalized: dict[str, Any] | None = None,
) -> NormalizedEvent:
    tag = f"sf{rule_number:03d}-{fixture}"
    return NormalizedEvent(
        event_id=f"evt-{tag}-{sequence:02d}",
        timestamp=SCENARIO_TIME + timedelta(minutes=minute, seconds=second),
        event_source=source,
        event_type=event_type,
        host=host,
        user=user,
        source_ip=source_ip,
        destination_ip=destination_ip,
        action=action,
        result=result,
        correlation_id=f"corr-{tag}",
        raw_event_ref=f"synthetic://fixtures/{tag}-{sequence:02d}",
        normalized=normalized or {},
    )


def _password_spray(fixture: str, accounts: int) -> list[NormalizedEvent]:
    return [
        _event(
            1,
            fixture,
            index + 1,
            source=EventSource.SIGNIN_LOGS,
            event_type="interactive_sign_in",
            action="authenticate",
            result="failure",
            minute=index,
            user=f"training.user{index + 1}@example.test",
            normalized={"result_code": "50126", "country": "GB", "application": "Lab Portal"},
        )
        for index in range(accounts)
    ]


def _failed_then_success(fixture: str, failure_count: int) -> list[NormalizedEvent]:
    events = [
        _event(
            2,
            fixture,
            index + 1,
            source=EventSource.SIGNIN_LOGS,
            event_type="interactive_sign_in",
            action="authenticate",
            result="failure",
            minute=index,
            normalized={"result_code": "50126", "application": "Mail Lab"},
        )
        for index in range(failure_count)
    ]
    events.append(
        _event(
            2,
            fixture,
            failure_count + 1,
            source=EventSource.SIGNIN_LOGS,
            event_type="interactive_sign_in",
            action="authenticate",
            result="success",
            minute=failure_count,
            normalized={"result_code": "0", "application": "Mail Lab"},
        )
    )
    return events


def _impossible_travel(
    fixture: str, second_coordinates: tuple[float, float]
) -> list[NormalizedEvent]:
    locations = [(47.6062, -122.3321, "US"), (*second_coordinates, "GB")]
    return [
        _event(
            3,
            fixture,
            index + 1,
            source=EventSource.SIGNIN_LOGS,
            event_type="interactive_sign_in",
            action="authenticate",
            result="success",
            minute=index * 60,
            source_ip=f"198.51.100.{80 + index}",
            normalized={"latitude": latitude, "longitude": longitude, "country": country},
        )
        for index, (latitude, longitude, country) in enumerate(locations)
    ]


def _mfa_fatigue(fixture: str, denied_count: int) -> list[NormalizedEvent]:
    events = [
        _event(
            4,
            fixture,
            index + 1,
            source=EventSource.SIGNIN_LOGS,
            event_type="mfa_challenge",
            action="mfa_verify",
            result="failure",
            minute=index * 2,
            normalized={"mfa_result": "denied", "application": "Finance Training"},
        )
        for index in range(denied_count)
    ]
    events.append(
        _event(
            4,
            fixture,
            denied_count + 1,
            source=EventSource.SIGNIN_LOGS,
            event_type="mfa_challenge",
            action="mfa_verify",
            result="success",
            minute=denied_count * 2,
            normalized={"mfa_result": "approved", "application": "Finance Training"},
        )
    )
    return events


def _rdp(fixture: str, host_count: int) -> list[NormalizedEvent]:
    return [
        _event(
            8,
            fixture,
            index + 1,
            source=EventSource.DEVICE_LOGON_EVENTS,
            event_type="device_logon",
            action="logon",
            result="success",
            minute=index * 5,
            host=f"srv-{601 + index}.sentinelforge.test",
            normalized={"logon_type": "RemoteInteractive", "protocol": "RDP"},
        )
        for index in range(host_count)
    ]


def _dns(fixture: str, count: int, *, long_labels: bool) -> list[NormalizedEvent]:
    label = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4"
    return [
        _event(
            10,
            fixture,
            index + 1,
            source=EventSource.DEVICE_NETWORK_EVENTS,
            event_type="dns_query",
            action="resolve",
            result="success",
            minute=index,
            destination_ip="203.0.113.53",
            normalized={
                "protocol": "dns",
                "query": f"{label}{index}.telemetry.example.test"
                if long_labels
                else "api.example.test",
                "initiating_process": "training-agent.exe",
            },
        )
        for index in range(count)
    ]


def _beacon(fixture: str, intervals: list[int]) -> list[NormalizedEvent]:
    elapsed = 0
    events: list[NormalizedEvent] = []
    for index, interval in enumerate([0, *intervals]):
        elapsed += interval
        events.append(
            _event(
                12,
                fixture,
                index + 1,
                source=EventSource.COMMON_SECURITY_LOG,
                event_type="firewall_traffic",
                action="allow",
                result="success",
                second=elapsed,
                host="ws-712.sentinelforge.test",
                source_ip="198.51.100.112",
                destination_ip="203.0.113.212",
                normalized={
                    "device_vendor": "Palo Alto Networks",
                    "destination_port": 443,
                    "application": "ssl",
                    "bytes_sent": 612,
                },
            )
        )
    return events


def scenario_fixtures() -> dict[str, tuple[list[NormalizedEvent], list[NormalizedEvent]]]:
    """Return positive and negative fixture batches keyed by stable rule ID."""

    return {
        "SF-001": (_password_spray("positive", 5), _password_spray("negative", 4)),
        "SF-002": (_failed_then_success("positive", 4), _failed_then_success("negative", 3)),
        "SF-003": (
            _impossible_travel("positive", (51.5074, -0.1278)),
            _impossible_travel("negative", (45.5152, -122.6784)),
        ),
        "SF-004": (_mfa_fatigue("positive", 5), _mfa_fatigue("negative", 4)),
        "SF-005": (
            [
                _event(
                    5,
                    "positive",
                    1,
                    source=EventSource.DEVICE_PROCESS_EVENTS,
                    event_type="process_created",
                    action="process_start",
                    result="success",
                    normalized={
                        "file_name": "powershell.exe",
                        "command_line": "powershell.exe -EncodedCommand SYNTHETIC-LAB-CONTENT",
                        "parent_process": "training-runner.exe",
                    },
                )
            ],
            [
                _event(
                    5,
                    "negative",
                    1,
                    source=EventSource.DEVICE_PROCESS_EVENTS,
                    event_type="process_created",
                    action="process_start",
                    result="success",
                    normalized={
                        "file_name": "powershell.exe",
                        "command_line": "powershell.exe -File approved-inventory.ps1",
                        "parent_process": "management-agent.exe",
                    },
                )
            ],
        ),
        "SF-006": (
            [
                _event(
                    6,
                    "positive",
                    1,
                    source=EventSource.DEVICE_PROCESS_EVENTS,
                    event_type="process_access",
                    action="open_process",
                    result="success",
                    normalized={
                        "file_name": "unapproved-diagnostic.exe",
                        "target_process": "lsass.exe",
                        "access_type": "memory_read",
                        "approved_security_tool": False,
                    },
                )
            ],
            [
                _event(
                    6,
                    "negative",
                    1,
                    source=EventSource.DEVICE_PROCESS_EVENTS,
                    event_type="process_access",
                    action="open_process",
                    result="success",
                    normalized={
                        "file_name": "approved-edr-sensor.exe",
                        "target_process": "lsass.exe",
                        "access_type": "memory_read",
                        "approved_security_tool": True,
                    },
                )
            ],
        ),
        "SF-007": (
            [
                _event(
                    7,
                    "positive",
                    1,
                    source=EventSource.SECURITY_EVENT,
                    event_type="directory_service_access",
                    action="replicate_directory",
                    result="success",
                    host="dc-01.sentinelforge.test",
                    normalized={
                        "event_id": 4662,
                        "properties": "DS-Replication-Get-Changes-All",
                        "domain": "sentinelforge.test",
                        "approved_directory_replication": False,
                    },
                )
            ],
            [
                _event(
                    7,
                    "negative",
                    1,
                    source=EventSource.SECURITY_EVENT,
                    event_type="directory_service_access",
                    action="replicate_directory",
                    result="success",
                    host="dc-01.sentinelforge.test",
                    user="sync-service@example.test",
                    normalized={
                        "event_id": 4662,
                        "properties": "DS-Replication-Get-Changes-All",
                        "domain": "sentinelforge.test",
                        "approved_directory_replication": True,
                    },
                )
            ],
        ),
        "SF-008": (_rdp("positive", 3), _rdp("negative", 2)),
        "SF-009": (
            [
                _event(
                    9,
                    "positive",
                    1,
                    source=EventSource.DEVICE_PROCESS_EVENTS,
                    event_type="process_created",
                    action="process_start",
                    result="success",
                    normalized={"file_name": "AnyDesk.exe", "approved_remote_support": False},
                )
            ],
            [
                _event(
                    9,
                    "negative",
                    1,
                    source=EventSource.DEVICE_PROCESS_EVENTS,
                    event_type="process_created",
                    action="process_start",
                    result="success",
                    normalized={"file_name": "AnyDesk.exe", "approved_remote_support": True},
                )
            ],
        ),
        "SF-010": (_dns("positive", 4, long_labels=True), _dns("negative", 4, long_labels=False)),
        "SF-011": (
            [
                _event(
                    11,
                    "positive",
                    1,
                    source=EventSource.AWS_CLOUDTRAIL,
                    event_type="aws_api_call",
                    action="CreateAccessKey",
                    result="success",
                    normalized={
                        "event_name": "CreateAccessKey",
                        "mfa_authenticated": False,
                        "unfamiliar_source": True,
                        "target": "training-user",
                    },
                )
            ],
            [
                _event(
                    11,
                    "negative",
                    1,
                    source=EventSource.AWS_CLOUDTRAIL,
                    event_type="aws_api_call",
                    action="CreateAccessKey",
                    result="success",
                    normalized={
                        "event_name": "CreateAccessKey",
                        "mfa_authenticated": True,
                        "unfamiliar_source": False,
                        "target": "training-user",
                    },
                )
            ],
        ),
        "SF-012": (
            _beacon("positive", [60, 60, 61, 59, 60]),
            _beacon("negative", [20, 180, 45, 200, 15]),
        ),
    }


def generate_attack_scenarios(rule_ids: set[str] | None = None) -> list[NormalizedEvent]:
    """Return positive fixtures used by the local demo runner."""

    selected = rule_ids or set(scenario_fixtures())
    return sorted(
        [
            event
            for rule_id, (positive, _) in scenario_fixtures().items()
            if rule_id in selected
            for event in positive
        ],
        key=lambda event: event.timestamp,
    )
