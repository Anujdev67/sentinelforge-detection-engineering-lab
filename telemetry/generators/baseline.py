"""Deterministic benign telemetry spanning every supported source family."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

from telemetry.models import EventSource, NormalizedEvent

BASE_TIME = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)

_SOURCE_PROFILES: dict[EventSource, dict[str, Any]] = {
    EventSource.SIGNIN_LOGS: {
        "event_type": "interactive_sign_in",
        "action": "authenticate",
        "normalized": {
            "application": "SentinelForge Portal",
            "country": "US",
            "mfa_result": "satisfied",
        },
    },
    EventSource.AUDIT_LOGS: {
        "event_type": "directory_audit",
        "action": "update_group_membership",
        "normalized": {
            "operation": "Add member to training group",
            "target": "soc-readers@example.test",
        },
    },
    EventSource.SECURITY_EVENT: {
        "event_type": "windows_security",
        "action": "logon",
        "normalized": {"event_id": 4624, "logon_type": 2, "authentication_package": "Kerberos"},
    },
    EventSource.DEVICE_PROCESS_EVENTS: {
        "event_type": "process_created",
        "action": "process_start",
        "normalized": {
            "file_name": "notepad.exe",
            "command_line": "notepad.exe training-notes.txt",
            "parent_process": "explorer.exe",
        },
    },
    EventSource.DEVICE_NETWORK_EVENTS: {
        "event_type": "network_connection",
        "action": "connect",
        "normalized": {
            "protocol": "tcp",
            "destination_port": 443,
            "initiating_process": "msedge.exe",
            "bytes_sent": 1820,
        },
    },
    EventSource.DEVICE_LOGON_EVENTS: {
        "event_type": "device_logon",
        "action": "logon",
        "normalized": {"logon_type": "Interactive", "is_local_admin": False},
    },
    EventSource.COMMON_SECURITY_LOG: {
        "event_type": "firewall_traffic",
        "action": "allow",
        "normalized": {
            "device_vendor": "Fictional Firewall",
            "destination_port": 443,
            "protocol": "tcp",
            "bytes_sent": 2400,
        },
    },
    EventSource.OFFICE_ACTIVITY: {
        "event_type": "office_operation",
        "action": "file_access",
        "normalized": {
            "workload": "SharePoint",
            "operation": "FileAccessed",
            "object": "synthetic://documents/runbook",
        },
    },
    EventSource.AZURE_ACTIVITY: {
        "event_type": "azure_control_plane",
        "action": "read_resource",
        "normalized": {
            "operation": "Microsoft.Resources/subscriptions/resourceGroups/read",
            "resource_group": "rg-sentinelforge-demo",
        },
    },
    EventSource.AWS_CLOUDTRAIL: {
        "event_type": "aws_api_call",
        "action": "ListBuckets",
        "normalized": {
            "event_name": "ListBuckets",
            "event_source": "s3.amazonaws.com",
            "aws_region": "us-east-1",
        },
    },
    EventSource.GUARDDUTY: {
        "event_type": "guardduty_finding",
        "action": "observe",
        "normalized": {
            "finding_type": "Recon:EC2/PortProbeUnprotectedPort",
            "finding_severity": 1.2,
            "archived": True,
        },
    },
}


def generate_baseline(
    *,
    events_per_source: int = 3,
    seed: int = 20260115,
    start: datetime = BASE_TIME,
) -> list[NormalizedEvent]:
    """Return repeatable benign events without contacting any external service."""

    if events_per_source < 1:
        raise ValueError("events_per_source must be at least one")
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic fixtures, not security
    users = ["maya.chen@example.test", "noah.okafor@example.test", "lina.berg@example.test"]
    hosts = ["ws-104.sentinelforge.test", "ws-217.sentinelforge.test", "srv-031.sentinelforge.test"]
    events: list[NormalizedEvent] = []
    sequence = 0

    for source_index, source in enumerate(EventSource):
        profile = _SOURCE_PROFILES[source]
        for item_index in range(events_per_source):
            sequence += 1
            source_ip_octet = 10 + ((source_index * events_per_source + item_index) % 200)
            destination_ip_octet = 20 + ((source_index + item_index) % 200)
            event = NormalizedEvent(
                event_id=f"evt-baseline-{sequence:04d}",
                timestamp=start + timedelta(minutes=sequence * 3 + rng.randint(0, 1)),
                event_source=source,
                event_type=profile["event_type"],
                host=hosts[(source_index + item_index) % len(hosts)],
                user=users[(source_index + item_index) % len(users)],
                source_ip=f"198.51.100.{source_ip_octet}",
                destination_ip=f"203.0.113.{destination_ip_octet}",
                action=profile["action"],
                result="success",
                correlation_id=f"corr-baseline-{source.value.lower()}-{item_index:02d}",
                raw_event_ref=f"synthetic://baseline/{source.value.lower()}-{item_index:02d}",
                normalized=dict(profile["normalized"]),
            )
            events.append(event)

    return sorted(events, key=lambda event: event.timestamp)
