"""Purpose-built local behavioral counterparts for SentinelForge KQL rules.

The functions in this module operate on normalized synthetic events. They do
not parse KQL and they intentionally implement only the behavior documented in
each detection pack.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Callable, Hashable, Iterable
from datetime import timedelta
from hashlib import sha256
from itertools import pairwise
from statistics import mean, pstdev
from typing import Any

from telemetry.models import Alert, DetectionMetadata, EventSource, NormalizedEvent

Evaluator = Callable[[list[NormalizedEvent], DetectionMetadata], list[Alert]]


def _digest(value: str) -> str:
    return sha256(value.encode(), usedforsecurity=False).hexdigest()[:12]


def _grouped[Key: Hashable](
    events: Iterable[NormalizedEvent], key: Callable[[NormalizedEvent], Key]
) -> dict[Key, list[NormalizedEvent]]:
    groups: dict[Key, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        groups[key(event)].append(event)
    return {
        group_key: sorted(items, key=lambda item: item.timestamp)
        for group_key, items in groups.items()
    }


def _qualifying_window(
    events: list[NormalizedEvent], minutes: int, predicate: Callable[[list[NormalizedEvent]], bool]
) -> list[NormalizedEvent] | None:
    for start_index, first in enumerate(events):
        end = first.timestamp + timedelta(minutes=minutes)
        window = [event for event in events[start_index:] if event.timestamp <= end]
        if predicate(window):
            return window
    return None


def _build_alert(
    metadata: DetectionMetadata,
    evidence: list[NormalizedEvent],
    entities: dict[str, list[str]],
    summary: str,
) -> Alert:
    ordered = sorted(evidence, key=lambda event: event.timestamp)
    correlation_id = ordered[0].correlation_id
    identity = (
        f"{metadata.rule_id}:{correlation_id}:{','.join(event.event_id for event in ordered)}"
    )
    last_observed = ordered[-1].timestamp
    return Alert(
        alert_id=f"alert-{metadata.rule_id.lower()}-{_digest(identity)}",
        rule_id=metadata.rule_id,
        title=metadata.title,
        severity=metadata.severity,
        detected_at=last_observed + timedelta(milliseconds=250),
        first_observed=ordered[0].timestamp,
        last_observed=last_observed,
        summary=summary,
        evidence_event_ids=[event.event_id for event in ordered],
        entities={name: sorted(set(values)) for name, values in entities.items()},
        mitre_attack=metadata.mitre_attack,
        correlation_id=correlation_id,
        detection_latency_ms=250,
    )


def password_spray(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    failures = [
        event
        for event in events
        if event.event_source is EventSource.SIGNIN_LOGS
        and event.event_type == "interactive_sign_in"
        and event.result == "failure"
        and event.source_ip
    ]
    alerts: list[Alert] = []
    for source_ip, items in _grouped(failures, lambda event: event.source_ip or "").items():
        window = _qualifying_window(
            items,
            metadata.time_window_minutes,
            lambda candidate: len({event.user for event in candidate}) >= metadata.threshold,
        )
        if window:
            alerts.append(
                _build_alert(
                    metadata,
                    window,
                    {"ip": [source_ip], "account": [event.user for event in window]},
                    (
                        "One source produced failed sign-ins across "
                        f"{len({event.user for event in window})} accounts."
                    ),
                )
            )
    return alerts


def failed_then_success(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    signins = [
        event
        for event in events
        if event.event_source is EventSource.SIGNIN_LOGS
        and event.event_type == "interactive_sign_in"
    ]
    alerts: list[Alert] = []
    for (user, source_ip), items in _grouped(
        signins, lambda event: (event.user, event.source_ip or "unknown")
    ).items():

        def qualifies(candidate: list[NormalizedEvent]) -> bool:
            success_indexes = [i for i, event in enumerate(candidate) if event.result == "success"]
            return any(
                sum(event.result == "failure" for event in candidate[:index]) >= metadata.threshold
                for index in success_indexes
            )

        window = _qualifying_window(items, metadata.time_window_minutes, qualifies)
        if window:
            final_success = next(event for event in reversed(window) if event.result == "success")
            evidence = [event for event in window if event.timestamp <= final_success.timestamp]
            alerts.append(
                _build_alert(
                    metadata,
                    evidence,
                    {"account": [user], "ip": [source_ip]},
                    f"{metadata.threshold} or more failures were followed by a successful sign-in.",
                )
            )
    return alerts


def _haversine_km(first: tuple[float, float], second: tuple[float, float]) -> float:
    lat1, lon1 = map(math.radians, first)
    lat2, lon2 = map(math.radians, second)
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    value = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    )
    return 6371.0 * 2 * math.asin(math.sqrt(value))


def impossible_travel(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    signins = [
        event
        for event in events
        if event.event_source is EventSource.SIGNIN_LOGS
        and event.result == "success"
        and isinstance(event.normalized.get("latitude"), (int, float))
        and isinstance(event.normalized.get("longitude"), (int, float))
    ]
    alerts: list[Alert] = []
    for user, items in _grouped(signins, lambda event: event.user).items():
        for first, second in pairwise(items):
            hours = (second.timestamp - first.timestamp).total_seconds() / 3600
            if hours <= 0 or hours > metadata.time_window_minutes / 60:
                continue
            first_geo = (float(first.normalized["latitude"]), float(first.normalized["longitude"]))
            second_geo = (
                float(second.normalized["latitude"]),
                float(second.normalized["longitude"]),
            )
            speed = _haversine_km(first_geo, second_geo) / hours
            if speed >= metadata.threshold:
                alerts.append(
                    _build_alert(
                        metadata,
                        [first, second],
                        {"account": [user], "ip": [first.source_ip or "", second.source_ip or ""]},
                        f"Successful sign-ins imply travel at approximately {speed:.0f} km/h.",
                    )
                )
                break
    return alerts


def mfa_fatigue(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    signins = [event for event in events if event.event_source is EventSource.SIGNIN_LOGS]
    alerts: list[Alert] = []
    for user, items in _grouped(signins, lambda event: event.user).items():

        def qualifies(candidate: list[NormalizedEvent]) -> bool:
            denied = sum(event.normalized.get("mfa_result") == "denied" for event in candidate)
            return denied >= metadata.threshold and any(
                event.normalized.get("mfa_result") == "approved" for event in candidate
            )

        window = _qualifying_window(items, metadata.time_window_minutes, qualifies)
        if window:
            alerts.append(
                _build_alert(
                    metadata,
                    window,
                    {"account": [user], "ip": [event.source_ip or "" for event in window]},
                    (
                        "Repeated MFA denials were followed by an approval in the same "
                        "activity window."
                    ),
                )
            )
    return alerts


def suspicious_powershell(
    events: list[NormalizedEvent], metadata: DetectionMetadata
) -> list[Alert]:
    indicators = (
        "-encodedcommand",
        " -enc ",
        "frombase64string",
        "invoke-webrequest",
        "-windowstyle hidden",
    )
    matches = [
        event
        for event in events
        if event.event_source is EventSource.DEVICE_PROCESS_EVENTS
        and str(event.normalized.get("file_name", "")).lower() in {"powershell.exe", "pwsh.exe"}
        and any(
            indicator in f" {str(event.normalized.get('command_line', '')).lower()} "
            for indicator in indicators
        )
    ]
    return [
        _build_alert(
            metadata,
            [event],
            {
                "account": [event.user],
                "host": [event.host],
                "process": [str(event.normalized["file_name"])],
            },
            "PowerShell was launched with encoded, download, or hidden-window indicators.",
        )
        for event in matches
    ]


def lsass_access(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    matches = [
        event
        for event in events
        if event.event_source is EventSource.DEVICE_PROCESS_EVENTS
        and str(event.normalized.get("target_process", "")).lower() == "lsass.exe"
        and str(event.normalized.get("access_type", "")).lower() in {"memory_read", "process_dump"}
        and not bool(event.normalized.get("approved_security_tool"))
    ]
    return [
        _build_alert(
            metadata,
            [event],
            {
                "account": [event.user],
                "host": [event.host],
                "process": [str(event.normalized.get("file_name", "unknown"))],
            },
            "An unapproved process requested memory-read or dump access to LSASS.",
        )
        for event in matches
    ]


def dcsync_activity(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    matches = [
        event
        for event in events
        if event.event_source is EventSource.SECURITY_EVENT
        and int(event.normalized.get("event_id", 0)) == 4662
        and "ds-replication-get-changes-all" in str(event.normalized.get("properties", "")).lower()
        and not bool(event.normalized.get("approved_directory_replication"))
    ]
    return [
        _build_alert(
            metadata,
            [event],
            {
                "account": [event.user],
                "host": [event.host],
                "domain": [str(event.normalized.get("domain", "sentinelforge.test"))],
            },
            (
                "Directory replication rights were exercised by an identity outside the "
                "synthetic allowlist."
            ),
        )
        for event in matches
    ]


def rdp_lateral_movement(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    rdp = [
        event
        for event in events
        if event.event_source is EventSource.DEVICE_LOGON_EVENTS
        and str(event.normalized.get("logon_type")) == "RemoteInteractive"
        and event.result == "success"
    ]
    alerts: list[Alert] = []
    for (user, source_ip), items in _grouped(
        rdp, lambda e: (e.user, e.source_ip or "unknown")
    ).items():
        window = _qualifying_window(
            items,
            metadata.time_window_minutes,
            lambda candidate: len({event.host for event in candidate}) >= metadata.threshold,
        )
        if window:
            alerts.append(
                _build_alert(
                    metadata,
                    window,
                    {
                        "account": [user],
                        "ip": [source_ip],
                        "host": [event.host for event in window],
                    },
                    f"One identity opened RDP sessions to {len({e.host for e in window})} hosts.",
                )
            )
    return alerts


def unauthorized_remote_tool(
    events: list[NormalizedEvent], metadata: DetectionMetadata
) -> list[Alert]:
    tool_names = {"anydesk.exe", "teamviewer.exe", "teamviewer_service.exe"}
    matches = [
        event
        for event in events
        if event.event_source is EventSource.DEVICE_PROCESS_EVENTS
        and str(event.normalized.get("file_name", "")).lower() in tool_names
        and not bool(event.normalized.get("approved_remote_support"))
    ]
    return [
        _build_alert(
            metadata,
            [event],
            {
                "account": [event.user],
                "host": [event.host],
                "process": [str(event.normalized["file_name"])],
            },
            "A remote-access tool executed without a matching synthetic approval record.",
        )
        for event in matches
    ]


def dns_tunneling(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    dns = [
        event
        for event in events
        if event.event_source is EventSource.DEVICE_NETWORK_EVENTS
        and str(event.normalized.get("protocol", "")).lower() == "dns"
        and len(str(event.normalized.get("query", "")).split(".")[0]) >= 45
    ]
    alerts: list[Alert] = []
    for host, items in _grouped(dns, lambda event: event.host).items():
        window = _qualifying_window(
            items,
            metadata.time_window_minutes,
            lambda candidate: (
                len({event.normalized.get("query") for event in candidate}) >= metadata.threshold
            ),
        )
        if window:
            alerts.append(
                _build_alert(
                    metadata,
                    window,
                    {
                        "host": [host],
                        "domain": [str(event.normalized["query"]) for event in window],
                    },
                    (
                        "Multiple unique DNS queries contained unusually long "
                        "high-entropy-style labels."
                    ),
                )
            )
    return alerts


def anomalous_aws_iam(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    sensitive_actions = {
        "CreateAccessKey",
        "AttachUserPolicy",
        "PutUserPolicy",
        "CreateLoginProfile",
    }
    matches = [
        event
        for event in events
        if event.event_source is EventSource.AWS_CLOUDTRAIL
        and str(event.normalized.get("event_name")) in sensitive_actions
        and not bool(event.normalized.get("mfa_authenticated"))
        and bool(event.normalized.get("unfamiliar_source"))
    ]
    return [
        _build_alert(
            metadata,
            [event],
            {
                "account": [event.user],
                "ip": [event.source_ip or ""],
                "cloud_resource": [str(event.normalized.get("target", "iam"))],
            },
            "A sensitive AWS IAM API operation came from an unfamiliar source without MFA context.",
        )
        for event in matches
    ]


def outbound_beaconing(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    network = [
        event
        for event in events
        if event.event_source is EventSource.COMMON_SECURITY_LOG
        and event.action == "allow"
        and event.source_ip
        and event.destination_ip
    ]
    alerts: list[Alert] = []
    for (source_ip, destination_ip, port), items in _grouped(
        network,
        lambda event: (
            event.source_ip or "",
            event.destination_ip or "",
            int(event.normalized.get("destination_port", 0)),
        ),
    ).items():
        if len(items) < metadata.threshold:
            continue
        intervals = [
            (current.timestamp - previous.timestamp).total_seconds()
            for previous, current in pairwise(items)
        ]
        if intervals and 30 <= mean(intervals) <= 120 and pstdev(intervals) <= 5:
            alerts.append(
                _build_alert(
                    metadata,
                    items,
                    {
                        "ip": [source_ip, destination_ip],
                        "host": [items[0].host],
                        "port": [str(port)],
                    },
                    (
                        f"{len(items)} outbound sessions repeated every "
                        f"{mean(intervals):.0f}s with low jitter."
                    ),
                )
            )
    return alerts


EVALUATORS: dict[str, Evaluator] = {
    "password_spray": password_spray,
    "failed_then_success": failed_then_success,
    "impossible_travel": impossible_travel,
    "mfa_fatigue": mfa_fatigue,
    "suspicious_powershell": suspicious_powershell,
    "lsass_access": lsass_access,
    "dcsync_activity": dcsync_activity,
    "rdp_lateral_movement": rdp_lateral_movement,
    "unauthorized_remote_tool": unauthorized_remote_tool,
    "dns_tunneling": dns_tunneling,
    "anomalous_aws_iam": anomalous_aws_iam,
    "outbound_beaconing": outbound_beaconing,
}


def evaluate_rule(events: list[NormalizedEvent], metadata: DetectionMetadata) -> list[Alert]:
    """Evaluate a normalized batch with the rule's named local counterpart."""

    try:
        evaluator = EVALUATORS[metadata.evaluator]
    except KeyError as exc:
        raise ValueError(f"evaluator is not registered: {metadata.evaluator}") from exc
    return evaluator(events, metadata)


def alert_regression_view(alert: Alert) -> dict[str, Any]:
    """Return stable fields used by committed detection snapshots."""

    return {
        "rule_id": alert.rule_id,
        "alert_count": 1,
        "evidence_event_ids": alert.evidence_event_ids,
        "entities": alert.entities,
    }
