"""Typed contracts shared by ingestion, detections, and the dashboard."""

from __future__ import annotations

from datetime import UTC, date, datetime
from enum import StrEnum
from ipaddress import IPv4Address, ip_address, ip_network
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EventSource(StrEnum):
    """Synthetic source families represented by the lab."""

    SIGNIN_LOGS = "SigninLogs"
    AUDIT_LOGS = "AuditLogs"
    SECURITY_EVENT = "SecurityEvent"
    DEVICE_PROCESS_EVENTS = "DeviceProcessEvents"
    DEVICE_NETWORK_EVENTS = "DeviceNetworkEvents"
    DEVICE_LOGON_EVENTS = "DeviceLogonEvents"
    COMMON_SECURITY_LOG = "CommonSecurityLog"
    OFFICE_ACTIVITY = "OfficeActivity"
    AZURE_ACTIVITY = "AzureActivity"
    AWS_CLOUDTRAIL = "AWSCloudTrail"
    GUARDDUTY = "GuardDuty"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(StrEnum):
    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"


class NormalizedEvent(BaseModel):
    """Canonical event used by intentionally narrow local evaluators."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(pattern=r"^evt-[a-z0-9-]{8,64}$")
    timestamp: datetime
    event_source: EventSource
    event_type: str = Field(min_length=2, max_length=100)
    host: str = Field(min_length=2, max_length=255)
    user: str = Field(min_length=2, max_length=255)
    source_ip: str | None = None
    destination_ip: str | None = None
    action: str = Field(min_length=2, max_length=100)
    result: str = Field(min_length=2, max_length=100)
    correlation_id: str = Field(pattern=r"^corr-[a-z0-9-]{6,64}$")
    raw_event_ref: str = Field(pattern=r"^synthetic://[a-z0-9/_-]+$")
    normalized: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(UTC)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def only_safe_ip_ranges(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parsed = ip_address(value)
        documentation_v4 = isinstance(parsed, IPv4Address) and any(
            parsed in ip_network(network)
            for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        )
        documentation_v6 = not isinstance(parsed, IPv4Address) and parsed in ip_network(
            "2001:db8::/32"
        )
        if not (documentation_v4 or documentation_v6 or parsed.is_private or parsed.is_loopback):
            raise ValueError("only documentation, private, or loopback IP ranges are allowed")
        return str(parsed)


class MitreMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tactic: str = Field(pattern=r"^TA\d{4}$")
    tactic_name: str = Field(min_length=3)
    technique: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    technique_name: str = Field(min_length=3)


class ChangelogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    date: date
    changes: str = Field(min_length=8)


class DetectionMetadata(BaseModel):
    """Contract for a versioned detection pack."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(pattern=r"^SF-\d{3}$")
    title: str = Field(min_length=8, max_length=140)
    description: str = Field(min_length=30)
    severity: Severity
    status: RuleStatus
    required_data_sources: list[EventSource] = Field(min_length=1)
    kql_file: str = Field(pattern=r"^[a-z0-9_-]+\.kql$")
    sigma_file: str | None = Field(default=None, pattern=r"^[a-z0-9_-]+\.yml$")
    evaluator: str = Field(pattern=r"^[a-z][a-z0-9_]+$")
    mitre_attack: list[MitreMapping] = Field(min_length=1)
    entity_mappings: dict[str, str] = Field(min_length=1)
    known_false_positives: list[str] = Field(min_length=1)
    investigation_steps: list[str] = Field(min_length=2)
    containment_recommendations: list[str] = Field(min_length=1)
    threshold: int = Field(ge=1)
    time_window_minutes: int = Field(ge=1, le=10_080)
    tuning_required: bool = False
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    changelog: list[ChangelogEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def latest_changelog_matches_version(self) -> DetectionMetadata:
        if self.changelog[0].version != self.version:
            raise ValueError("first changelog entry must match current version")
        return self


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(pattern=r"^alert-[a-z0-9-]{8,64}$")
    rule_id: str = Field(pattern=r"^SF-\d{3}$")
    title: str
    severity: Severity
    detected_at: datetime
    first_observed: datetime
    last_observed: datetime
    summary: str
    evidence_event_ids: list[str] = Field(min_length=1)
    entities: dict[str, list[str]]
    mitre_attack: list[MitreMapping]
    correlation_id: str
    detection_latency_ms: int = Field(ge=0)


class IncidentStatus(StrEnum):
    NEW = "new"
    ACTIVE = "active"
    PENDING_APPROVAL = "pending_approval"
    CONTAINED_SIMULATED = "contained_simulated"
    CLOSED = "closed"


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(pattern=r"^inc-[a-z0-9-]{8,64}$")
    title: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.NEW
    executive_summary: str
    alert_ids: list[str] = Field(min_length=1)
    entities: dict[str, list[str]]
    first_observed: datetime
    last_observed: datetime
    assigned_to: str | None = None
    created_at: datetime


class AuditRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(pattern=r"^audit-[a-z0-9-]{8,64}$")
    incident_id: str
    playbook_id: str
    action: str
    actor: str
    outcome: str
    simulated: bool = True
    created_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)
