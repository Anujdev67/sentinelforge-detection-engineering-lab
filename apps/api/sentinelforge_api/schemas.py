"""FastAPI request and compound response contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from telemetry.models import Alert, Incident, IncidentStatus, NormalizedEvent, Severity


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[NormalizedEvent] = Field(min_length=1, max_length=10_000)


class IngestResult(BaseModel):
    accepted: int
    duplicates: int


class EvaluationResult(BaseModel):
    alerts_created: int
    incidents_created: int
    alert_ids: list[str]
    incident_ids: list[str]


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus | None = None
    assigned_to: str | None = Field(default=None, min_length=3, max_length=255)


class AnalystNoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    author: str = Field(min_length=3, max_length=255)
    body: str = Field(min_length=3, max_length=5000)


class AnalystNote(BaseModel):
    note_id: int
    incident_id: str
    author: str
    body: str
    created_at: datetime


class PlaybookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requested_by: str = Field(min_length=3, max_length=255)
    input_data: dict[str, Any] = Field(default_factory=dict)


class PlaybookApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved_by: str = Field(min_length=3, max_length=255)


class PlaybookExecution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executed_by: str = Field(min_length=3, max_length=255)


class PlaybookRun(BaseModel):
    run_id: str
    incident_id: str
    playbook_id: str
    status: str
    requires_approval: bool
    requested_by: str
    approved_by: str | None
    created_at: datetime
    approved_at: datetime | None
    completed_at: datetime | None
    input_data: dict[str, Any]
    output_data: dict[str, Any]


class IncidentDetail(BaseModel):
    incident: Incident
    alerts: list[Alert]
    timeline: list[NormalizedEvent]
    notes: list[AnalystNote]
    playbook_runs: list[PlaybookRun]
    investigation_checklist: list[str]
    recommended_containment: list[str]


class HuntDefinition(BaseModel):
    hunt_id: str
    title: str
    hypothesis: str
    data_sources: list[str]
    query_example: str


class HuntRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_source: str | None = None
    limit: int = Field(default=100, ge=1, le=1000)


class OverviewMetrics(BaseModel):
    open_incidents: int
    incidents_by_severity: dict[str, int]
    alerts_over_time: list[dict[str, Any]]
    top_entities: list[dict[str, Any]]
    attack_tactics_observed: list[dict[str, Any]]
    mean_detection_latency_ms: float
    total_events: int
    total_alerts: int


class HealthResponse(BaseModel):
    status: str
    database: str
    mode: str


class AnalyticsBreakdownItem(BaseModel):
    label: str
    count: int = Field(ge=0)


class AnalyticsRuleMetric(BaseModel):
    rule_id: str
    title: str
    severity: str
    alert_count: int = Field(ge=0)
    incident_count: int = Field(ge=0)
    mean_latency_ms: float = Field(ge=0)


class AnalyticsEntityMetric(BaseModel):
    entity: str
    entity_type: str
    incident_count: int = Field(ge=0)
    alert_count: int = Field(ge=0)
    risk_score: int = Field(ge=0, le=100)


class AnalyticsDailyPoint(BaseModel):
    date: str
    events: int = Field(ge=0)
    alerts: int = Field(ge=0)
    incidents: int = Field(ge=0)


class AnalyticsSnapshot(BaseModel):
    generated_at: datetime
    total_events: int = Field(ge=0)
    total_alerts: int = Field(ge=0)
    total_incidents: int = Field(ge=0)
    alert_to_incident_ratio: float = Field(ge=0)
    event_sources: list[AnalyticsBreakdownItem]
    event_results: list[AnalyticsBreakdownItem]
    incident_statuses: list[AnalyticsBreakdownItem]
    rules: list[AnalyticsRuleMetric]
    entity_risk: list[AnalyticsEntityMetric]
    daily_activity: list[AnalyticsDailyPoint]


class ObservableType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"


class ReputationVerdict(StrEnum):
    BENIGN = "benign"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"


class ReputationLookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observable: str = Field(min_length=1, max_length=255)
    observable_type: ObservableType | None = None
    providers: list[str] = Field(default_factory=list, max_length=4)
    requested_by: str = Field(min_length=3, max_length=255)
    incident_id: str | None = Field(default=None, pattern=r"^inc-[a-f0-9]{14}$")
    force_refresh: bool = False


class ReputationProviderStatus(BaseModel):
    provider: str
    display_name: str
    supported_types: list[ObservableType]
    configured: bool
    live: bool
    enabled: bool
    status: str
    privacy_notice: str


class ReputationResult(BaseModel):
    lookup_id: str
    incident_id: str | None
    observable: str
    observable_type: ObservableType
    provider: str
    verdict: ReputationVerdict
    confidence: int = Field(ge=0, le=100)
    malicious_count: int = Field(ge=0)
    suspicious_count: int = Field(ge=0)
    total_sources: int = Field(ge=0)
    categories: list[str]
    country: str | None
    as_owner: str | None
    reference_url: str | None
    live_lookup: bool
    cache_hit: bool
    requested_by: str
    queried_at: datetime
    expires_at: datetime
    error: str | None
    details: dict[str, Any]


class ReputationLookupResponse(BaseModel):
    observable: str
    observable_type: ObservableType
    overall_verdict: ReputationVerdict
    risk_score: int = Field(ge=0, le=100)
    results: list[ReputationResult]
    live_connectors_used: bool
    analyst_notice: str


class IncidentFilters(BaseModel):
    severity: Severity | None = None
    status: IncidentStatus | None = None
    rule_id: str | None = None
    entity: str | None = None
