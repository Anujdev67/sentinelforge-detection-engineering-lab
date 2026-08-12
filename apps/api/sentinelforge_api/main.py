"""SentinelForge FastAPI application and local SOC endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Any

import httpx
import yaml
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from apps.api.sentinelforge_api.config import Settings, get_settings
from apps.api.sentinelforge_api.database import Database
from apps.api.sentinelforge_api.db_models import AnalystNoteRecord, IncidentRecord
from apps.api.sentinelforge_api.playbook_service import (
    PlaybookStateError,
    approve_playbook,
    execute_playbook,
    list_audit_records,
    request_playbook,
)
from apps.api.sentinelforge_api.reputation import (
    lookup_reputation,
    provider_statuses,
    reputation_history,
)
from apps.api.sentinelforge_api.schemas import (
    AnalystNote,
    AnalystNoteCreate,
    AnalyticsSnapshot,
    EvaluationResult,
    EventBatch,
    HealthResponse,
    HuntDefinition,
    HuntRunRequest,
    IncidentDetail,
    IncidentUpdate,
    IngestResult,
    OverviewMetrics,
    PlaybookApproval,
    PlaybookExecution,
    PlaybookRequest,
    PlaybookRun,
    ReputationLookupRequest,
    ReputationLookupResponse,
    ReputationProviderStatus,
    ReputationResult,
)
from apps.api.sentinelforge_api.services import (
    analytics_snapshot,
    evaluate_and_correlate,
    get_incident_detail,
    ingest_events,
    list_alerts,
    list_events,
    list_incidents,
    overview_metrics,
)
from detections.loader import load_detection_packs
from detections.quality import build_quality_snapshot
from soar.local_playbooks import PLAYBOOKS
from telemetry.models import Alert, Incident, IncidentStatus, NormalizedEvent, Severity

API_PREFIX = "/api/v1"
ATTACK_VERSION = "19.1"
ATTACK_RELEASE_DATE = "2026-04-28"

HUNTS = {
    "identity-authentication-chain": HuntDefinition(
        hunt_id="identity-authentication-chain",
        title="Authentication failure-to-success chain",
        hypothesis="An identity may have been accessed after repeated authentication failures.",
        data_sources=["SigninLogs", "AuditLogs"],
        query_example=(
            "SigninLogs | where TimeGenerated > ago(24h) "
            "| summarize Failures=countif(ResultType != '0'), "
            "Successes=countif(ResultType == '0') by UserPrincipalName, IPAddress"
        ),
    ),
    "suspicious-process-chain": HuntDefinition(
        hunt_id="suspicious-process-chain",
        title="Suspicious PowerShell and remote-support execution",
        hypothesis="A suspicious scripting process may be followed by unauthorized remote access.",
        data_sources=["DeviceProcessEvents", "DeviceNetworkEvents"],
        query_example=(
            "DeviceProcessEvents | where Timestamp > ago(24h) "
            "| where FileName in~ ('powershell.exe', 'pwsh.exe', 'anydesk.exe', 'teamviewer.exe')"
        ),
    ),
    "periodic-network-activity": HuntDefinition(
        hunt_id="periodic-network-activity",
        title="Periodic outbound and unusual DNS activity",
        hypothesis="A device may be using DNS or low-jitter web sessions for command and control.",
        data_sources=["DeviceNetworkEvents", "CommonSecurityLog"],
        query_example=(
            "CommonSecurityLog | where TimeGenerated > ago(24h) "
            "| summarize Sessions=count() by SourceIP, DestinationIP, bin(TimeGenerated, 5m)"
        ),
    ),
}

ENTERPRISE_TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Stealth"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0112", "Defense Impairment"),
    ("TA0040", "Impact"),
]


def _session(request: Request) -> Generator[Session, None, None]:
    database: Database = request.app.state.database
    with database.session_factory() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


SessionDependency = Annotated[Session, Depends(_session)]


def create_app(*, settings: Settings | None = None, database_url: str | None = None) -> FastAPI:
    configured = settings or get_settings()
    application_database = Database(database_url or configured.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        application_database.create_schema()
        yield

    application = FastAPI(
        title="SentinelForge API",
        description=(
            "Local-only SOC workflow for synthetic telemetry, detection engineering, "
            "incident correlation, and approval-gated SOAR simulation."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )
    application.state.database = application_database
    application.state.settings = configured
    application.add_middleware(
        CORSMiddleware,
        allow_origins=configured.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type", "Accept"],
    )

    @application.get(f"{API_PREFIX}/health", response_model=HealthResponse, tags=["system"])
    def health(session: SessionDependency) -> HealthResponse:
        try:
            session.execute(text("SELECT 1"))
            database_health = "ready"
        except SQLAlchemyError:
            database_health = "unavailable"
        return HealthResponse(
            status="ok" if database_health == "ready" else "degraded",
            database=database_health,
            mode="synthetic-local-simulation",
        )

    @application.post(
        f"{API_PREFIX}/events/ingest",
        response_model=IngestResult,
        status_code=status.HTTP_201_CREATED,
        tags=["events"],
    )
    def ingest(payload: EventBatch, session: SessionDependency) -> IngestResult:
        return ingest_events(session, payload.events)

    @application.get(f"{API_PREFIX}/events", response_model=list[NormalizedEvent], tags=["events"])
    def events(
        session: SessionDependency,
        source: str | None = None,
        user: str | None = None,
        host: str | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    ) -> list[NormalizedEvent]:
        return list_events(session, source=source, user=user, host=host, limit=limit)

    @application.post(
        f"{API_PREFIX}/detections/evaluate",
        response_model=EvaluationResult,
        tags=["detections"],
    )
    def evaluate(session: SessionDependency) -> EvaluationResult:
        return evaluate_and_correlate(session)

    @application.get(f"{API_PREFIX}/alerts", response_model=list[Alert], tags=["alerts"])
    def alerts(session: SessionDependency, rule_id: str | None = None) -> list[Alert]:
        return list_alerts(session, rule_id)

    @application.get(f"{API_PREFIX}/incidents", response_model=list[Incident], tags=["incidents"])
    def incidents(
        session: SessionDependency,
        severity: Severity | None = None,
        incident_status: Annotated[IncidentStatus | None, Query(alias="status")] = None,
        rule_id: str | None = None,
        entity: str | None = None,
    ) -> list[Incident]:
        return list_incidents(
            session,
            severity=severity.value if severity else None,
            status=incident_status.value if incident_status else None,
            rule_id=rule_id,
            entity=entity,
        )

    @application.get(
        f"{API_PREFIX}/incidents/{{incident_id}}",
        response_model=IncidentDetail,
        tags=["incidents"],
    )
    def incident_detail(incident_id: str, session: SessionDependency) -> IncidentDetail:
        detail = get_incident_detail(session, incident_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return detail

    @application.patch(
        f"{API_PREFIX}/incidents/{{incident_id}}",
        response_model=Incident,
        tags=["incidents"],
    )
    def update_incident(
        incident_id: str, payload: IncidentUpdate, session: SessionDependency
    ) -> Incident:
        record = session.get(IncidentRecord, incident_id)
        if record is None:
            raise HTTPException(status_code=404, detail="incident not found")
        if payload.status is not None:
            record.status = payload.status.value
        if "assigned_to" in payload.model_fields_set:
            record.assigned_to = payload.assigned_to
        session.flush()
        updated = get_incident_detail(session, incident_id)
        if updated is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return updated.incident

    @application.post(
        f"{API_PREFIX}/incidents/{{incident_id}}/notes",
        response_model=AnalystNote,
        status_code=status.HTTP_201_CREATED,
        tags=["incidents"],
    )
    def add_note(
        incident_id: str, payload: AnalystNoteCreate, session: SessionDependency
    ) -> AnalystNote:
        if session.get(IncidentRecord, incident_id) is None:
            raise HTTPException(status_code=404, detail="incident not found")
        row = AnalystNoteRecord(
            incident_id=incident_id,
            author=payload.author,
            body=payload.body,
            created_at=datetime.now(UTC),
        )
        session.add(row)
        session.flush()
        return AnalystNote(
            note_id=row.note_id,
            incident_id=row.incident_id,
            author=row.author,
            body=row.body,
            created_at=row.created_at,
        )

    @application.get(f"{API_PREFIX}/overview", response_model=OverviewMetrics, tags=["overview"])
    def overview(session: SessionDependency) -> OverviewMetrics:
        return overview_metrics(session)

    @application.get(
        f"{API_PREFIX}/analytics",
        response_model=AnalyticsSnapshot,
        tags=["analytics"],
    )
    def analytics(session: SessionDependency) -> AnalyticsSnapshot:
        return analytics_snapshot(session)

    @application.get(f"{API_PREFIX}/detections", tags=["detections"])
    def detections() -> list[dict[str, Any]]:
        quality_by_id = {result.rule_id: result for result in build_quality_snapshot().rules}
        return [
            {
                **pack.metadata.model_dump(mode="json"),
                "kql": pack.kql,
                "sigma": yaml.safe_dump(pack.sigma, sort_keys=False) if pack.sigma else None,
                "test_status": quality_by_id[pack.metadata.rule_id].model_dump(),
                "local_evaluator_notice": (
                    "Purpose-built Python behavioral counterpart; this is not a KQL "
                    "execution engine."
                ),
            }
            for pack in load_detection_packs()
        ]

    @application.get(f"{API_PREFIX}/quality", tags=["detections"])
    def quality() -> dict[str, Any]:
        return build_quality_snapshot().model_dump(mode="json")

    @application.get(f"{API_PREFIX}/attack-coverage", tags=["detections"])
    def attack_coverage() -> dict[str, Any]:
        packs = load_detection_packs()
        rule_by_tactic: dict[str, set[str]] = {}
        technique_rows: dict[str, dict[str, Any]] = {}
        for pack in packs:
            for mapping in pack.metadata.mitre_attack:
                rule_by_tactic.setdefault(mapping.tactic, set()).add(pack.metadata.rule_id)
                technique = technique_rows.setdefault(
                    mapping.technique,
                    {
                        "technique_id": mapping.technique,
                        "technique_name": mapping.technique_name,
                        "tactic_id": mapping.tactic,
                        "tactic_name": mapping.tactic_name,
                        "rule_ids": [],
                        "data_sources": [],
                        "severities": [],
                        "validation": "positive and negative local fixtures",
                    },
                )
                technique["rule_ids"].append(pack.metadata.rule_id)
                technique["data_sources"].extend(pack.metadata.required_data_sources)
                technique["severities"].append(pack.metadata.severity.value)
        techniques = sorted(technique_rows.values(), key=lambda item: item["technique_id"])
        for technique in techniques:
            technique["rule_ids"] = sorted(set(technique["rule_ids"]))
            technique["data_sources"] = sorted(set(technique["data_sources"]))
            technique["severities"] = sorted(set(technique["severities"]))
        covered_count = len(rule_by_tactic)
        return {
            "framework": {
                "name": "MITRE ATT&CK Enterprise",
                "version": ATTACK_VERSION,
                "release_date": ATTACK_RELEASE_DATE,
                "source": "https://attack.mitre.org/",
                "local_snapshot": True,
            },
            "summary": {
                "covered_tactics": covered_count,
                "total_tactics": len(ENTERPRISE_TACTICS),
                "coverage_percent": round(covered_count * 100 / len(ENTERPRISE_TACTICS), 1),
                "mapped_techniques": len(techniques),
                "mapped_rules": len(packs),
            },
            "tactics": [
                {
                    "tactic_id": tactic_id,
                    "tactic_name": tactic_name,
                    "covered": tactic_id in rule_by_tactic,
                    "gap": tactic_id not in rule_by_tactic,
                    "rule_ids": sorted(rule_by_tactic.get(tactic_id, set())),
                }
                for tactic_id, tactic_name in ENTERPRISE_TACTICS
            ],
            "techniques": techniques,
            "limitations": [
                "Coverage represents implemented detection mappings, not defensive effectiveness.",
                (
                    "Local fixture validation does not replace production telemetry "
                    "validation and tuning."
                ),
                "This pinned snapshot does not update automatically from MITRE TAXII or STIX.",
            ],
        }

    @application.get(
        f"{API_PREFIX}/attack-coverage/navigator-layer",
        tags=["detections"],
    )
    def attack_navigator_layer() -> dict[str, Any]:
        coverage = attack_coverage()
        techniques = coverage["techniques"]
        return {
            "name": "SentinelForge detection coverage",
            "versions": {
                "attack": ATTACK_VERSION,
                "navigator": "4.5.0",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": (
                "SentinelForge local detection-to-technique coverage. "
                "Scores indicate mapped-rule count, not detection efficacy."
            ),
            "filters": {"platforms": []},
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": [
                {
                    "techniqueID": technique["technique_id"],
                    "score": min(100, 40 + len(technique["rule_ids"]) * 20),
                    "comment": (
                        f"Rules: {', '.join(technique['rule_ids'])}; "
                        f"data: {', '.join(technique['data_sources'])}"
                    ),
                    "enabled": True,
                    "metadata": [
                        {"name": "Rule", "value": rule_id} for rule_id in technique["rule_ids"]
                    ],
                }
                for technique in techniques
            ],
            "gradient": {
                "colors": ["#172b3d", "#5e8bff", "#31d2b3"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Mapped by one rule", "color": "#5e8bff"},
                {"label": "Mapped by multiple rules", "color": "#31d2b3"},
            ],
            "metadata": [
                {"name": "ATT&CK release", "value": ATTACK_VERSION},
                {"name": "Validation", "value": "local positive/negative fixtures"},
            ],
            "links": [
                {
                    "label": "SentinelForge ATT&CK coverage",
                    "url": "https://attack.mitre.org/",
                }
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#0b1826",
            "selectTechniquesAcrossTactics": True,
        }

    @application.get(f"{API_PREFIX}/hunts", response_model=list[HuntDefinition], tags=["hunting"])
    def hunts() -> list[HuntDefinition]:
        return list(HUNTS.values())

    @application.post(f"{API_PREFIX}/hunts/{{hunt_id}}/run", tags=["hunting"])
    def run_hunt(
        hunt_id: str, payload: HuntRunRequest, session: SessionDependency
    ) -> dict[str, Any]:
        hunt = HUNTS.get(hunt_id)
        if hunt is None:
            raise HTTPException(status_code=404, detail="hunt not found")
        source = payload.data_source or hunt.data_sources[0]
        if source not in hunt.data_sources:
            raise HTTPException(status_code=422, detail="data source is not supported by this hunt")
        results = list_events(session, source=source, limit=payload.limit)
        return {
            "hunt": hunt.model_dump(),
            "data_source": source,
            "result_count": len(results),
            "results": [event.model_dump(mode="json") for event in results],
            "investigation_notes": (
                f"Hypothesis: {hunt.hypothesis}\n"
                f"Reviewed {len(results)} synthetic {source} events.\n"
                "Analyst conclusion: pending review."
            ),
        }

    @application.get(
        f"{API_PREFIX}/reputation/providers",
        response_model=list[ReputationProviderStatus],
        tags=["threat intelligence"],
    )
    def reputation_providers() -> list[ReputationProviderStatus]:
        return provider_statuses(configured)

    @application.post(
        f"{API_PREFIX}/reputation/lookup",
        response_model=ReputationLookupResponse,
        tags=["threat intelligence"],
    )
    async def reputation_lookup(
        payload: ReputationLookupRequest, session: SessionDependency
    ) -> ReputationLookupResponse:
        timeout = httpx.Timeout(configured.reputation_timeout_seconds)
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": "SentinelForge/1.0 read-only-enrichment"},
        ) as client:
            try:
                return await lookup_reputation(session, payload, configured, client)
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.get(
        f"{API_PREFIX}/reputation/history",
        response_model=list[ReputationResult],
        tags=["threat intelligence"],
    )
    def reputation_lookup_history(
        session: SessionDependency,
        observable: str | None = None,
        incident_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[ReputationResult]:
        try:
            return reputation_history(
                session,
                observable=observable,
                incident_id=incident_id,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.get(f"{API_PREFIX}/playbooks", tags=["soar"])
    def playbooks() -> list[dict[str, Any]]:
        return [
            {
                "playbook_id": definition.playbook_id,
                "title": definition.title,
                "description": definition.description,
                "requires_approval": definition.requires_approval,
                "simulation_only": True,
            }
            for definition in PLAYBOOKS.values()
        ]

    @application.post(
        f"{API_PREFIX}/incidents/{{incident_id}}/playbooks/{{playbook_id}}/request",
        response_model=PlaybookRun,
        status_code=status.HTTP_201_CREATED,
        tags=["soar"],
    )
    def request_run(
        incident_id: str,
        playbook_id: str,
        payload: PlaybookRequest,
        session: SessionDependency,
    ) -> PlaybookRun:
        try:
            return request_playbook(
                session,
                incident_id=incident_id,
                playbook_id=playbook_id,
                requested_by=payload.requested_by,
                input_data=payload.input_data,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="playbook not found") from exc
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="incident not found") from exc

    @application.post(
        f"{API_PREFIX}/playbook-runs/{{run_id}}/approve",
        response_model=PlaybookRun,
        tags=["soar"],
    )
    def approve_run(
        run_id: str, payload: PlaybookApproval, session: SessionDependency
    ) -> PlaybookRun:
        try:
            return approve_playbook(session, run_id, payload.approved_by)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="playbook run not found") from exc
        except PlaybookStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post(
        f"{API_PREFIX}/playbook-runs/{{run_id}}/execute",
        response_model=PlaybookRun,
        tags=["soar"],
    )
    def execute_run(
        run_id: str, payload: PlaybookExecution, session: SessionDependency
    ) -> PlaybookRun:
        try:
            return execute_playbook(session, run_id, payload.executed_by)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="playbook run not found") from exc
        except PlaybookStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.get(f"{API_PREFIX}/incidents/{{incident_id}}/audit", tags=["soar"])
    def audit(incident_id: str, session: SessionDependency) -> list[dict[str, Any]]:
        if session.get(IncidentRecord, incident_id) is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return list_audit_records(session, incident_id)

    return application


app = create_app()
