"""Persistence, detection execution, correlation, timeline, and metric services."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from hashlib import sha256

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from apps.api.sentinelforge_api.db_models import (
    AlertRecord,
    AnalystNoteRecord,
    EventRecord,
    IncidentRecord,
    PlaybookRunRecord,
)
from apps.api.sentinelforge_api.schemas import (
    AnalystNote,
    AnalyticsBreakdownItem,
    AnalyticsDailyPoint,
    AnalyticsEntityMetric,
    AnalyticsRuleMetric,
    AnalyticsSnapshot,
    EvaluationResult,
    IncidentDetail,
    IngestResult,
    OverviewMetrics,
    PlaybookRun,
)
from detections.loader import load_detection_pack, load_detection_packs
from evaluators.engine import evaluate_rule
from telemetry.models import (
    Alert,
    Incident,
    IncidentStatus,
    MitreMapping,
    NormalizedEvent,
    Severity,
)

SEVERITY_RANK = {
    Severity.INFORMATIONAL.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _digest(value: str) -> str:
    return sha256(value.encode(), usedforsecurity=False).hexdigest()[:14]


def event_from_record(row: EventRecord) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=row.event_id,
        timestamp=_aware(row.timestamp),
        event_source=row.event_source,
        event_type=row.event_type,
        host=row.host,
        user=row.user,
        source_ip=row.source_ip,
        destination_ip=row.destination_ip,
        action=row.action,
        result=row.result,
        correlation_id=row.correlation_id,
        raw_event_ref=row.raw_event_ref,
        normalized=row.normalized,
    )


def alert_from_record(row: AlertRecord) -> Alert:
    return Alert(
        alert_id=row.alert_id,
        rule_id=row.rule_id,
        title=row.title,
        severity=row.severity,
        detected_at=_aware(row.detected_at),
        first_observed=_aware(row.first_observed),
        last_observed=_aware(row.last_observed),
        summary=row.summary,
        evidence_event_ids=row.evidence_event_ids,
        entities=row.entities,
        mitre_attack=[MitreMapping.model_validate(item) for item in row.mitre_attack],
        correlation_id=row.correlation_id,
        detection_latency_ms=row.detection_latency_ms,
    )


def incident_from_record(row: IncidentRecord) -> Incident:
    return Incident(
        incident_id=row.incident_id,
        title=row.title,
        severity=row.severity,
        status=row.status,
        executive_summary=row.executive_summary,
        alert_ids=row.alert_ids,
        entities=row.entities,
        first_observed=_aware(row.first_observed),
        last_observed=_aware(row.last_observed),
        assigned_to=row.assigned_to,
        created_at=_aware(row.created_at),
    )


def playbook_run_from_record(row: PlaybookRunRecord) -> PlaybookRun:
    return PlaybookRun(
        run_id=row.run_id,
        incident_id=row.incident_id,
        playbook_id=row.playbook_id,
        status=row.status,
        requires_approval=row.requires_approval,
        requested_by=row.requested_by,
        approved_by=row.approved_by,
        created_at=_aware(row.created_at),
        approved_at=_aware(row.approved_at) if row.approved_at else None,
        completed_at=_aware(row.completed_at) if row.completed_at else None,
        input_data=row.input_data,
        output_data=row.output_data,
    )


def ingest_events(session: Session, events: list[NormalizedEvent]) -> IngestResult:
    accepted = 0
    duplicates = 0
    for event in events:
        if session.get(EventRecord, event.event_id) is not None:
            duplicates += 1
            continue
        session.add(
            EventRecord(
                event_id=event.event_id,
                timestamp=event.timestamp,
                event_source=event.event_source.value,
                event_type=event.event_type,
                host=event.host,
                user=event.user,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                action=event.action,
                result=event.result,
                correlation_id=event.correlation_id,
                raw_event_ref=event.raw_event_ref,
                normalized=event.normalized,
            )
        )
        accepted += 1
    session.flush()
    return IngestResult(accepted=accepted, duplicates=duplicates)


def list_events(
    session: Session,
    *,
    source: str | None = None,
    user: str | None = None,
    host: str | None = None,
    limit: int = 500,
) -> list[NormalizedEvent]:
    query: Select[tuple[EventRecord]] = select(EventRecord).order_by(EventRecord.timestamp.desc())
    if source:
        query = query.where(EventRecord.event_source == source)
    if user:
        query = query.where(EventRecord.user == user)
    if host:
        query = query.where(EventRecord.host == host)
    return [event_from_record(row) for row in session.scalars(query.limit(limit))]


def _persist_alert(session: Session, alert: Alert) -> bool:
    if session.get(AlertRecord, alert.alert_id) is not None:
        return False
    session.add(
        AlertRecord(
            alert_id=alert.alert_id,
            rule_id=alert.rule_id,
            title=alert.title,
            severity=alert.severity.value,
            detected_at=alert.detected_at,
            first_observed=alert.first_observed,
            last_observed=alert.last_observed,
            summary=alert.summary,
            evidence_event_ids=alert.evidence_event_ids,
            entities=alert.entities,
            mitre_attack=[mapping.model_dump() for mapping in alert.mitre_attack],
            correlation_id=alert.correlation_id,
            detection_latency_ms=alert.detection_latency_ms,
        )
    )
    return True


def _entity_values(alert: Alert, names: set[str]) -> set[str]:
    return {
        value
        for name, values in alert.entities.items()
        if name in names
        for value in values
        if value
    }


def _connected_alert_groups(alerts: list[Alert]) -> list[list[Alert]]:
    parents = list(range(len(alerts)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(first: int, second: int) -> None:
        first_root, second_root = find(first), find(second)
        if first_root != second_root:
            parents[second_root] = first_root

    for first_index, first in enumerate(alerts):
        for second_index in range(first_index + 1, len(alerts)):
            second = alerts[second_index]
            within_window = (
                abs((second.first_observed - first.last_observed).total_seconds()) <= 3600
            )
            shared_high_confidence_entity = bool(
                _entity_values(first, {"account", "host"})
                & _entity_values(second, {"account", "host"})
            )
            if first.correlation_id == second.correlation_id or (
                within_window and shared_high_confidence_entity
            ):
                union(first_index, second_index)

    grouped: dict[int, list[Alert]] = defaultdict(list)
    for index, alert in enumerate(alerts):
        grouped[find(index)].append(alert)
    return [sorted(group, key=lambda alert: alert.first_observed) for group in grouped.values()]


def _merge_entities(alerts: list[Alert]) -> dict[str, list[str]]:
    merged: dict[str, set[str]] = defaultdict(set)
    for alert in alerts:
        for entity_type, values in alert.entities.items():
            merged[entity_type].update(value for value in values if value)
    return {entity_type: sorted(values) for entity_type, values in sorted(merged.items())}


def _persist_incident(session: Session, alerts: list[Alert]) -> IncidentRecord | None:
    alert_ids = sorted(alert.alert_id for alert in alerts)
    incident_id = f"inc-{_digest(':'.join(alert_ids))}"
    if session.get(IncidentRecord, incident_id) is not None:
        return None
    entities = _merge_entities(alerts)
    severity = max((alert.severity.value for alert in alerts), key=SEVERITY_RANK.__getitem__)
    title = (
        alerts[0].title if len(alerts) == 1 else f"Correlated activity across {len(alerts)} alerts"
    )
    rule_ids = sorted({alert.rule_id for alert in alerts})
    record = IncidentRecord(
        incident_id=incident_id,
        title=title,
        severity=severity,
        status=IncidentStatus.NEW.value,
        executive_summary=(
            f"SentinelForge correlated {len(alerts)} synthetic alert(s) from rules "
            f"{', '.join(rule_ids)} using correlation IDs and overlapping account or host entities."
        ),
        alert_ids=alert_ids,
        entities=entities,
        first_observed=min(alert.first_observed for alert in alerts),
        last_observed=max(alert.last_observed for alert in alerts),
        assigned_to=None,
        created_at=max(alert.detected_at for alert in alerts),
    )
    session.add(record)
    return record


def evaluate_and_correlate(session: Session) -> EvaluationResult:
    events = [event_from_record(row) for row in session.scalars(select(EventRecord))]
    created_alert_ids: list[str] = []
    for pack in load_detection_packs():
        for alert in evaluate_rule(events, pack.metadata):
            if _persist_alert(session, alert):
                created_alert_ids.append(alert.alert_id)
    session.flush()

    all_alerts = [alert_from_record(row) for row in session.scalars(select(AlertRecord))]
    created_incident_ids: list[str] = []
    for group in _connected_alert_groups(all_alerts):
        incident = _persist_incident(session, group)
        if incident:
            created_incident_ids.append(incident.incident_id)
    session.flush()
    return EvaluationResult(
        alerts_created=len(created_alert_ids),
        incidents_created=len(created_incident_ids),
        alert_ids=created_alert_ids,
        incident_ids=created_incident_ids,
    )


def list_alerts(session: Session, rule_id: str | None = None) -> list[Alert]:
    query = select(AlertRecord).order_by(AlertRecord.detected_at.desc())
    if rule_id:
        query = query.where(AlertRecord.rule_id == rule_id)
    return [alert_from_record(row) for row in session.scalars(query)]


def list_incidents(
    session: Session,
    *,
    severity: str | None = None,
    status: str | None = None,
    rule_id: str | None = None,
    entity: str | None = None,
) -> list[Incident]:
    query = select(IncidentRecord).order_by(IncidentRecord.last_observed.desc())
    if severity:
        query = query.where(IncidentRecord.severity == severity)
    if status:
        query = query.where(IncidentRecord.status == status)
    incidents = [incident_from_record(row) for row in session.scalars(query)]
    if entity:
        needle = entity.casefold()
        incidents = [
            incident
            for incident in incidents
            if any(
                needle in value.casefold()
                for values in incident.entities.values()
                for value in values
            )
        ]
    if rule_id:
        matching_alert_ids = set(
            session.scalars(select(AlertRecord.alert_id).where(AlertRecord.rule_id == rule_id))
        )
        incidents = [
            incident
            for incident in incidents
            if matching_alert_ids.intersection(incident.alert_ids)
        ]
    return incidents


def get_incident_detail(session: Session, incident_id: str) -> IncidentDetail | None:
    record = session.get(IncidentRecord, incident_id)
    if record is None:
        return None
    alerts = [
        alert_from_record(row)
        for alert_id in record.alert_ids
        if (row := session.get(AlertRecord, alert_id)) is not None
    ]
    evidence_ids = {event_id for alert in alerts for event_id in alert.evidence_event_ids}
    timeline = [
        event_from_record(row)
        for row in session.scalars(
            select(EventRecord)
            .where(EventRecord.event_id.in_(evidence_ids))
            .order_by(EventRecord.timestamp)
        )
    ]
    note_rows = session.scalars(
        select(AnalystNoteRecord)
        .where(AnalystNoteRecord.incident_id == incident_id)
        .order_by(AnalystNoteRecord.created_at)
    )
    notes = [
        AnalystNote(
            note_id=row.note_id,
            incident_id=row.incident_id,
            author=row.author,
            body=row.body,
            created_at=_aware(row.created_at),
        )
        for row in note_rows
    ]
    playbook_runs = [
        playbook_run_from_record(row)
        for row in session.scalars(
            select(PlaybookRunRecord)
            .where(PlaybookRunRecord.incident_id == incident_id)
            .order_by(PlaybookRunRecord.created_at.desc())
        )
    ]
    metadata = [load_detection_pack(alert.rule_id).metadata for alert in alerts]
    return IncidentDetail(
        incident=incident_from_record(record),
        alerts=alerts,
        timeline=timeline,
        notes=notes,
        playbook_runs=playbook_runs,
        investigation_checklist=list(
            dict.fromkeys(step for item in metadata for step in item.investigation_steps)
        ),
        recommended_containment=list(
            dict.fromkeys(step for item in metadata for step in item.containment_recommendations)
        ),
    )


def overview_metrics(session: Session) -> OverviewMetrics:
    incidents = [incident_from_record(row) for row in session.scalars(select(IncidentRecord))]
    alerts = [alert_from_record(row) for row in session.scalars(select(AlertRecord))]
    severity_counts = Counter(incident.severity.value for incident in incidents)
    daily_alerts = Counter(alert.detected_at.date().isoformat() for alert in alerts)
    entity_counter = Counter(
        f"{entity_type}:{value}"
        for incident in incidents
        for entity_type, values in incident.entities.items()
        for value in values
    )
    tactic_counter = Counter(
        mapping.tactic_name for alert in alerts for mapping in alert.mitre_attack
    )
    latency = sum(alert.detection_latency_ms for alert in alerts) / len(alerts) if alerts else 0.0
    open_statuses = {IncidentStatus.NEW, IncidentStatus.ACTIVE, IncidentStatus.PENDING_APPROVAL}
    return OverviewMetrics(
        open_incidents=sum(incident.status in open_statuses for incident in incidents),
        incidents_by_severity=dict(sorted(severity_counts.items())),
        alerts_over_time=[
            {"date": date, "count": count} for date, count in sorted(daily_alerts.items())
        ],
        top_entities=[
            {"entity": entity, "count": count} for entity, count in entity_counter.most_common(10)
        ],
        attack_tactics_observed=[
            {"tactic": tactic, "count": count} for tactic, count in tactic_counter.most_common()
        ],
        mean_detection_latency_ms=round(latency, 2),
        total_events=session.scalar(select(func.count()).select_from(EventRecord)) or 0,
        total_alerts=len(alerts),
    )


def analytics_snapshot(session: Session) -> AnalyticsSnapshot:
    """Build deterministic operational metrics from persisted local SOC records."""
    event_rows = list(session.scalars(select(EventRecord)))
    alerts = [alert_from_record(row) for row in session.scalars(select(AlertRecord))]
    incidents = [incident_from_record(row) for row in session.scalars(select(IncidentRecord))]
    event_sources = Counter(row.event_source for row in event_rows)
    event_results = Counter(row.result for row in event_rows)
    incident_statuses = Counter(incident.status.value for incident in incidents)

    incident_ids_by_alert: defaultdict[str, set[str]] = defaultdict(set)
    for incident in incidents:
        for alert_id in incident.alert_ids:
            incident_ids_by_alert[alert_id].add(incident.incident_id)

    packs = {pack.metadata.rule_id: pack.metadata for pack in load_detection_packs()}
    alerts_by_rule: defaultdict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        alerts_by_rule[alert.rule_id].append(alert)
    rule_metrics: list[AnalyticsRuleMetric] = []
    for rule_id, metadata in sorted(packs.items()):
        rule_alerts = alerts_by_rule[rule_id]
        linked_incidents = {
            incident_id
            for alert in rule_alerts
            for incident_id in incident_ids_by_alert[alert.alert_id]
        }
        mean_latency = (
            sum(alert.detection_latency_ms for alert in rule_alerts) / len(rule_alerts)
            if rule_alerts
            else 0.0
        )
        rule_metrics.append(
            AnalyticsRuleMetric(
                rule_id=rule_id,
                title=metadata.title,
                severity=metadata.severity.value,
                alert_count=len(rule_alerts),
                incident_count=len(linked_incidents),
                mean_latency_ms=round(mean_latency, 2),
            )
        )

    alert_entity_counts: Counter[tuple[str, str]] = Counter()
    for alert in alerts:
        for entity_type, values in alert.entities.items():
            alert_entity_counts.update((entity_type, value) for value in set(values))
    incident_entity_counts: Counter[tuple[str, str]] = Counter()
    entity_severity: defaultdict[tuple[str, str], int] = defaultdict(int)
    for incident in incidents:
        weight = (SEVERITY_RANK[incident.severity.value] + 1) * 16
        for entity_type, values in incident.entities.items():
            for value in set(values):
                key = (entity_type, value)
                incident_entity_counts[key] += 1
                entity_severity[key] = max(entity_severity[key], weight)
    all_entities = set(alert_entity_counts) | set(incident_entity_counts)
    entity_metrics = [
        AnalyticsEntityMetric(
            entity=value,
            entity_type=entity_type,
            incident_count=incident_entity_counts[(entity_type, value)],
            alert_count=alert_entity_counts[(entity_type, value)],
            risk_score=min(
                100,
                entity_severity[(entity_type, value)]
                + incident_entity_counts[(entity_type, value)] * 6
                + alert_entity_counts[(entity_type, value)] * 3,
            ),
        )
        for entity_type, value in all_entities
    ]
    entity_metrics.sort(
        key=lambda item: (-item.risk_score, -item.alert_count, item.entity_type, item.entity)
    )

    daily_events = Counter(_aware(row.timestamp).date().isoformat() for row in event_rows)
    daily_alerts = Counter(alert.detected_at.date().isoformat() for alert in alerts)
    daily_incidents = Counter(incident.created_at.date().isoformat() for incident in incidents)
    dates = sorted(set(daily_events) | set(daily_alerts) | set(daily_incidents))

    return AnalyticsSnapshot(
        generated_at=datetime.now(UTC),
        total_events=len(event_rows),
        total_alerts=len(alerts),
        total_incidents=len(incidents),
        alert_to_incident_ratio=round(len(alerts) / len(incidents), 2) if incidents else 0.0,
        event_sources=[
            AnalyticsBreakdownItem(label=label, count=count)
            for label, count in event_sources.most_common()
        ],
        event_results=[
            AnalyticsBreakdownItem(label=label, count=count)
            for label, count in event_results.most_common()
        ],
        incident_statuses=[
            AnalyticsBreakdownItem(label=label, count=count)
            for label, count in incident_statuses.most_common()
        ],
        rules=rule_metrics,
        entity_risk=entity_metrics[:25],
        daily_activity=[
            AnalyticsDailyPoint(
                date=date,
                events=daily_events[date],
                alerts=daily_alerts[date],
                incidents=daily_incidents[date],
            )
            for date in dates
        ],
    )
