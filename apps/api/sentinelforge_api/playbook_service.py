"""Approval-gated local SOAR orchestration with an immutable audit trail."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.sentinelforge_api.db_models import (
    AlertRecord,
    AnalystNoteRecord,
    AuditRecordRow,
    IncidentRecord,
    PlaybookRunRecord,
)
from apps.api.sentinelforge_api.schemas import PlaybookRun
from apps.api.sentinelforge_api.services import playbook_run_from_record
from soar.local_playbooks import PLAYBOOKS
from telemetry.models import IncidentStatus


class PlaybookStateError(ValueError):
    """Raised when a run would bypass its approval state machine."""


def _audit(
    session: Session,
    *,
    incident_id: str,
    playbook_id: str,
    action: str,
    actor: str,
    outcome: str,
    details: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditRecordRow(
            audit_id=f"audit-{uuid4().hex}",
            incident_id=incident_id,
            playbook_id=playbook_id,
            action=action,
            actor=actor,
            outcome=outcome,
            simulated=True,
            created_at=datetime.now(UTC),
            details=details or {},
        )
    )


def request_playbook(
    session: Session,
    *,
    incident_id: str,
    playbook_id: str,
    requested_by: str,
    input_data: dict[str, Any],
) -> PlaybookRun:
    if playbook_id not in PLAYBOOKS:
        raise KeyError(playbook_id)
    incident = session.get(IncidentRecord, incident_id)
    if incident is None:
        raise LookupError(incident_id)
    definition = PLAYBOOKS[playbook_id]
    now = datetime.now(UTC)
    run = PlaybookRunRecord(
        run_id=f"run-{uuid4().hex}",
        incident_id=incident_id,
        playbook_id=playbook_id,
        status="pending_approval",
        requires_approval=definition.requires_approval,
        requested_by=requested_by,
        approved_by=None,
        created_at=now,
        approved_at=None,
        completed_at=None,
        input_data=input_data,
        output_data={},
    )
    session.add(run)
    if incident.status not in {
        IncidentStatus.CLOSED.value,
        IncidentStatus.CONTAINED_SIMULATED.value,
    }:
        incident.status = IncidentStatus.PENDING_APPROVAL.value
    _audit(
        session,
        incident_id=incident_id,
        playbook_id=playbook_id,
        action="playbook_requested",
        actor=requested_by,
        outcome="pending_approval",
        details={"run_id": run.run_id, "requires_approval": True},
    )
    session.flush()
    return playbook_run_from_record(run)


def approve_playbook(session: Session, run_id: str, approved_by: str) -> PlaybookRun:
    run = session.get(PlaybookRunRecord, run_id)
    if run is None:
        raise LookupError(run_id)
    if run.status != "pending_approval":
        raise PlaybookStateError(f"run must be pending approval, not {run.status}")
    if run.requested_by.casefold() == approved_by.casefold():
        raise PlaybookStateError("requester and approver must be different analysts")
    run.status = "approved"
    run.approved_by = approved_by
    run.approved_at = datetime.now(UTC)
    _audit(
        session,
        incident_id=run.incident_id,
        playbook_id=run.playbook_id,
        action="playbook_approved",
        actor=approved_by,
        outcome="approved",
        details={"run_id": run.run_id},
    )
    session.flush()
    return playbook_run_from_record(run)


def _context(session: Session, run: PlaybookRunRecord) -> dict[str, Any]:
    incident = session.get(IncidentRecord, run.incident_id)
    if incident is None:
        raise LookupError(run.incident_id)
    alerts = [
        row
        for alert_id in incident.alert_ids
        if (row := session.get(AlertRecord, alert_id)) is not None
    ]
    notes = list(
        session.scalars(
            select(AnalystNoteRecord).where(AnalystNoteRecord.incident_id == incident.incident_id)
        )
    )
    return {
        "incident_id": incident.incident_id,
        "severity": incident.severity,
        "status": incident.status,
        "alert_ids": incident.alert_ids,
        "entities": incident.entities,
        "evidence_event_ids": sorted(
            {event_id for alert in alerts for event_id in alert.evidence_event_ids}
        ),
        "notes": [
            {"author": note.author, "body": note.body, "created_at": note.created_at.isoformat()}
            for note in notes
        ],
        "input_data": run.input_data,
    }


def execute_playbook(session: Session, run_id: str, executed_by: str) -> PlaybookRun:
    run = session.get(PlaybookRunRecord, run_id)
    if run is None:
        raise LookupError(run_id)
    if run.status != "approved" or not run.approved_by:
        raise PlaybookStateError("playbook execution requires recorded approval")
    definition = PLAYBOOKS[run.playbook_id]
    output = definition.executor(_context(session, run))
    if not output.get("simulated") or output.get("external_actions_performed") is not False:
        raise RuntimeError("playbook violated the local simulation contract")
    run.output_data = output
    run.status = "simulated_completed"
    run.completed_at = datetime.now(UTC)
    incident = session.get(IncidentRecord, run.incident_id)
    if incident is not None:
        requested_containment = run.input_data.get("simulate_containment") is True
        incident.status = (
            IncidentStatus.CONTAINED_SIMULATED.value
            if requested_containment
            else IncidentStatus.ACTIVE.value
        )
    _audit(
        session,
        incident_id=run.incident_id,
        playbook_id=run.playbook_id,
        action="playbook_executed",
        actor=executed_by,
        outcome="simulated_completed",
        details={
            "run_id": run.run_id,
            "approved_by": run.approved_by,
            "external_actions_performed": False,
        },
    )
    session.flush()
    return playbook_run_from_record(run)


def list_audit_records(session: Session, incident_id: str) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(AuditRecordRow)
        .where(AuditRecordRow.incident_id == incident_id)
        .order_by(AuditRecordRow.created_at)
    )
    return [
        {
            "audit_id": row.audit_id,
            "incident_id": row.incident_id,
            "playbook_id": row.playbook_id,
            "action": row.action,
            "actor": row.actor,
            "outcome": row.outcome,
            "simulated": row.simulated,
            "created_at": row.created_at.isoformat(),
            "details": row.details,
        }
        for row in rows
    ]
