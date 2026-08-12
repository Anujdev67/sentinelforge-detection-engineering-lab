"""SQLAlchemy 2 persistence models shared by PostgreSQL and SQLite tests."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_source: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    user: Mapped[str] = mapped_column(String(255), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100))
    result: Mapped[str] = mapped_column(String(100), index=True)
    correlation_id: Mapped[str] = mapped_column(String(96), index=True)
    raw_event_ref: Mapped[str] = mapped_column(String(255), unique=True)
    normalized: Mapped[dict[str, Any]] = mapped_column(JSON)


class AlertRecord(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(24), index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    first_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    summary: Mapped[str] = mapped_column(Text)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSON)
    entities: Mapped[dict[str, list[str]]] = mapped_column(JSON)
    mitre_attack: Mapped[list[dict[str, str]]] = mapped_column(JSON)
    correlation_id: Mapped[str] = mapped_column(String(96), index=True)
    detection_latency_ms: Mapped[int] = mapped_column(Integer)


class IncidentRecord(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(24), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    executive_summary: Mapped[str] = mapped_column(Text)
    alert_ids: Mapped[list[str]] = mapped_column(JSON)
    entities: Mapped[dict[str, list[str]]] = mapped_column(JSON)
    first_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ReputationLookupRecord(Base):
    __tablename__ = "reputation_lookups"

    lookup_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), nullable=True, index=True
    )
    observable_type: Mapped[str] = mapped_column(String(24), index=True)
    observable_value: Mapped[str] = mapped_column(String(255), index=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    verdict: Mapped[str] = mapped_column(String(24), index=True)
    confidence: Mapped[int] = mapped_column(Integer)
    malicious_count: Mapped[int] = mapped_column(Integer)
    suspicious_count: Mapped[int] = mapped_column(Integer)
    total_sources: Mapped[int] = mapped_column(Integer)
    categories: Mapped[list[str]] = mapped_column(JSON)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    as_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reference_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    live_lookup: Mapped[bool] = mapped_column(Boolean, default=False)
    requested_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON)


class AnalystNoteRecord(Base):
    __tablename__ = "analyst_notes"

    note_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )
    author: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PlaybookRunRecord(Base):
    __tablename__ = "playbook_runs"

    run_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )
    playbook_id: Mapped[str] = mapped_column(String(96), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    requested_by: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    input_data: Mapped[dict[str, Any]] = mapped_column(JSON)
    output_data: Mapped[dict[str, Any]] = mapped_column(JSON)


class AuditRecordRow(Base):
    __tablename__ = "audit_log"

    audit_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )
    playbook_id: Mapped[str] = mapped_column(String(96), index=True)
    action: Mapped[str] = mapped_column(String(100))
    actor: Mapped[str] = mapped_column(String(255))
    outcome: Mapped[str] = mapped_column(String(64))
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
