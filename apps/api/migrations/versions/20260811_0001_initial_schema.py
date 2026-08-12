"""Create the initial SentinelForge event, incident, and SOAR schema."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("event_id", sa.String(length=96), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_source", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("user", sa.String(length=255), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_ip", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("result", sa.String(length=100), nullable=False),
        sa.Column("correlation_id", sa.String(length=96), nullable=False),
        sa.Column("raw_event_ref", sa.String(length=255), nullable=False, unique=True),
        sa.Column("normalized", sa.JSON(), nullable=False),
    )
    for column in (
        "timestamp",
        "event_source",
        "event_type",
        "host",
        "user",
        "source_ip",
        "destination_ip",
        "result",
        "correlation_id",
    ):
        op.create_index(f"ix_events_{column}", "events", [column])

    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.String(length=96), primary_key=True),
        sa.Column("rule_id", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_observed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence_event_ids", sa.JSON(), nullable=False),
        sa.Column("entities", sa.JSON(), nullable=False),
        sa.Column("mitre_attack", sa.JSON(), nullable=False),
        sa.Column("correlation_id", sa.String(length=96), nullable=False),
        sa.Column("detection_latency_ms", sa.Integer(), nullable=False),
    )
    for column in ("rule_id", "severity", "detected_at", "correlation_id"):
        op.create_index(f"ix_alerts_{column}", "alerts", [column])

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(length=96), primary_key=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("executive_summary", sa.Text(), nullable=False),
        sa.Column("alert_ids", sa.JSON(), nullable=False),
        sa.Column("entities", sa.JSON(), nullable=False),
        sa.Column("first_observed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assigned_to", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("severity", "status", "assigned_to", "created_at"):
        op.create_index(f"ix_incidents_{column}", "incidents", [column])

    op.create_table(
        "analyst_notes",
        sa.Column("note_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "incident_id",
            sa.String(length=96),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("author", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_analyst_notes_incident_id", "analyst_notes", ["incident_id"])

    op.create_table(
        "playbook_runs",
        sa.Column("run_id", sa.String(length=96), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(length=96),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("playbook_id", sa.String(length=96), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requires_approval", sa.Boolean(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("input_data", sa.JSON(), nullable=False),
        sa.Column("output_data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_playbook_runs_incident_id", "playbook_runs", ["incident_id"])
    op.create_index("ix_playbook_runs_playbook_id", "playbook_runs", ["playbook_id"])
    op.create_index("ix_playbook_runs_status", "playbook_runs", ["status"])

    op.create_table(
        "audit_log",
        sa.Column("audit_id", sa.String(length=96), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(length=96),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("playbook_id", sa.String(length=96), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("outcome", sa.String(length=64), nullable=False),
        sa.Column("simulated", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("ix_audit_log_incident_id", "audit_log", ["incident_id"])
    op.create_index("ix_audit_log_playbook_id", "audit_log", ["playbook_id"])
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("playbook_runs")
    op.drop_table("analyst_notes")
    op.drop_table("incidents")
    op.drop_table("alerts")
    op.drop_table("events")
