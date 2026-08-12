"""Add cached, auditable reputation lookup records."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0002"
down_revision: str | None = "20260811_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reputation_lookups",
        sa.Column("lookup_id", sa.String(length=96), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(length=96),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("observable_type", sa.String(length=24), nullable=False),
        sa.Column("observable_value", sa.String(length=255), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("verdict", sa.String(length=24), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("malicious_count", sa.Integer(), nullable=False),
        sa.Column("suspicious_count", sa.Integer(), nullable=False),
        sa.Column("total_sources", sa.Integer(), nullable=False),
        sa.Column("categories", sa.JSON(), nullable=False),
        sa.Column("country", sa.String(length=8), nullable=True),
        sa.Column("as_owner", sa.String(length=255), nullable=True),
        sa.Column("reference_url", sa.String(length=500), nullable=True),
        sa.Column("live_lookup", sa.Boolean(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error", sa.String(length=255), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    for column in (
        "incident_id",
        "observable_type",
        "observable_value",
        "provider",
        "verdict",
        "created_at",
        "expires_at",
    ):
        op.create_index(
            f"ix_reputation_lookups_{column}",
            "reputation_lookups",
            [column],
        )


def downgrade() -> None:
    op.drop_table("reputation_lookups")
