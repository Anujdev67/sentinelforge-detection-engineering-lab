"""Reset and populate the guarded, synthetic-only SentinelForge demo database."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import delete, make_url
from sqlalchemy.orm import Session

from apps.api.sentinelforge_api.config import Settings
from apps.api.sentinelforge_api.database import Database
from apps.api.sentinelforge_api.db_models import (
    AlertRecord,
    AnalystNoteRecord,
    AuditRecordRow,
    EventRecord,
    IncidentRecord,
    PlaybookRunRecord,
)
from apps.api.sentinelforge_api.services import (
    evaluate_and_correlate,
    ingest_events,
    list_incidents,
)
from telemetry.generators.baseline import generate_baseline
from telemetry.generators.scenarios import scenario_fixtures
from telemetry.models import NormalizedEvent

DASHBOARD_URL = "http://localhost:5173"
ALLOWED_SQLITE_DATABASES = {"sentinelforge-demo.db", "sentinelforge_demo.db"}


class UnsafeDemoResetError(RuntimeError):
    """Raised when a database does not satisfy the local demo reset guard."""


def assert_demo_reset_allowed(settings: Settings) -> None:
    """Require an unmistakably local demo target before permitting row deletion."""

    if not settings.demo_mode:
        raise UnsafeDemoResetError("demo reset refused: SENTINELFORGE_DEMO_MODE is not true")
    url = make_url(settings.database_url)
    database_name = Path(url.database or "").name
    is_named_postgres_demo = url.get_backend_name() == "postgresql" and (
        database_name == "sentinelforge_demo"
    )
    is_named_sqlite_demo = url.get_backend_name() == "sqlite" and (
        database_name in ALLOWED_SQLITE_DATABASES
    )
    if not (is_named_postgres_demo or is_named_sqlite_demo):
        raise UnsafeDemoResetError(
            "demo reset refused: target must be PostgreSQL database 'sentinelforge_demo' "
            "or a named SentinelForge SQLite demo file"
        )


def reset_demo_data(session: Session, settings: Settings) -> None:
    """Delete only known SentinelForge demo tables in foreign-key-safe order."""

    assert_demo_reset_allowed(settings)
    for table in (
        AuditRecordRow,
        AnalystNoteRecord,
        PlaybookRunRecord,
        IncidentRecord,
        AlertRecord,
        EventRecord,
    ):
        session.execute(delete(table))
    session.flush()


def _updated(
    events: Iterable[NormalizedEvent],
    *,
    correlation_id: str,
    host: str | None = None,
    user: str | None = None,
) -> list[NormalizedEvent]:
    return [
        event.model_copy(
            update={
                "correlation_id": correlation_id,
                **({"host": host} if host else {}),
                **({"user": user} if user else {}),
            }
        )
        for event in events
    ]


def generate_demo_scenarios() -> list[NormalizedEvent]:
    """Build all positive fixtures with three explainable correlation stories."""

    positive = {rule_id: pair[0] for rule_id, pair in scenario_fixtures().items()}

    # Identity story: one sprayed account is subsequently accessed successfully.
    identity_spray = [
        event.model_copy(update={"user": "alex.morgan@example.test"}) if index == 0 else event
        for index, event in enumerate(positive["SF-001"])
    ]
    identity_events = _updated(
        [*identity_spray, *positive["SF-002"]], correlation_id="corr-demo-identity-chain"
    )

    # Endpoint story: suspicious PowerShell and periodic outbound sessions share a device.
    endpoint_events = _updated(
        [*positive["SF-005"], *positive["SF-012"]],
        correlation_id="corr-demo-powershell-beacon",
        host="ws-417.sentinelforge.test",
        user="casey.lee@example.test",
    )

    independent_profiles: dict[str, tuple[str | None, str]] = {
        "SF-003": ("idn-303.sentinelforge.test", "travel.user@example.test"),
        "SF-004": ("idn-404.sentinelforge.test", "mfa.user@example.test"),
        "SF-006": ("ws-606.sentinelforge.test", "endpoint.user@example.test"),
        "SF-007": ("dc-701.sentinelforge.test", "directory.user@example.test"),
        # Preserve the three distinct RDP destination hosts from the fixture.
        "SF-008": (None, "rdp.user@example.test"),
        "SF-009": ("ws-909.sentinelforge.test", "remote.user@example.test"),
        "SF-010": ("ws-810.sentinelforge.test", "dns.user@example.test"),
        "SF-011": ("cloud-111.sentinelforge.test", "aws.user@example.test"),
    }
    independent_events = [
        event
        for rule_id, (host, user) in independent_profiles.items()
        for event in _updated(
            positive[rule_id],
            correlation_id=f"corr-demo-{rule_id.lower()}",
            host=host,
            user=user,
        )
    ]
    return sorted(
        [*identity_events, *endpoint_events, *independent_events],
        key=lambda event: event.timestamp,
    )


def run_demo(settings: Settings | None = None) -> tuple[int, int, list[str]]:
    """Reset, ingest, evaluate, correlate, and return actual demo results."""

    configured = settings or Settings()
    assert_demo_reset_allowed(configured)
    database = Database(configured.database_url)
    database.create_schema()
    with database.session_factory.begin() as session:
        reset_demo_data(session, configured)
        events = [*generate_baseline(events_per_source=4), *generate_demo_scenarios()]
        ingest_events(session, events)
        result = evaluate_and_correlate(session)
        incidents = list_incidents(session)
        incident_lines = [
            f"{incident.incident_id} | {incident.severity.value.upper():8} | "
            f"{incident.title}"
            for incident in incidents
        ]
    return result.alerts_created, result.incidents_created, incident_lines


def main() -> None:
    alerts, incidents, incident_lines = run_demo()
    print("SentinelForge synthetic demo is ready.")
    print(f"Created {alerts} alerts and {incidents} correlated incidents.")
    print("Expected incidents now visible:")
    for line in incident_lines:
        print(f"  {line}")
    print(f"Dashboard: {DASHBOARD_URL}")


if __name__ == "__main__":
    main()
