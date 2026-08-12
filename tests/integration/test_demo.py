"""Safety and outcome tests for the local demo workflow."""

from pathlib import Path

import pytest

from apps.api.sentinelforge_api.config import Settings
from scripts.demo import UnsafeDemoResetError, run_demo


def test_demo_reset_refuses_non_demo_mode(tmp_path: Path) -> None:
    settings = Settings(
        demo_mode=False,
        database_url=f"sqlite:///{tmp_path / 'sentinelforge-demo.db'}",
    )
    with pytest.raises(UnsafeDemoResetError, match="DEMO_MODE"):
        run_demo(settings)


def test_demo_reset_refuses_wrong_database_name(tmp_path: Path) -> None:
    settings = Settings(
        demo_mode=True,
        database_url=f"sqlite:///{tmp_path / 'application.db'}",
    )
    with pytest.raises(UnsafeDemoResetError, match="target must be"):
        run_demo(settings)


@pytest.mark.integration
def test_demo_creates_all_expected_alerts(tmp_path: Path) -> None:
    settings = Settings(
        demo_mode=True,
        database_url=f"sqlite:///{tmp_path / 'sentinelforge-demo.db'}",
    )
    alert_count, incident_count, incident_lines = run_demo(settings)

    assert alert_count == 12
    assert 1 <= incident_count <= alert_count
    assert len(incident_lines) == incident_count
    assert any("Correlated activity across 2 alerts" in line for line in incident_lines)
