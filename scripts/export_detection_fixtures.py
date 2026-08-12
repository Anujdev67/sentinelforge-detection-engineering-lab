"""Rebuild committed detection fixtures and expected-alert snapshots.

This is an explicit maintainer command, not part of CI. Review every generated
snapshot so behavior changes cannot silently approve themselves.
"""

from __future__ import annotations

import json
from pathlib import Path

from detections.loader import load_detection_packs
from evaluators.engine import alert_regression_view, evaluate_rule
from telemetry.generators.scenarios import scenario_fixtures

ROOT = Path(__file__).parents[1]


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    fixtures = scenario_fixtures()
    for pack in load_detection_packs():
        positive, negative = fixtures[pack.metadata.rule_id]
        positive_alerts = evaluate_rule(positive, pack.metadata)
        if len(positive_alerts) != 1:
            raise RuntimeError(
                f"{pack.metadata.rule_id} produced {len(positive_alerts)} positive alerts"
            )
        if evaluate_rule(negative, pack.metadata):
            raise RuntimeError(f"{pack.metadata.rule_id} negative fixture produced an alert")
        _write(
            pack.path / "fixtures" / "positive.json",
            [event.model_dump(mode="json") for event in positive],
        )
        _write(
            pack.path / "fixtures" / "negative.json",
            [event.model_dump(mode="json") for event in negative],
        )
        _write(pack.path / "expected-alert.json", alert_regression_view(positive_alerts[0]))
    print(f"Exported fixtures for {len(fixtures)} detection packs.")


if __name__ == "__main__":
    main()
