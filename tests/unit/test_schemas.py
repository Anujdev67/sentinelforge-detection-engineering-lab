"""Ensure committed schemas describe current Pydantic contracts."""

import json
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator, FormatChecker

from telemetry.generators import generate_baseline

ROOT = Path(__file__).parents[2]


def _schema(path: str) -> dict[str, object]:
    payload = json.loads((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"schema must be a JSON object: {path}")
    return cast(dict[str, object], payload)


def test_committed_schemas_are_valid_draft_2020_12() -> None:
    for path in (
        "detections/schemas/detection-rule.schema.json",
        "detections/schemas/expected-alert.schema.json",
        "telemetry/schemas/normalized-event.schema.json",
    ):
        Draft202012Validator.check_schema(_schema(path))


def test_generated_events_validate_against_json_schema() -> None:
    validator = Draft202012Validator(
        _schema("telemetry/schemas/normalized-event.schema.json"),
        format_checker=FormatChecker(),
    )
    for event in generate_baseline(events_per_source=1):
        validator.validate(event.model_dump(mode="json"))
