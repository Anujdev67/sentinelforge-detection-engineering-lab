"""Detection-as-code metadata, KQL, Sigma, and regression gates."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from sigma.collection import SigmaCollection

from detections.loader import DetectionPack, load_detection_packs
from detections.quality import build_quality_snapshot
from evaluators.engine import EVALUATORS, alert_regression_view, evaluate_rule
from telemetry.models import NormalizedEvent

ROOT = Path(__file__).parents[2]
RULE_SCHEMA = json.loads(
    (ROOT / "detections/schemas/detection-rule.schema.json").read_text(encoding="utf-8")
)
EVENT_SCHEMA = json.loads(
    (ROOT / "telemetry/schemas/normalized-event.schema.json").read_text(encoding="utf-8")
)
EXPECTED_SCHEMA = json.loads(
    (ROOT / "detections/schemas/expected-alert.schema.json").read_text(encoding="utf-8")
)


@pytest.fixture(scope="module")
def packs() -> list[DetectionPack]:
    return load_detection_packs()


def _fixture(pack: DetectionPack, name: str) -> list[NormalizedEvent]:
    raw = json.loads((pack.path / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))
    Draft202012Validator(EVENT_SCHEMA, format_checker=FormatChecker()).validate(raw[0])
    return [NormalizedEvent.model_validate(item) for item in raw]


def test_library_contains_twelve_unique_rules(packs: list[DetectionPack]) -> None:
    rule_ids = [pack.metadata.rule_id for pack in packs]
    assert len(packs) == 12
    assert len(rule_ids) == len(set(rule_ids))
    assert rule_ids == [f"SF-{number:03d}" for number in range(1, 13)]


def test_metadata_matches_json_schema_and_registered_evaluator(packs: list[DetectionPack]) -> None:
    validator = Draft202012Validator(RULE_SCHEMA, format_checker=FormatChecker())
    for pack in packs:
        raw_metadata = pack.metadata.model_dump(mode="json")
        validator.validate(raw_metadata)
        assert pack.metadata.evaluator in EVALUATORS
        assert pack.metadata.changelog[0].version == pack.metadata.version
        assert len(pack.metadata.investigation_steps) >= 2
        assert pack.metadata.known_false_positives
        assert pack.metadata.containment_recommendations


def test_kql_is_non_empty_time_bounded_and_structurally_sound(packs: list[DetectionPack]) -> None:
    forbidden_markers = re.compile(r"\b(?:TODO|FIXME|PLACEHOLDER)\b", re.IGNORECASE)
    for pack in packs:
        query = pack.kql
        assert len(query) >= 200, pack.metadata.rule_id
        assert "ago(" in query, pack.metadata.rule_id
        assert query.count("|") >= 3, pack.metadata.rule_id
        assert query.count("(") == query.count(")"), pack.metadata.rule_id
        assert not forbidden_markers.search(query), pack.metadata.rule_id
        for source in pack.metadata.required_data_sources:
            assert source.value in query, (
                f"{pack.metadata.rule_id} does not reference {source.value}"
            )


def test_at_least_six_sigma_rules_parse_with_pysigma(packs: list[DetectionPack]) -> None:
    sigma_packs = [pack for pack in packs if pack.metadata.sigma_file]
    assert len(sigma_packs) >= 6
    sigma_ids: set[str] = set()
    for pack in sigma_packs:
        sigma_path = pack.path / str(pack.metadata.sigma_file)
        collection = SigmaCollection.from_yaml(sigma_path.read_text(encoding="utf-8"))
        assert len(collection.rules) == 1
        sigma_id = str(collection.rules[0].id)
        assert sigma_id not in sigma_ids
        sigma_ids.add(sigma_id)


@pytest.mark.detection
@pytest.mark.parametrize("rule_id", [f"SF-{number:03d}" for number in range(1, 13)])
def test_positive_and_negative_fixture_regression(rule_id: str, packs: list[DetectionPack]) -> None:
    pack = next(candidate for candidate in packs if candidate.metadata.rule_id == rule_id)
    positive_alerts = evaluate_rule(_fixture(pack, "positive"), pack.metadata)
    negative_alerts = evaluate_rule(_fixture(pack, "negative"), pack.metadata)
    expected_path = pack.path / "expected-alert.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    Draft202012Validator(EXPECTED_SCHEMA).validate(expected)

    assert len(positive_alerts) == expected["alert_count"] == 1
    assert alert_regression_view(positive_alerts[0]) == expected
    assert negative_alerts == []


def test_quality_snapshot_is_derived_from_current_fixtures() -> None:
    validated_at = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
    quality = build_quality_snapshot(validated_at)

    assert quality.total_detections == 12
    assert quality.positive_tests_passed == 12
    assert quality.negative_tests_passed == 12
    assert quality.sigma_rule_count == 7
    assert len(quality.attack_coverage) >= 10
    assert len(quality.covered_data_sources) >= 7
    assert quality.rules_requiring_tuning >= 1
    assert quality.last_validation_time == validated_at
