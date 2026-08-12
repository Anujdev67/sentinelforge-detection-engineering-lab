"""Rule-quality snapshot derived from live content and fixture evaluation."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from detections.loader import DetectionPack, load_detection_packs
from evaluators.engine import evaluate_rule
from telemetry.models import NormalizedEvent


class RuleQualityResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    positive_passed: bool
    negative_passed: bool


class RuleQualitySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_detections: int = Field(ge=0)
    positive_tests_passed: int = Field(ge=0)
    negative_tests_passed: int = Field(ge=0)
    attack_coverage: list[str]
    covered_data_sources: list[str]
    rules_by_severity: dict[str, int]
    rules_requiring_tuning: int = Field(ge=0)
    sigma_rule_count: int = Field(ge=0)
    last_validation_time: datetime
    rules: list[RuleQualityResult]


def _events(pack: DetectionPack, fixture_name: str) -> list[NormalizedEvent]:
    raw = json.loads((pack.path / "fixtures" / f"{fixture_name}.json").read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"fixture must be a list: {pack.path}/{fixture_name}.json")
    return [NormalizedEvent.model_validate(item) for item in raw]


def build_quality_snapshot(validated_at: datetime | None = None) -> RuleQualitySnapshot:
    """Evaluate all committed fixtures and aggregate operational quality metrics."""

    packs = load_detection_packs()
    results: list[RuleQualityResult] = []
    attack_coverage: set[str] = set()
    sources: set[str] = set()
    severity_counter: Counter[str] = Counter()

    for pack in packs:
        positive_passed = len(evaluate_rule(_events(pack, "positive"), pack.metadata)) == 1
        negative_passed = len(evaluate_rule(_events(pack, "negative"), pack.metadata)) == 0
        results.append(
            RuleQualityResult(
                rule_id=pack.metadata.rule_id,
                positive_passed=positive_passed,
                negative_passed=negative_passed,
            )
        )
        attack_coverage.update(mapping.technique for mapping in pack.metadata.mitre_attack)
        sources.update(source.value for source in pack.metadata.required_data_sources)
        severity_counter[pack.metadata.severity.value] += 1

    timestamp = validated_at or datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise ValueError("validated_at must be timezone-aware")
    return RuleQualitySnapshot(
        total_detections=len(packs),
        positive_tests_passed=sum(result.positive_passed for result in results),
        negative_tests_passed=sum(result.negative_passed for result in results),
        attack_coverage=sorted(attack_coverage),
        covered_data_sources=sorted(sources),
        rules_by_severity=dict(sorted(severity_counter.items())),
        rules_requiring_tuning=sum(pack.metadata.tuning_required for pack in packs),
        sigma_rule_count=sum(pack.metadata.sigma_file is not None for pack in packs),
        last_validation_time=timestamp.astimezone(UTC),
        rules=results,
    )


def quality_snapshot_json(validated_at: datetime | None = None) -> dict[str, Any]:
    """Return a JSON-compatible quality view for API and CLI consumers."""

    return build_quality_snapshot(validated_at).model_dump(mode="json")
