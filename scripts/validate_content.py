"""Repository-native content validation used locally and in CI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from detections.loader import load_detection_packs
from detections.quality import build_quality_snapshot

ROOT = Path(__file__).resolve().parents[1]


class ContentValidationError(RuntimeError):
    """Raised when repository content is structurally invalid."""


def _validate_logic_app_artifacts() -> int:
    directory = ROOT / "soar" / "logic-app-templates"
    artifacts = sorted(directory.glob("*.json"))
    if len(artifacts) != 5:
        raise ContentValidationError(f"expected 5 Logic Apps artifacts, found {len(artifacts)}")
    required = {
        "artifact_type",
        "artifact_version",
        "name",
        "deployable",
        "simulation_notice",
        "trigger",
        "approval_gate",
        "steps",
        "forbidden_actions",
        "audit",
    }
    for path in artifacts:
        payload = json.loads(path.read_text(encoding="utf-8"))
        missing = required.difference(payload)
        if missing:
            raise ContentValidationError(f"{path.name} missing keys: {sorted(missing)}")
        if payload["deployable"] is not False:
            raise ContentValidationError(f"{path.name} must remain non-deployable")
        if payload["approval_gate"].get("required") is not True:
            raise ContentValidationError(f"{path.name} must require approval")
        if not payload["steps"]:
            raise ContentValidationError(f"{path.name} has no documented workflow steps")
    return len(artifacts)


def _validate_yaml_and_json() -> tuple[int, int]:
    yaml_files = [
        ROOT / "docker-compose.yml",
        *sorted((ROOT / ".github" / "workflows").glob("*.yml")),
        *sorted((ROOT / "detections" / "rules").glob("*/metadata.yml")),
        *sorted((ROOT / "detections" / "rules").glob("*/rule.yml")),
    ]
    json_files = [
        ROOT / "apps" / "dashboard" / "package.json",
        *sorted((ROOT / "detections" / "rules").glob("*/fixtures/*.json")),
        *sorted((ROOT / "detections" / "rules").glob("*/expected-alert.json")),
        *sorted((ROOT / "detections" / "schemas").glob("*.json")),
        *sorted((ROOT / "telemetry" / "schemas").glob("*.json")),
    ]
    for path in yaml_files:
        if not path.is_file():
            raise ContentValidationError(f"missing YAML file: {path.relative_to(ROOT)}")
        if yaml.safe_load(path.read_text(encoding="utf-8")) is None:
            raise ContentValidationError(f"empty YAML document: {path.relative_to(ROOT)}")
    for path in json_files:
        if not path.is_file():
            raise ContentValidationError(f"missing JSON file: {path.relative_to(ROOT)}")
        json.loads(path.read_text(encoding="utf-8"))
    return len(yaml_files), len(json_files)


def _validate_terraform_references() -> int:
    terraform_root = ROOT / "infrastructure" / "terraform"
    required = {
        "versions.tf",
        "providers.tf",
        "variables.tf",
        "locals.tf",
        "main.tf",
        "outputs.tf",
        "terraform.tfvars.example",
    }
    missing = [name for name in required if not (terraform_root / name).is_file()]
    if missing:
        raise ContentValidationError(f"missing Terraform files: {missing}")
    locals_text = (terraform_root / "locals.tf").read_text(encoding="utf-8")
    references = locals_text.count("query.kql\")")
    if references != 12:
        raise ContentValidationError(
            f"Terraform must reference 12 authoritative KQL files, found {references}"
        )
    all_terraform = "\n".join(
        path.read_text(encoding="utf-8") for path in terraform_root.rglob("*.tf")
    )
    forbidden_commands = ("terraform apply", "auto-approve")
    if any(command in all_terraform.casefold() for command in forbidden_commands):
        raise ContentValidationError("Terraform artifacts contain a deployment command")
    return len(list(terraform_root.rglob("*.tf")))


def validate() -> dict[str, Any]:
    """Validate detection, structured content, IaC references, and safety gates."""

    quality = build_quality_snapshot()
    if not all(rule.positive_passed and rule.negative_passed for rule in quality.rules):
        raise ContentValidationError("one or more detection fixture gates failed")
    packs = load_detection_packs()
    if len(packs) != 12:
        raise ContentValidationError(f"expected 12 detection packs, found {len(packs)}")
    sigma_count = sum(pack.sigma is not None for pack in packs)
    if sigma_count < 6:
        raise ContentValidationError(f"expected at least 6 Sigma rules, found {sigma_count}")
    yaml_count, json_count = _validate_yaml_and_json()
    return {
        "detections": len(packs),
        "sigma_rules": sigma_count,
        "positive_tests_passed": quality.positive_tests_passed,
        "negative_tests_passed": quality.negative_tests_passed,
        "logic_app_artifacts": _validate_logic_app_artifacts(),
        "terraform_files": _validate_terraform_references(),
        "yaml_files": yaml_count,
        "json_files": json_count,
    }


def main() -> None:
    result = validate()
    print("SentinelForge content validation passed")
    for label, value in result.items():
        print(f"  {label.replace('_', ' ')}: {value}")


if __name__ == "__main__":
    main()
