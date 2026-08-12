"""Security hardening regression gates."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from apps.api.sentinelforge_api.config import Settings
from scripts.create_env import create_env

REPOSITORY_ROOT = Path(__file__).parents[2]
ACTION_REFERENCE = re.compile(r"^\s*-\s+uses:\s+([^@\s]+)@([^\s#]+)", re.MULTILINE)
IMMUTABLE_SHA = re.compile(r"^[0-9a-f]{40}$")


def test_remote_github_actions_are_immutable() -> None:
    findings: list[str] = []
    for workflow in sorted((REPOSITORY_ROOT / ".github" / "workflows").glob("*.yml")):
        content = workflow.read_text(encoding="utf-8")
        for action, reference in ACTION_REFERENCE.findall(content):
            if not action.startswith("./") and not IMMUTABLE_SHA.fullmatch(reference):
                findings.append(f"{workflow.name}:{action}@{reference}")
    assert not findings, f"mutable GitHub Action references found: {findings}"


def test_compose_publishes_local_services_on_loopback_only() -> None:
    compose = yaml.safe_load((REPOSITORY_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for service_name in ("api", "dashboard"):
        service = compose["services"][service_name]
        assert all(str(port).startswith("127.0.0.1:") for port in service["ports"])
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["read_only"] is True


def test_cors_and_host_configuration_rejects_wildcards() -> None:
    assert Settings(cors_origins="https://soc.example.test").cors_origin_list == [
        "https://soc.example.test"
    ]
    with pytest.raises(ValueError, match="Unsafe CORS"):
        _ = Settings(cors_origins="*").cors_origin_list
    with pytest.raises(ValueError, match="must use HTTPS"):
        _ = Settings(cors_origins="http://soc.example.test").cors_origin_list
    with pytest.raises(ValueError, match="Allowed hosts"):
        _ = Settings(allowed_hosts="*").allowed_host_list


def test_local_environment_generator_uses_a_random_password(tmp_path: Path) -> None:
    example = tmp_path / ".env.example"
    output = tmp_path / ".env"
    example.write_text(
        "SENTINELFORGE_DATABASE_URL=postgresql://user:change-me-locally@db/demo\n"
        "POSTGRES_PASSWORD=change-me-locally\n",
        encoding="utf-8",
    )

    assert create_env(example, output) is True
    rendered = output.read_text(encoding="utf-8")
    assert _PASSWORD_PLACEHOLDER not in rendered
    password = rendered.split("POSTGRES_PASSWORD=", maxsplit=1)[1].strip()
    assert len(password) == 48
    assert f":{password}@db/demo" in rendered
    assert create_env(example, output) is False


_PASSWORD_PLACEHOLDER = "change-me-locally"
