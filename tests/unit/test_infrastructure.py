"""Structural tests for safe IaC and Logic Apps documentation artifacts."""

from pathlib import Path

from scripts.validate_content import ROOT, validate


def test_repository_content_validation_passes() -> None:
    result = validate()
    assert result["detections"] == 12
    assert result["sigma_rules"] >= 6
    assert result["logic_app_artifacts"] == 5


def test_terraform_has_no_embedded_cloud_identity_or_state() -> None:
    terraform_root = ROOT / "infrastructure" / "terraform"
    content = "\n".join(
        path.read_text(encoding="utf-8")
        for path in terraform_root.rglob("*")
        if path.is_file() and (path.suffix == ".tf" or path.name.endswith(".tfvars.example"))
    ).casefold()

    assert "tenant_id =" not in content
    assert "subscription_id =" not in content
    assert not list(terraform_root.rglob("*.tfstate*"))
    assert ".terraform/" in (ROOT / ".gitignore").read_text(encoding="utf-8")


def test_logic_app_artifacts_are_explicitly_non_deployable() -> None:
    artifacts = list((ROOT / "soar" / "logic-app-templates").glob("*.json"))
    for artifact in artifacts:
        text = artifact.read_text(encoding="utf-8")
        assert '"deployable": false' in text
        assert '"required": true' in text


def test_example_variable_file_contains_no_uuid() -> None:
    example = Path(ROOT / "infrastructure" / "terraform" / "terraform.tfvars.example")
    assert "00000000-" not in example.read_text(encoding="utf-8")
