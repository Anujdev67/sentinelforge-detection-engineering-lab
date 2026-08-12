"""Safe playbook definitions and deterministic execution functions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

PlaybookExecutor = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class PlaybookDefinition:
    playbook_id: str
    title: str
    description: str
    requires_approval: bool
    executor: PlaybookExecutor


def _base_output() -> dict[str, Any]:
    return {
        "simulated": True,
        "external_actions_performed": False,
        "safety_notice": (
            "Local simulation only; no identity, endpoint, network, or cloud resource was changed."
        ),
    }


def suspicious_identity(context: dict[str, Any]) -> dict[str, Any]:
    output = _base_output()
    entities = context.get("entities", {})
    output.update(
        {
            "accounts_reviewed": entities.get("account", []),
            "source_ips_reviewed": entities.get("ip", []),
            "investigation_context": [
                "Compare sign-in failures, MFA outcomes, devices, locations, and applications.",
                "Validate successful sessions with the fictional identity owner.",
                "Review nearby directory, mailbox, and cloud control-plane activity.",
            ],
            "containment_recommendations": [
                "Consider session revocation after identity-owner and analyst confirmation.",
                "Consider a credential reset if evidence supports account compromise.",
            ],
        }
    )
    return output


def remote_access_tool(context: dict[str, Any]) -> dict[str, Any]:
    output = _base_output()
    entities = context.get("entities", {})
    output.update(
        {
            "hosts_reviewed": entities.get("host", []),
            "processes_reviewed": entities.get("process", []),
            "investigation_context": [
                "Validate signer, hash, parent process, install source, and support approval.",
                "Review remote sessions, network destinations, file transfer, and persistence.",
            ],
            "containment_recommendations": [
                (
                    "Consider endpoint isolation only if the support session is confirmed "
                    "unauthorized."
                ),
                "Preserve process and network evidence before removing remote-access software.",
            ],
        }
    )
    return output


def ioc_enrichment(context: dict[str, Any]) -> dict[str, Any]:
    output = _base_output()
    input_data = context.get("input_data", {})
    indicators = input_data.get("indicators", [])
    if not isinstance(indicators, list):
        indicators = []
    enrichment: list[dict[str, Any]] = []
    for raw_indicator in indicators[:50]:
        indicator = str(raw_indicator)
        score = int(sha256(indicator.encode(), usedforsecurity=False).hexdigest()[:2], 16) % 101
        enrichment.append(
            {
                "indicator": indicator,
                "provider": "sentinelforge-deterministic-mock",
                "risk_score": score,
                "classification": "review" if score >= 50 else "low-context",
                "network_lookup_performed": False,
            }
        )
    output["enrichment"] = enrichment
    return output


def high_severity_notification(context: dict[str, Any]) -> dict[str, Any]:
    output = _base_output()
    output.update(
        {
            "delivery_target": "local-audit-sink",
            "delivered_externally": False,
            "notification_preview": (
                f"SIMULATION: {context.get('severity', 'unknown').upper()} incident "
                f"{context.get('incident_id', 'unknown')} requires analyst review."
            ),
        }
    )
    return output


def evidence_package(context: dict[str, Any]) -> dict[str, Any]:
    output = _base_output()
    output.update(
        {
            "package_format": "application/json",
            "manifest": {
                "incident_id": context.get("incident_id"),
                "alert_ids": context.get("alert_ids", []),
                "entities": context.get("entities", {}),
                "evidence_event_ids": context.get("evidence_event_ids", []),
                "notes": context.get("notes", []),
                "provenance": "synthetic SentinelForge records only",
            },
        }
    )
    return output


PLAYBOOKS: dict[str, PlaybookDefinition] = {
    "suspicious-identity-investigation": PlaybookDefinition(
        playbook_id="suspicious-identity-investigation",
        title="Suspicious identity investigation",
        description="Assemble identity context and human-reviewed containment recommendations.",
        requires_approval=True,
        executor=suspicious_identity,
    ),
    "remote-access-tool-investigation": PlaybookDefinition(
        playbook_id="remote-access-tool-investigation",
        title="Malware or remote-access-tool investigation",
        description="Assemble endpoint process, host, and network investigation context.",
        requires_approval=True,
        executor=remote_access_tool,
    ),
    "ioc-enrichment": PlaybookDefinition(
        playbook_id="ioc-enrichment",
        title="IOC enrichment",
        description="Enrich documentation-safe indicators using deterministic offline mock data.",
        requires_approval=True,
        executor=ioc_enrichment,
    ),
    "high-severity-notification": PlaybookDefinition(
        playbook_id="high-severity-notification",
        title="High-severity notification",
        description=(
            "Create a notification preview in the local audit sink without sending a message."
        ),
        requires_approval=True,
        executor=high_severity_notification,
    ),
    "incident-evidence-package": PlaybookDefinition(
        playbook_id="incident-evidence-package",
        title="Incident evidence packaging",
        description="Create a synthetic JSON evidence manifest from persisted incident records.",
        requires_approval=True,
        executor=evidence_package,
    ),
}
