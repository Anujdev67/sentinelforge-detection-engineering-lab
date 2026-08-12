"""End-to-end local SOC workflow through public API endpoints."""

from typing import Any, cast

from fastapi.testclient import TestClient

from telemetry.generators import generate_baseline
from telemetry.generators.scenarios import generate_attack_scenarios


def _seed_demo(client: TestClient) -> dict[str, Any]:
    events = generate_baseline(events_per_source=1) + generate_attack_scenarios()
    payload = {"events": [event.model_dump(mode="json") for event in events]}
    ingest = client.post("/api/v1/events/ingest", json=payload)
    assert ingest.status_code == 201
    assert ingest.json()["accepted"] == len(events)
    evaluation = client.post("/api/v1/detections/evaluate")
    assert evaluation.status_code == 200
    assert evaluation.json()["alerts_created"] == 12
    assert evaluation.json()["incidents_created"] >= 1
    return cast(dict[str, Any], evaluation.json())


def test_ingestion_detection_correlation_and_incident_detail(client: TestClient) -> None:
    result = _seed_demo(client)

    duplicate = client.post(
        "/api/v1/events/ingest",
        json={"events": [generate_baseline(events_per_source=1)[0].model_dump(mode="json")]},
    )
    assert duplicate.status_code == 201
    assert duplicate.json() == {"accepted": 0, "duplicates": 1}

    alerts = client.get("/api/v1/alerts")
    assert alerts.status_code == 200
    assert len(alerts.json()) == 12
    assert all(alert["evidence_event_ids"] for alert in alerts.json())

    incidents = client.get("/api/v1/incidents")
    assert incidents.status_code == 200
    assert len(incidents.json()) == result["incidents_created"]
    incident_id = incidents.json()[0]["incident_id"]

    detail = client.get(f"/api/v1/incidents/{incident_id}")
    assert detail.status_code == 200
    assert detail.json()["alerts"]
    assert detail.json()["timeline"]
    assert detail.json()["investigation_checklist"]
    assert detail.json()["recommended_containment"]

    update = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "active", "assigned_to": "analyst.one@example.test"},
    )
    assert update.status_code == 200
    assert update.json()["status"] == "active"
    assert update.json()["assigned_to"] == "analyst.one@example.test"

    note = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"author": "analyst.one@example.test", "body": "Validated synthetic evidence chain."},
    )
    assert note.status_code == 201
    assert note.json()["note_id"] >= 1

    refreshed = client.get(f"/api/v1/incidents/{incident_id}")
    assert refreshed.json()["notes"][0]["body"] == "Validated synthetic evidence chain."


def test_filters_metrics_detection_library_hunts_and_coverage(client: TestClient) -> None:
    _seed_demo(client)

    health = client.get("/api/v1/health")
    assert health.json() == {
        "status": "ok",
        "database": "ready",
        "mode": "synthetic-local-simulation",
    }

    filtered = client.get("/api/v1/incidents", params={"rule_id": "SF-005"})
    assert filtered.status_code == 200
    assert filtered.json()

    overview = client.get("/api/v1/overview").json()
    assert overview["total_events"] > 20
    assert overview["total_alerts"] == 12
    assert overview["mean_detection_latency_ms"] == 250.0
    assert overview["incidents_by_severity"]

    library = client.get("/api/v1/detections").json()
    assert len(library) == 12
    assert all(rule["kql"] for rule in library)
    assert all("not a KQL execution engine" in rule["local_evaluator_notice"] for rule in library)

    quality = client.get("/api/v1/quality").json()
    assert quality["positive_tests_passed"] == 12
    assert quality["negative_tests_passed"] == 12

    coverage = client.get("/api/v1/attack-coverage").json()
    assert coverage["framework"]["version"] == "19.1"
    assert coverage["summary"]["total_tactics"] == 15
    assert any(
        tactic["tactic_id"] == "TA0005" and tactic["tactic_name"] == "Stealth"
        for tactic in coverage["tactics"]
    )
    assert any(
        tactic["tactic_id"] == "TA0112" and tactic["gap"]
        for tactic in coverage["tactics"]
    )
    assert any(tactic["covered"] for tactic in coverage["tactics"])
    assert any(tactic["gap"] for tactic in coverage["tactics"])
    assert coverage["techniques"]
    assert all(technique["data_sources"] for technique in coverage["techniques"])

    navigator = client.get("/api/v1/attack-coverage/navigator-layer")
    assert navigator.status_code == 200
    assert navigator.json()["domain"] == "enterprise-attack"
    assert navigator.json()["versions"]["attack"] == "19.1"
    assert navigator.json()["techniques"]

    analytics = client.get("/api/v1/analytics")
    assert analytics.status_code == 200
    analytics_body = analytics.json()
    assert analytics_body["total_events"] == overview["total_events"]
    assert analytics_body["total_alerts"] == 12
    assert analytics_body["total_incidents"] > 0
    assert analytics_body["alert_to_incident_ratio"] > 0
    assert len(analytics_body["rules"]) == 12
    assert analytics_body["entity_risk"]
    assert analytics_body["daily_activity"]

    hunts = client.get("/api/v1/hunts").json()
    assert len(hunts) == 3
    hunt = client.post(
        f"/api/v1/hunts/{hunts[0]['hunt_id']}/run",
        json={"data_source": hunts[0]["data_sources"][0], "limit": 20},
    )
    assert hunt.status_code == 200
    assert "Analyst conclusion: pending review." in hunt.json()["investigation_notes"]


def test_playbook_requires_separate_approval_and_remains_simulated(client: TestClient) -> None:
    _seed_demo(client)
    incident_id = client.get("/api/v1/incidents").json()[0]["incident_id"]

    playbooks = client.get("/api/v1/playbooks").json()
    assert len(playbooks) == 5
    assert all(item["requires_approval"] and item["simulation_only"] for item in playbooks)

    requested = client.post(
        f"/api/v1/incidents/{incident_id}/playbooks/ioc-enrichment/request",
        json={
            "requested_by": "analyst.one@example.test",
            "input_data": {
                "indicators": ["198.51.100.44", "synthetic-hash-001"],
                "simulate_containment": True,
            },
        },
    )
    assert requested.status_code == 201
    run_id = requested.json()["run_id"]
    assert requested.json()["status"] == "pending_approval"

    bypass = client.post(
        f"/api/v1/playbook-runs/{run_id}/execute",
        json={"executed_by": "analyst.one@example.test"},
    )
    assert bypass.status_code == 409

    self_approval = client.post(
        f"/api/v1/playbook-runs/{run_id}/approve",
        json={"approved_by": "analyst.one@example.test"},
    )
    assert self_approval.status_code == 409

    approval = client.post(
        f"/api/v1/playbook-runs/{run_id}/approve",
        json={"approved_by": "analyst.two@example.test"},
    )
    assert approval.status_code == 200
    assert approval.json()["status"] == "approved"

    execution = client.post(
        f"/api/v1/playbook-runs/{run_id}/execute",
        json={"executed_by": "analyst.one@example.test"},
    )
    assert execution.status_code == 200
    output = execution.json()["output_data"]
    assert execution.json()["status"] == "simulated_completed"
    assert output["simulated"] is True
    assert output["external_actions_performed"] is False
    assert all(item["network_lookup_performed"] is False for item in output["enrichment"])

    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["incident"]["status"] == "contained_simulated"

    audit = client.get(f"/api/v1/incidents/{incident_id}/audit").json()
    assert [item["action"] for item in audit] == [
        "playbook_requested",
        "playbook_approved",
        "playbook_executed",
    ]
    assert all(item["simulated"] is True for item in audit)


def test_reputation_lookup_is_safe_cached_and_auditable(client: TestClient) -> None:
    providers = client.get("/api/v1/reputation/providers")
    assert providers.status_code == 200
    provider_rows = providers.json()
    assert {row["provider"] for row in provider_rows} == {
        "synthetic",
        "virustotal",
        "abuseipdb",
        "greynoise",
    }
    synthetic = next(row for row in provider_rows if row["provider"] == "synthetic")
    assert synthetic["enabled"] is True
    assert synthetic["live"] is False

    request = {
        "observable": "203.0.113.77",
        "observable_type": "ip",
        "providers": ["synthetic"],
        "requested_by": "analyst.one@example.test",
    }
    first = client.post("/api/v1/reputation/lookup", json=request)
    assert first.status_code == 200
    body = first.json()
    assert body["observable"] == "203.0.113.77"
    assert body["live_connectors_used"] is False
    assert body["results"][0]["provider"] == "synthetic"
    assert body["results"][0]["cache_hit"] is False
    assert body["results"][0]["details"]["simulation"] is True
    assert "no containment action" in body["analyst_notice"]

    second = client.post("/api/v1/reputation/lookup", json=request)
    assert second.status_code == 200
    assert second.json()["results"][0]["cache_hit"] is True
    assert second.json()["results"][0]["lookup_id"] == body["results"][0]["lookup_id"]

    history = client.get(
        "/api/v1/reputation/history", params={"observable": "203.0.113.77"}
    )
    assert history.status_code == 200
    assert len(history.json()) == 1
    assert history.json()[0]["requested_by"] == "analyst.one@example.test"

    live_disabled = client.post(
        "/api/v1/reputation/lookup",
        json={**request, "observable": "203.0.113.8", "providers": ["virustotal"]},
    )
    assert live_disabled.status_code == 422
    assert "disabled" in live_disabled.json()["detail"]

    rejected_url = client.post(
        "/api/v1/reputation/lookup",
        json={**request, "observable": "http://internal.example/path"},
    )
    assert rejected_url.status_code == 422
    assert "bare IP address or domain" in rejected_url.json()["detail"]
