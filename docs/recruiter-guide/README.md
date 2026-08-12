# Recruiter guide

## What to inspect in five minutes

1. Run the guarded demo and open SOC Overview.
2. Open the identity incident and follow two alerts into one entity timeline.
3. Open Detection Library and compare KQL, Sigma, metadata, false positives, and fixture status.
4. Open Rule Quality and ATT&CK Coverage to see automated assurance and explicit gaps.
5. Open an incident playbook, request it, approve with a different analyst, execute, and inspect the local audit trail.

## Evidence map

| Capability | Repository evidence |
| --- | --- |
| Detection engineering | `detections/rules`, expected alerts, quality tests |
| KQL / Sentinel | 12 authoritative `query.kql` files and Terraform mappings |
| Sigma | Seven validated portable rule files |
| Python platform | evaluators, generators, FastAPI services, Pytest |
| Incident response | correlation, evidence timeline, notes, five safe playbooks |
| Full-stack | typed React dashboard connected to live API endpoints |
| Detection-as-code | metadata schemas, positive/negative regression gates, GitHub Actions |
| Azure security | Sentinel/Log Analytics Terraform and Logic Apps mappings |

## 90-second demo script

“SentinelForge is a local-first Microsoft Sentinel detection-engineering lab that uses only deterministic synthetic telemetry. I start with one guarded demo command; it refuses non-demo databases, loads a benign baseline plus 12 attack scenarios, then produces 12 tested alerts and 10 incidents.

On SOC Overview, every metric comes from FastAPI and PostgreSQL: incident severity, alert trend, entities, ATT&CK tactics, and measured local evaluator latency. I’ll open the identity incident. Two rules—password spray and failure-followed-by-success—correlated on the same synthetic identity and correlation ID. The detail page shows the executive summary, exact evidence event IDs, entity timeline, ATT&CK mappings, investigation checklist, containment recommendations, analyst notes, and an approval-gated playbook.

The playbook cannot touch a real user or device. A different analyst must approve it, execution changes only local state, and every step is audited.

In Detection Library, KQL remains the authoritative Sentinel content. Sigma is included where the semantics are portable, while purpose-built Python counterparts make local tests deterministic; this is explicitly not a full KQL engine. Rule Quality proves 12 positive and 12 negative fixture outcomes, and ATT&CK Coverage marks gaps honestly.

Finally, the repository includes disabled-by-default Terraform for Sentinel resources, non-deployable Logic Apps integration mappings, Docker Compose, strict linting and typing, secret scanning, and GitHub Actions. The result demonstrates the workflow from log normalization through detection-as-code, investigation, and safe incident response without requiring a paid cloud service.”

## Truthful resume bullets

- Built SentinelForge, a local Microsoft Sentinel detection-engineering lab with FastAPI, PostgreSQL, React, and Docker Compose that normalizes 11 synthetic telemetry sources and correlates 12 explainable alerts into incident timelines.
- Authored 12 versioned KQL analytics rules with MITRE ATT&CK mappings, seven Sigma equivalents, purpose-built Python evaluators, and positive/negative regression fixtures enforced by Pytest, Ruff, strict MyPy, ESLint, and GitHub Actions.
- Implemented five separation-of-duties SOAR simulations with deterministic enrichment, approval gates, local audit records, and Azure Logic Apps/Terraform mappings that perform no real containment or cloud deployment.

## Recommended portfolio images

- SOC Overview at desktop width: demonstrates operational prioritization.
- Identity incident detail at the timeline and ATT&CK mapping: demonstrates investigation reasoning.
- Detection Library with SF-005 KQL/Sigma preview: demonstrates content engineering.
- Rule Quality plus ATT&CK Coverage: demonstrates testing discipline and coverage honesty.
- Responsive Incident Queue: demonstrates full-stack polish.

Capture only from the healthy running dashboard using the checklist in docs/screenshots/README.md; no image is currently committed, and a mocked UI must never be substituted.
