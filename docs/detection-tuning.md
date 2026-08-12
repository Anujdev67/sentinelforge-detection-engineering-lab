# Detection tuning guide

## Workflow

1. Read the rule metadata, KQL, local evaluator, fixtures, and expected alert together.
2. Confirm the required table and fields exist in the target environment.
3. Measure normal volume, cardinality, ingestion delay, service accounts, approved tools, and maintenance windows.
4. Add a benign fixture for every proposed exception before changing logic.
5. Add or adjust a malicious fixture that proves the threat behavior still triggers.
6. Update version/changelog and run all detection gates.
7. Test the KQL in a non-production workspace and review projected entity mappings.
8. Deploy disabled, compare results, obtain detection-owner approval, and enable through the organization’s process.

## High-value tuning points

| Rule family | Primary tuning inputs |
| --- | --- |
| Password/MFA | trusted egress, break-glass accounts, smart lockout, application, result codes |
| Geographic anomaly | VPN egress, travel, corporate proxies, IP geolocation confidence |
| PowerShell/LSASS | signed automation, EDR tooling, parent lineage, signer/hash allowlists |
| DCSync/RDP | domain controller inventory, replication principals, jump hosts, admin tiers |
| Remote tools | approved product, signer, install path, ticket/change context, device group |
| DNS/beaconing | resolver behavior, CDN/SaaS endpoints, sample size, jitter, device role |
| AWS IAM | CI/CD roles, MFA context, source network, change windows, CloudTrail completeness |

Avoid broad user, host, or process exclusions. Prefer scoped, expiring, owner-attributed watchlist entries and retain the pre-exclusion telemetry for audit.

## Required change evidence

- positive fixture passes;
- paired benign fixture does not alert;
- expected alert snapshot reviewed;
- known false positives and investigation steps updated;
- version/changelog updated;
- KQL and Sigma structural checks pass;
- ATT&CK and entity mappings remain accurate;
- local-vs-KQL semantic differences remain explicit.

The Rule Quality page marks rules whose metadata says tuning is still required. That flag is a review signal, not an error.
