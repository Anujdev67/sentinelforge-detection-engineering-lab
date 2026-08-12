# Case study: password spray followed by successful authentication

## Initial alert

The deterministic demo created incident `inc-52fe50efc453c4` by correlating:

- `SF-001` / `alert-sf-001-bcc40dfc9159`: one documentation-safe source produced failed sign-ins across five accounts.
- `SF-002` / `alert-sf-002-255d48dc53ca`: at least four failures for one account were followed by success.

Severity: **High**. Observed window: **2026-02-03 14:00–14:04 UTC**.

## Investigation hypothesis

An actor attempted a low-volume password spray from one source, identified a valid credential for `alex.morgan@example.test`, and then authenticated successfully. The alternative hypothesis is a shared egress address plus user password mistakes; the success sequence and targeted-account cardinality make that explanation less likely but still require identity-owner validation.

## Data sources

- `SigninLogs`-shaped synthetic events
- normalized authentication outcome, account, application, source IP, correlation, and result-code fields
- SF-001 and SF-002 KQL/Python detection results

## Query logic

[SF-001 KQL](../../detections/rules/sf-001-password-spray/query.kql) groups invalid-credential result code `50126` by source IP over ten minutes and requires at least five distinct accounts. [SF-002 KQL](../../detections/rules/sf-002-failed-then-success/query.kql) groups failure/success results by identity and address, then requires four failures before a later success. The local counterparts operate only on normalized `interactive_sign_in` events; they do not execute KQL.

## Timeline

| UTC | Evidence | Interpretation |
| --- | --- | --- |
| 14:00 | `evt-sf001-positive-01`, `evt-sf002-positive-01` | Spray begins; the focal account also begins repeated failures |
| 14:01 | `evt-sf001-positive-02`, `evt-sf002-positive-02` | Additional targeted account and repeated focal-account failure |
| 14:02 | `evt-sf001-positive-03`, `evt-sf002-positive-03` | Pattern remains within threshold window |
| 14:03 | `evt-sf001-positive-04`, `evt-sf002-positive-04` | Fourth focal-account failure satisfies sequence prerequisite |
| 14:04 | `evt-sf001-positive-05`, `evt-sf002-positive-05` | Fifth distinct spray target and successful focal-account sign-in |

## Entities

- Source IP: `198.51.100.77` (RFC 5737)
- Focal identity: `alex.morgan@example.test`
- Other targets: `training.user2@example.test` through `training.user5@example.test`
- Synthetic correlation: `corr-demo-identity-chain`

## Evidence and scope assessment

Both alerts share the focal identity, source, and explicit demo correlation. Nine SF-001 evidence rows and six SF-002 rows show the aggregation and ordered sequence. Scope review should search all authentication from the source, all activity by the focal account after success, MFA and conditional-access context, audit changes, mailbox/cloud activity, and other accounts with successful outcomes. The fixture contains no subsequent real action, so compromise is suspected—not asserted as fact.

## MITRE ATT&CK

- Credential Access / Password Spraying — `T1110.003`
- Credential Access / Brute Force — `T1110`
- Initial Access / Valid Accounts: Cloud Accounts — `T1078.004`

## Containment decision

Recommend a human-approved identity containment decision after validating the account owner and sign-in context. In a real environment this could include session revocation and credential reset through authorized Microsoft Entra ID procedures. SentinelForge records the recommendation and approval decision only; it cannot act on the user.

## Recovery recommendation

Review identity risk, registered authentication methods, tokens/sessions, privileged role assignments, inbox/cloud rules, and audit changes. Restore access only after identity verification, credential rotation, phishing-resistant MFA review, and confirmation that no persistence remains.

## Detection tuning considerations

- trusted proxy/VPN egress and managed password-validation services;
- smart-lockout behavior and result-code consistency;
- service, break-glass, and test accounts;
- source plus application/tenant segmentation;
- ingestion delay and overlapping scheduling windows;
- avoid excluding a whole egress IP when a narrower account/application exception works.

## Lessons learned

Single-rule triage can miss the transition from broad targeting to successful access. Entity/correlation-aware grouping raises priority while retaining each rule’s independent evidence. MFA challenge events must remain semantically distinct from invalid-credential sign-ins—an integrated demo test now protects that boundary.
