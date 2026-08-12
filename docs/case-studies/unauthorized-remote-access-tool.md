# Case study: unauthorized remote-access tool execution

## Initial alert

Incident `inc-7b5b6a71127997` contains `SF-009` alert `alert-sf-009-debff6c2b408`: an AnyDesk/TeamViewer-family process executed without a matching synthetic approval marker. Severity: **High**. Observed: **2026-02-03 14:00 UTC**.

## Investigation hypothesis

An unauthorized remote-support utility may have been installed or launched to establish persistent interactive access. A plausible benign alternative is legitimate support activity missing current approval metadata, so process provenance and change/ticket context must be checked before containment.

## Data sources

- `DeviceProcessEvents`-shaped synthetic process creation
- normalized file name and `approved_remote_support` flag
- endpoint/device ownership and local entity context

## Query logic

[SF-009 KQL](../../detections/rules/sf-009-unauthorized-remote-tool/query.kql) selects AnyDesk or TeamViewer executable names and excludes events matched to an approved-device watchlist. The [Sigma equivalent](../../detections/rules/sf-009-unauthorized-remote-tool/rule.yml) carries the portable process-name selection. The Python evaluator checks the normalized approval flag and emits evidence for each unapproved execution.

## Timeline

| UTC | Evidence | Interpretation |
| --- | --- | --- |
| 14:00 | `evt-sf009-positive-01` | `AnyDesk.exe` starts on the focal workstation without synthetic approval |
| 14:00 | `alert-sf-009-debff6c2b408` | SF-009 creates an explainable process alert |
| 14:00 | `inc-7b5b6a71127997` | Correlator creates the single-alert incident |

## Entities

- Device: `ws-909.sentinelforge.test`
- Account: `remote.user@example.test`
- Process: `AnyDesk.exe`
- Synthetic source: `198.51.100.77`

## Evidence and scope assessment

The single process event proves execution in the fixture but does not prove a remote session or malicious operator. Scope assessment should inspect signer/hash/reputation, install path, parent process, persistence, service creation, network destinations, logons, file transfer, user/device ownership, software inventory, ticket/change history, and execution on peer devices.

## MITRE ATT&CK

- Command and Control / Remote Access Software — `T1219.002`

## Containment decision

Recommend human-approved device isolation or process removal only if ownership, approval, and process/network context confirm risk. SentinelForge can request, approve, and audit that recommendation locally but has no Defender device-isolation or process-termination adapter.

## Recovery recommendation

Remove unauthorized software through the approved endpoint-management process, revoke any tool-specific unattended-access configuration, inspect persistence and remote sessions, rotate exposed credentials where evidence supports it, and confirm EDR health before returning the device to service.

## Detection tuning considerations

- use an owner-attributed, expiring approved-tool watchlist;
- include signer, hash, path, service, and device-group constraints;
- cover renamed binaries with product/signature metadata where available;
- correlate network or service-install evidence for priority, but retain the initial process alert;
- do not globally allowlist a product used only on a narrow support device group.

## Lessons learned

Remote-support software is dual use, so execution is an investigation signal rather than automatic proof of compromise. Approval context must be authoritative and time-bounded, and containment must remain a human decision.
