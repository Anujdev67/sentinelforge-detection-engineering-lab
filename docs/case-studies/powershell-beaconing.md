# Case study: suspicious PowerShell followed by outbound beaconing

## Initial alert

Incident `inc-49a8e3332bd37f` correlates:

- `SF-005` / `alert-sf-005-6d0f9d3efeea`: suspicious encoded PowerShell execution.
- `SF-012` / `alert-sf-012-33ba2a0b007e`: six Palo Alto-style outbound sessions at approximately 60-second intervals with low jitter.

Overall severity: **High**. Observed window: **2026-02-03 14:00–14:05 UTC**.

## Investigation hypothesis

Encoded PowerShell on a workstation may have launched or staged code that then established periodic HTTPS command-and-control traffic. Alternative explanations include sanctioned automation plus a periodic management service; process lineage and network ownership are required to distinguish them.

## Data sources

- `DeviceProcessEvents`-shaped process creation
- `CommonSecurityLog`-shaped firewall sessions
- normalized command line, parent process, destination/port, byte count, host, and timing

## Query logic

[SF-005 KQL](../../detections/rules/sf-005-suspicious-powershell/query.kql) selects PowerShell with encoded/download/hidden-window indicators and projects process entities. [SF-012 KQL](../../detections/rules/sf-012-outbound-beaconing/query.kql) groups allowed firewall traffic by source, destination, and port, calculates intervals, and requires sufficient periodic sessions with low standard deviation. Sigma exists for SF-005; interval aggregation remains KQL/Python because it is not honestly portable in a basic Sigma rule.

## Timeline

| UTC | Evidence | Interpretation |
| --- | --- | --- |
| 14:00 | `evt-sf005-positive-01` | `powershell.exe` launches with an encoded-command indicator |
| 14:00 | `evt-sf012-positive-01` | First allowed session from the same device context |
| 14:01–14:05 | `evt-sf012-positive-02` … `-06` | Five further sessions repeat at 59–61 second intervals |
| 14:05 | `alert-sf-012-33ba2a0b007e` | Periodicity threshold is satisfied and correlates with SF-005 |

## Entities

- Device: `ws-417.sentinelforge.test`
- Account: `casey.lee@example.test`
- Process: `powershell.exe`
- Network: `198.51.100.112` → `203.0.113.212:443`
- Synthetic correlation: `corr-demo-powershell-beacon`

## Evidence and scope assessment

The endpoint alert has one process event; the network alert has six firewall events. Together they establish temporal and host correlation, not causality. Scope review should obtain process tree/script-block/AMSI context, signer/hash, file and registry activity, DNS resolution, destination reputation/ownership, peer-device connections, identity logons, and whether the destination belongs to an approved service.

## MITRE ATT&CK

- Execution / PowerShell — `T1059.001`
- Stealth / Obfuscated Files or Information — `T1027`
- Command and Control / Web Protocols — `T1071.001`

## Containment decision

Recommend a human-approved endpoint containment decision when process ancestry or destination context supports malicious execution. Preserve volatile evidence and network telemetry first where policy permits. SentinelForge does not isolate the device, kill PowerShell, or block the destination.

## Recovery recommendation

Remove confirmed artifacts with approved endpoint tooling, remediate persistence, rotate credentials shown to be exposed, validate EDR health, monitor the destination and process indicators, and return the host only after a clean investigative checkpoint.

## Detection tuning considerations

- signed deployment tools and known encoded administration scripts;
- process parent, signer, device group, and change-window context;
- sanctioned monitoring endpoints and SaaS/CDN periodic traffic;
- minimum sample size, interval mean, jitter, bytes, and session duration;
- alert separately on strong process evidence even if network aggregation is incomplete.

## Lessons learned

Cross-domain correlation can turn two ambiguous signals into a coherent investigation hypothesis while still requiring causality checks. Low-jitter traffic is useful only with sufficient samples and environmental baselining.
