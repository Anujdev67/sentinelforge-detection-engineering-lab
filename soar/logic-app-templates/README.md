# Azure Logic Apps mapping artifacts

These five JSON files are intentionally **non-deployable pseudodeployment artifacts**. They show the connector boundary, approval gate, data passed between steps, and audit expectation for an Azure implementation without creating connections, identities, API credentials, or chargeable workflows.

Before translating one into a Logic App, an Azure owner must review data residency, managed-identity permissions, connector licensing, ServiceNow tables, notification destinations, and Microsoft Sentinel playbook permissions. Any containment branch must use an explicit approval callback and a separate least-privilege identity. SentinelForge itself never performs real containment.

| Artifact | Azure integration represented |
| --- | --- |
| `suspicious-identity-investigation.json` | Microsoft Sentinel, Defender XDR, Microsoft Entra ID |
| `remote-access-tool-investigation.json` | Microsoft Sentinel, Defender XDR |
| `ioc-enrichment.json` | Microsoft Sentinel plus an approved threat-intelligence service |
| `high-severity-notification.json` | Microsoft Sentinel, Microsoft Teams/email, ServiceNow |
| `incident-evidence-packaging.json` | Microsoft Sentinel and controlled evidence storage |

The JSON is documentation and is validated as such. `deployable` must remain `false`; no project command deploys these artifacts.
