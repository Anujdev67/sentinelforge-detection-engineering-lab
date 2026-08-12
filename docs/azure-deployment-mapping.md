# Azure deployment mapping, limitations, and cost controls

The Terraform configuration is a reviewable representation, not a deployment claim. It requires no subscription or tenant value for formatting and static validation, and repository commands never create Azure resources.

## Represented resources

| Module/resource | Purpose | Default safety state |
| --- | --- | --- |
| `modules/resource-group` | Dedicated lab resource group | Definition only |
| Log Analytics workspace | Sentinel data plane with 30-day retention and 0.1 GB/day cap | Definition only |
| Sentinel onboarding | Enables Sentinel on the workspace | Definition only |
| Entra ID connector | Same-tenant identity telemetry connector | Disabled by variable |
| 12 scheduled analytics rules | Authoritative KQL mapped to Sentinel rule settings | Disabled by variable |
| Automation rule | Labels/activates new incidents | Disabled |
| Watchlist + item | Training example for approved support tooling | Fictional value only |
| Workbook | Detection-quality alert summary | Definition only |

Sentinel supports `High`, `Medium`, `Low`, and `Informational`; local `Critical` rules SF-006 and SF-007 map to Sentinel `High`, its highest supported analytics-rule severity.

## Provider and service limitations

- AzureRM is constrained to `>= 4.74, < 5.0`; review the provider changelog and lock file before upgrading.
- The provider resource retains the legacy `azure_active_directory` name even though the service is Microsoft Entra ID.
- Connector support and required permissions vary by table, licensing, tenant type, and region. Only the same-tenant Entra example is represented, and it is opt-in.
- Microsoft 365, Defender XDR, AWS, and vendor firewall ingestion frequently need content-hub packages, Azure Lighthouse, Event Hubs, partner configuration, or APIs beyond a generic Terraform resource. Those are documented mappings, not falsely instantiated connectors.
- Logic Apps managed connections contain environment-specific resource IDs and authorization. The repository therefore provides non-deployable workflow contracts instead of unsafe connection resources.
- Scheduled queries must be compiled and tuned against the target workspace schemas. Static KQL checks cannot prove tenant-specific execution.
- Workbook JSON is intentionally minimal; production workbooks normally require organization-specific table availability, RBAC, parameters, and UX review.

## Cost considerations

Potentially chargeable items include Log Analytics ingestion and retention, Microsoft Sentinel analytics, connector upstream services, Logic Apps executions/connectors, notification services, and storage. Prices differ by region, agreement, commitment tier, and date, so this repository does not state a currency estimate.

Before any authorized plan:

1. confirm current Azure pricing with the organization’s agreement;
2. estimate daily source volume and filtering;
3. set an approved ingestion cap and retention;
4. identify connector and Logic Apps licensing;
5. configure budgets and alerts outside this example;
6. review destruction, retention, and legal-hold requirements.

## Safe validation

```powershell
Set-Location infrastructure/terraform
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
```

Authentication and deployment are deliberately outside these instructions. `terraform.tfvars.example` contains no cloud identity values.
