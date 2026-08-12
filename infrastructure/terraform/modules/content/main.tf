resource "azurerm_sentinel_alert_rule_scheduled" "this" {
  for_each = var.rules

  name                       = each.value.name
  log_analytics_workspace_id = var.workspace_id
  display_name               = "${each.key} — ${each.value.title}"
  description                = "SentinelForge detection-as-code example. Validate data availability and tune before enabling."
  enabled                    = var.enable_analytics_rules
  severity                   = each.value.severity
  query                      = each.value.query
  query_frequency            = "PT15M"
  query_period               = "PT2H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = each.value.tactics
  techniques                 = each.value.techniques

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled           = true
      lookback_duration = "PT1H"
    }
  }
}

resource "azurerm_sentinel_automation_rule" "triage" {
  name                       = "8d583f8e-8dab-4a24-8823-3be7cfb54001"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "SentinelForge — mark new synthetic-lab incidents active"
  order                      = 100
  enabled                    = false

  action_incident {
    order  = 1
    status = "Active"
    labels = ["SentinelForge", "HumanApprovalRequired"]
  }
}

resource "azurerm_sentinel_watchlist" "approved_remote_tools" {
  name                       = "sentinelforge-approved-remote-tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "SentinelForge approved remote-support tools"
  item_search_key            = "ToolName"
  description                = "Training-only allowlist example; populate from an authoritative asset process."
  labels                     = ["SentinelForge", "synthetic-only"]
}

resource "azurerm_sentinel_watchlist_item" "training_tool" {
  name         = "1a6db115-7b64-420f-b877-7dd9f1492001"
  watchlist_id = azurerm_sentinel_watchlist.approved_remote_tools.id
  properties = {
    ToolName = "FictionalSupportClient.exe"
    Scope    = "training-only"
    Owner    = "soc-lab@example.test"
  }
}

resource "azurerm_application_insights_workbook" "soc_quality" {
  name                = "524c5eef-4c11-42b3-a90f-2dfad9ea1001"
  resource_group_name = var.resource_group_name
  location            = var.location
  display_name        = "SentinelForge Detection Quality"
  source_id           = lower(var.workspace_id)
  category            = "sentinel"
  tags                = var.tags
  data_json = jsonencode({
    version = "Notebook/1.0"
    items = [
      {
        type = 1
        content = {
          json = "# SentinelForge Detection Quality\nValidate rule health, alert volume, and tuning in the target workspace."
        }
        name = "overview"
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = "SecurityAlert | summarize Alerts=count() by AlertSeverity, bin(TimeGenerated, 1h)"
          size    = 0
          title   = "Alerts by severity"
          timeContext = {
            durationMs = 86400000
          }
          queryType    = 0
          resourceType = "microsoft.operationalinsights/workspaces"
        }
        name = "alerts-by-severity"
      }
    ]
    fallbackResourceIds = [lower(var.workspace_id)]
  })
}
