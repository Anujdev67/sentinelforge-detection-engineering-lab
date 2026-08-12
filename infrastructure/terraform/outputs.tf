output "resource_group_name" {
  description = "Name of the represented lab resource group."
  value       = module.resource_group.name
}

output "log_analytics_workspace_id" {
  description = "Resource ID of the represented Log Analytics workspace."
  value       = module.sentinel.workspace_id
}

output "scheduled_rule_ids" {
  description = "Scheduled analytics rule resource IDs."
  value       = module.content.scheduled_rule_ids
}

output "cost_controls" {
  description = "Configured ingestion cap and retention; verify Azure pricing before deployment."
  value = {
    daily_quota_gb    = var.daily_quota_gb
    retention_in_days = var.retention_in_days
  }
}
