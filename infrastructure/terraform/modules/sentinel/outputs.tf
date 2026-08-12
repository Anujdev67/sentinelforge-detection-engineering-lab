output "workspace_id" {
  value = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
}

output "workspace_customer_id" {
  value = azurerm_log_analytics_workspace.this.workspace_id
}
