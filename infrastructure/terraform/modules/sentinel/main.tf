resource "azurerm_log_analytics_workspace" "this" {
  name                         = var.workspace_name
  location                     = var.location
  resource_group_name          = var.resource_group_name
  sku                          = "PerGB2018"
  retention_in_days            = var.retention_in_days
  daily_quota_gb               = var.daily_quota_gb
  local_authentication_enabled = false
  internet_ingestion_enabled   = true
  internet_query_enabled       = true
  tags                         = var.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "this" {
  workspace_id = azurerm_log_analytics_workspace.this.id
}

# The provider retains the legacy Azure Active Directory resource name. The
# connector represents Microsoft Entra ID and is deliberately opt-in.
resource "azurerm_sentinel_data_connector_azure_active_directory" "entra" {
  count = var.enable_entra_connector ? 1 : 0

  name                       = "sentinelforge-entra-id"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
}
