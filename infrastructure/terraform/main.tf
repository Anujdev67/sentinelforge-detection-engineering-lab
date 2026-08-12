module "resource_group" {
  source = "./modules/resource-group"

  name     = "rg-${var.name_prefix}"
  location = var.location
  tags     = var.tags
}

module "sentinel" {
  source = "./modules/sentinel"

  workspace_name         = "law-${var.name_prefix}"
  resource_group_name    = module.resource_group.name
  location               = module.resource_group.location
  retention_in_days      = var.retention_in_days
  daily_quota_gb         = var.daily_quota_gb
  enable_entra_connector = var.enable_entra_connector
  tags                   = var.tags
}

module "content" {
  source = "./modules/content"

  workspace_id           = module.sentinel.workspace_id
  resource_group_name    = module.resource_group.name
  location               = module.resource_group.location
  rules                  = local.rules
  enable_analytics_rules = var.enable_analytics_rules
  tags                   = var.tags
}
