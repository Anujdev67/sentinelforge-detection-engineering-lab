variable "workspace_id" {
  type        = string
  description = "Sentinel-enabled Log Analytics workspace resource ID."
}

variable "resource_group_name" {
  type        = string
  description = "Resource group containing the workspace and workbook."
}

variable "location" {
  type        = string
  description = "Azure region."
}

variable "enable_analytics_rules" {
  type        = bool
  description = "Whether represented analytics rules start enabled."
}

variable "tags" {
  type        = map(string)
  description = "Resource tags."
}

variable "rules" {
  description = "SentinelForge scheduled analytics rule definitions."
  type = map(object({
    name       = string
    title      = string
    severity   = string
    tactics    = list(string)
    techniques = list(string)
    query      = string
  }))
}
