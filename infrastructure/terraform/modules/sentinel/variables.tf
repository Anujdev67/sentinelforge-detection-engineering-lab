variable "workspace_name" {
  type        = string
  description = "Log Analytics workspace name."
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name."
}

variable "location" {
  type        = string
  description = "Azure region."
}

variable "retention_in_days" {
  type        = number
  description = "Workspace retention."
}

variable "daily_quota_gb" {
  type        = number
  description = "Daily ingestion cap."
}

variable "enable_entra_connector" {
  type        = bool
  description = "Whether to represent the same-tenant Entra connector."
}

variable "tags" {
  type        = map(string)
  description = "Resource tags."
}
