variable "location" {
  description = "Azure region for the lab resource group and workspace."
  type        = string
  default     = "uksouth"
}

variable "name_prefix" {
  description = "Lowercase prefix used for Azure resource names."
  type        = string
  default     = "sentinelforge-lab"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,30}$", var.name_prefix))
    error_message = "name_prefix must contain 3-30 lowercase letters, digits, or hyphens."
  }
}

variable "retention_in_days" {
  description = "Log Analytics retention. Longer retention can increase cost."
  type        = number
  default     = 30

  validation {
    condition     = var.retention_in_days >= 30 && var.retention_in_days <= 730
    error_message = "retention_in_days must be between 30 and 730."
  }
}

variable "daily_quota_gb" {
  description = "Daily Log Analytics ingestion cap. Set deliberately before deployment."
  type        = number
  default     = 0.1

  validation {
    condition     = var.daily_quota_gb > 0 && var.daily_quota_gb <= 5
    error_message = "The lab quota must be greater than 0 and no more than 5 GB."
  }
}

variable "enable_entra_connector" {
  description = "Opt in to the same-tenant Microsoft Entra ID connector after permission review."
  type        = bool
  default     = false
}

variable "enable_analytics_rules" {
  description = "Enable scheduled rules. Defaults false so validation cannot activate detections."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to supported Azure resources."
  type        = map(string)
  default = {
    project     = "SentinelForge"
    environment = "training"
    data_class  = "synthetic-only"
  }
}
