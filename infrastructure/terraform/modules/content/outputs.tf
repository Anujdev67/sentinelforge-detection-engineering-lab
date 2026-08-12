output "scheduled_rule_ids" {
  value = { for key, rule in azurerm_sentinel_alert_rule_scheduled.this : key => rule.id }
}

output "workbook_id" {
  value = azurerm_application_insights_workbook.soc_quality.id
}
