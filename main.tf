# 1. A resource group: a "folder" in Azure that holds everything for this project
resource "azurerm_resource_group" "rg" {
  name     = "rg-${var.prefix}"
  location = var.location
}

# 2. Log Analytics workspace: the database where security logs are stored
resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-${var.prefix}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# 3. Turn on Microsoft Sentinel on top of that workspace
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.law.id
}