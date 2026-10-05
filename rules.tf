# Rule 1: Suspicious PowerShell encoded command
# MITRE ATT&CK: Execution (T1059) and Defense Evasion (T1027)
resource "azurerm_sentinel_alert_rule_scheduled" "encoded_powershell" {
  name                       = "encoded-powershell-command"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = "Suspicious PowerShell Encoded Command"
  description                = "Detects PowerShell launched with Base64-encoded commands, a common way to hide malicious scripts."
  severity                   = "Medium"
  enabled                    = true

  query_frequency = "PT1H"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["Execution", "DefenseEvasion"]
  techniques = ["T1059", "T1027"]

  query = <<-EOT
    DeviceProcessEvents
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "-e ")
    // Exclude Azure Guest Configuration agent (verified in range, Oct 2026)
    | where not (InitiatingProcessFileName =~ "gc_worker.exe"
                 and InitiatingProcessFolderPath startswith @"c:\packages\plugins\microsoft.guestconfiguration")
    | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessFolderPath
  EOT
}
