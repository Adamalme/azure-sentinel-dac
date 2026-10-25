# Rule 1: Suspicious PowerShell encoded command
# MITRE ATT&CK: Execution (T1059) and Defense Evasion (T1027)
# Data source: SecurityEvent (Event ID 4688, process creation) via AMA + DCR
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

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "Account"
    }
  }

  query = <<-EOT
    SecurityEvent
    | where EventID == 4688
    | where NewProcessName has_any ("powershell.exe", "pwsh.exe")
    | where CommandLine has_any ("-EncodedCommand", "-enc ", "-e ")
    // Exclude Azure Guest Configuration agent (false positive seen in range, Oct 2026)
    | where not (ParentProcessName contains @"\packages\plugins\microsoft.guestconfiguration")
    | project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
  EOT
}


# Rule 2: Security event log cleared
# MITRE ATT&CK: Defense Evasion (T1070, Indicator Removal: Clear Windows Event Logs T1070.001)
# Data source: SecurityEvent (Event ID 1102, audit log cleared) via AMA + DCR
resource "azurerm_sentinel_alert_rule_scheduled" "security_log_cleared" {
  name                       = "security-log-cleared"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
  display_name               = "Security Event Log Cleared"
  description                = "Detects when the Windows Security event log is cleared, a common way attackers hide their tracks."
  severity                   = "High"
  enabled                    = true

  query_frequency = "PT1H"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["DefenseEvasion"]
  techniques = ["T1070"]

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "ClearedBy"
    }
  }

  query = <<-EOT
    SecurityEvent
    | where EventID == 1102
    // Account is empty for 1102; the user is stored inside EventData
    | extend ClearedBy = coalesce(Account, extract(@"<SubjectUserName>([^<]+)</SubjectUserName>", 1, tostring(EventData)))
    | project TimeGenerated, Computer, ClearedBy, Activity
  EOT
}