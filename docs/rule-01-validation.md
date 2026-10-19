# Rule 1 Validation: Suspicious PowerShell Encoded Command

## Summary
| Item | Detail |
|---|---|
| Rule name | Suspicious PowerShell Encoded Command |
| File | `rules.tf` |
| MITRE ATT&CK | T1059 (Command and Scripting Interpreter), T1027 (Obfuscation) |
| Data source | SecurityEvent, Event ID 4688 (process creation), via Azure Monitor Agent + DCR |
| Severity | Medium |
| Runs | Every 1 hour, looks back 1 hour |

## Why this rule matters
Attackers hide malicious PowerShell commands with Base64 encoding so they are harder to read in logs and can slip past simple keyword filters. This rule alerts when PowerShell starts with an encoded command.

## Test
On `vm-dac-test`, I ran a harmless encoded command:

    $cmd = "Write-Output 'Gaashaan detection test'"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    powershell.exe -EncodedCommand $enc

## Results
| Test | Date | Expected | Actual |
|---|---|---|---|
| Test 1 | Oct 8, 2026 | Incident created | Incident #1 created, Medium ✅ (Assets: 0) |
| Test 2 (after entity mapping) | Oct 13, 2026 | Incident shows host + account | Incident #3 created, Medium ✅ (Assets: 2, host + account) |

## Tuning
Excluded the Azure Guest Configuration agent, which runs encoded PowerShell for normal reasons (false positive seen in the cyber range).

## Improvements made
- Added entity mapping (Host = `Computer`, Account = `Account`) so incidents show the affected machine and user.

## Evidence
Screenshots are in `docs/evidence/` (account names and IPs blurred).