# Azure Sentinel Detection-as-Code

Terraform project that deploys Microsoft Sentinel and manages detection rules as code, mapped to MITRE ATT&CK.

## Status: Active

| Component | Status |
|---|---|
| Resource group, Log Analytics workspace, Sentinel (Terraform) | Deployed and validated |
| Rule 1: Suspicious PowerShell Encoded Command (T1059, T1027) | Deployed, validated, tuned |
| Rule 2: Security Event Log Cleared (T1070) | Deployed, validated, documented |
| Rule 3: User Added to Local Administrators (T1098) | Planned (next) |

## Validation evidence

Each rule is deployed with Terraform, triggered with a controlled attack simulation on an isolated test VM, and confirmed by a Sentinel incident. Results and screenshots are in [`docs/evidence/`](docs/evidence/).

- **Rule 1 (encoded PowerShell):** incident created on simulated encoded command; entity mapping (Host, Account) confirmed. Tuned out the Azure Guest Configuration agent, reducing noise from 747+ hits/week to 1 in 24 hours while still catching encoded PowerShell launched through WMI.
- **Rule 2 (log cleared):** cleared the Windows Security log (`wevtutil cl Security`) on the test VM; Sentinel created a High incident within ~44 minutes (event-to-incident latency), with Host and Account entities mapped. Resolved as benign positive (security testing).

## Detection tuning example

Rule 1 was tested against real telemetry in a cyber range lab. Excluding the Azure Guest Configuration agent (verified by process name and folder path) reduced noise from 747+ hits per week to 1 in 24 hours, while still catching encoded PowerShell launched through WMI.

## Files

- `providers.tf` — Azure provider setup
- `main.tf` — resource group, workspace, Sentinel
- `rules.tf` — scheduled analytics rules (Rule 1, Rule 2)
- `docs/evidence/`
