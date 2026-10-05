# Azure Sentinel Detection-as-Code

Terraform project that deploys Microsoft Sentinel and manages detection
rules as code, mapped to MITRE ATT&CK.

## Status: In progress

| Component | Status |
|---|---|
| Resource group, Log Analytics workspace, Sentinel (Terraform) | Written and validated |
| Rule 1: Suspicious PowerShell Encoded Command (T1059, T1027) | Written, validated, tuned |
| Deployment to Azure | Next |
| Additional rules | Planned |

## Detection tuning example
Rule 1 was tested against real telemetry in a cyber range lab.
Excluding the Azure Guest Configuration agent (verified by process
name and folder path) reduced noise from 747+ hits per week to 1 in 24 hours,
while still catching encoded PowerShell launched through WMI.

## Files
- `providers.tf` – Azure provider setup
- `main.tf` – resource group, workspace, Sentinel
- `variables.tf` – region and naming prefix
- `rules.tf` – detection rules
- `PROGRESS.MD` – build log
