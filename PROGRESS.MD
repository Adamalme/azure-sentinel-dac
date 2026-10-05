# Azure Sentinel DaC – Progress

## Done
- [x] Phase 0: Tools installed (Azure CLI, Terraform, VS Code)
- [x] Phase 1: providers.tf, main.tf, variables.tf (validated)
- [x] Phase 2: rules.tf – Rule 1: Encoded PowerShell (validated)
- [x] Tuned Rule 1 with cyber range data:
      excluded Azure Guest Configuration agent (gc_worker.exe in
      c:\packages\plugins\microsoft.guestconfiguration).
      Result: 747+ noisy hits/week reduced to 1 in 24h.
      Remaining hit: encoded PowerShell via wmiprvse.exe (WMI) as
      administrator – worth investigating (possible T1047).

## Next
- [ ] Phase 3: Deploy with terraform apply in MY OWN Azure account
- [ ] Phase 4: Add Rule 2 (brute-force logins)
- [ ] Phase 5: GitHub + README + CI/CD

## Reminders
- Start of each session:
  $env:ARM_SUBSCRIPTION_ID = (az account show --query id -o tsv)
- Before apply: az account show --query name -o tsv
- Never apply in the LOG(N) Pacific cyber range