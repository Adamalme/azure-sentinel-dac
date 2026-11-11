# Rule 3 Validation: User Added to Local Administrators Group

**Rule:** user-added-to-local-admins
**MITRE ATT&CK:** Account Manipulation (T1098) - Persistence, Privilege Escalation
**Data source:** SecurityEvent (Event ID 4732) via AMA + DCR
**Severity:** High

## What it detects
A member being added to a privileged local group (Administrators, Remote Desktop Users, or Backup Operators), a common persistence and privilege-escalation technique.

## Test performed
On the test VM (vm-dac-test), simulated the attack:

    net user testadmin P@ssw0rd123! /add
    net localgroup administrators testadmin /add

## Result: PASS
Event 4732 was collected in Sentinel and matched the detection query:

| TimeGenerated (UTC) | Computer | SubjectUserName | TargetUserName | Activity |
|---|---|---|---|---|
| 2026-11-11 02:06:51 | vm-dac-test | azureuser | Administrators | 4732 - A member was added to a security-enabled local group |

The rule correctly fired on the addition to the **Administrators** privileged group.

## Tuning note
A separate 4732 event for the non-privileged **Users** group was generated during testing. The rule filter (`TargetUserName in ("Administrators", "Remote Desktop Users", "Backup Operators")`) correctly excluded it, confirming the rule alerts only on privileged group changes.

## Cleanup
Test user removed after validation: `net user testadmin /delete`

## Evidence
See screenshot: docs/evidence/screenshots/2026-11-11_rule03-4732-validation.png