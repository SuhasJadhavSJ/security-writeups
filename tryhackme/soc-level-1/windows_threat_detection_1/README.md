# Windows Initial Access Detection: SOC Lab Write-up

Hands-on write-up of the TryHackMe **Windows Threat Detection 1** room. It covers how attackers gain Initial Access on Windows hosts and how to detect each technique using only Windows Security and Sysmon logs.

## Scenarios Covered

| # | Scenario | MITRE Technique | Key Evidence |
|---|----------|-----------------|--------------|
| 1 | Exposed RDP brute force | T1133 External Remote Services | Security Event IDs 4625 (failed), 4624 (success), logon types 3 and 10 |
| 2 | Phishing: binary attachments (.com, double extension) | T1566, T1036.007 | Sysmon Event IDs 1 and 11 |
| 3 | Phishing: LNK shortcut launching PowerShell | T1566 | LNK in Downloads, `powershell.exe` with `explorer.exe` as parent |
| 4 | Infected USB / removable media | T1091 Replication Through Removable Media | Execution from external drives (e.g. `E:\`), dropped files, spread to other drives |

Also discussed: T1190 Exploit Public-Facing Application.

## Detection Workflow

**RDP breach**
1. Filter Security logs for Event ID 4625 with logon types 3 and 10.
2. Check the `Source Network Address` field for external IPs.
3. Switch to Event ID 4624 to find the account used for the successful logon.
4. Copy the `Logon ID` and search Sysmon for every process started in that session.

**Phishing / USB**
1. Sysmon Event ID 1: browser or Explorer launch.
2. Sysmon Event ID 11: archive or LNK written to Downloads.
3. Sysmon Event ID 11: file extracted to a folder.
4. Sysmon Event ID 1: user double-clicks the file (parent `explorer.exe`).

## Repository Contents

- `SOC_Lab_Report.pdf`: one-page report (Incident Summary, Analysis, Verdict & Scope, Remediation)
- `README.md`: this file

## Tools & Log Sources

- Windows Event Viewer (Security log)
- Sysmon
- MITRE ATT&CK

## Key Takeaways

- Exposed services and user-driven attacks are the two most common Windows Initial Access paths.
- RDP brute force is easy to spot from default authentication logs (4624/4625).
- User-driven attacks are best caught with process execution telemetry, preferably Sysmon.
- LNK files leave little execution trace, so look for the earlier file-creation event.

## Author

**Suhas Jadhav**: entry-level SOC Analyst / Threat Intelligence aspirant
[LinkedIn](https://linkedin.com/in/suhas-jadhav-60214420b) | [TryHackMe](https://tryhackme.com/p/suhasjadhavsj046)

## Disclaimer

Educational lab work performed in the TryHackMe sandbox. No real systems or data were involved.