# SOC Lab Report: Sysmon Threat Hunting

**Analyst:** Suhas | **Lab:** TryHackMe Sysmon room | **Source:** Sysmon Operational log (Event Viewer, `Get-WinEvent` + XPath)

---

## 1. Incident Summary

Sysmon, running with the SwiftOnSecurity, ION-Storm and custom configs, raised alerts on seven suspicious behaviours in the lab's sample logs:

- outbound connections to non-standard ports (444, 8080)
- non-`svchost` access to `lsass.exe`
- a new file in the Startup folder
- a new Run-key value
- a file hidden in an NTFS alternate data stream
- a `CreateRemoteThread` from PowerShell into `notepad.exe`

Each alert fired on config rules for Event IDs 3, 10, 11, 13, 15 and 8.

## 2. Analysis

| Technique | Event ID | Key IOCs |
|---|---|---|
| Metasploit-style reverse shell | 3 (Network) | `C:\Users\THM-Threat\Downloads\shell.exe` (PID 3660) → `10.13.4.34:444/tcp`; source `10.10.98.207` (THM-SOC-DC01.thm.soc); 2021-01-05 02:21:22 UTC; rule `Usermode`. Hunt filter also covers 4444/5555. |
| RAT / C2 beaconing | 3 (Network) | `...\Downloads\bigbadrat.exe` (PID 6200) → `10.13.4.34:8080/tcp`; repeated connections about 4 s apart; 2021-01-05 04:42:32 UTC. |
| Credential dumping (Mimikatz) | 10 (ProcessAccess) | `...\Downloads\mimikatz.exe` (PID 3604) → `C:\Windows\system32\lsass.exe` (PID 744); GrantedAccess `0x1010`; 2021-01-05 03:22:52 UTC. |
| Persistence: Startup folder | 11 (FileCreate) | `notepad.exe` (PID 6736) wrote `...\Start Menu\Programs\Startup\persist.exe`; rule `T1023`; 2020-12-21 17:50:27 UTC; user THM-Threat. |
| Persistence: Run key | 13 (RegistryEvent) | `regedit.exe` (PID 1808) set `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Persistence` = `%windir%\system32\malicious.exe`; rule `T1060`; 2020-12-21 19:44:33 UTC. |
| Alternate Data Stream | 15 (FileCreateStreamHash) | `PowerShell_ISE.exe` created `C:\Users\THM-Analyst\Downloads\not_malicious.exe:malware`; MD5 `F6F3AE02ADDB415B00CAD86DF2E6E7BE`; contents `you-found-me!`; 2026-01-19 18:14:42 UTC. |
| Process injection | 8 (CreateRemoteThread) | `powershell.exe` (PID 3092) → `notepad.exe` (PID 1632); StartAddress `0x00560000`; 2019-07-03 20:39:30 UTC; reflective PE injection. |

**Example hunt query (reverse-shell port):**

```powershell
Get-WinEvent -Path .\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
```

## 3. Verdict & Scope

**Verdict:** True positives, not false positives. Every event matches a known attack technique (MITRE ATT&CK T1055, T1547/T1060, T1564) and is intentionally malicious lab activity.

**Assets touched:**

- Host `THM-SOC-DC01.thm.soc` (`10.10.98.207`) as the source of the C2 connections
- User profiles THM-Threat and THM-Analyst
- `lsass.exe` memory (treat cached credentials as compromised)
- Startup folder and HKLM Run key on the affected host
- External endpoint `10.13.4.34` (`ip-10-13-4-34.eu-west-1.compute.internal`)

The logs come from separate scenarios, so the timestamps do not form one continuous timeline.

## 4. Remediation

This lab was detection-only, so no eradication was performed. Recommended actions:

- **Contain:** isolate the host, terminate `shell.exe`, `bigbadrat.exe`, `mimikatz.exe` and the injected `notepad.exe`, and block `10.13.4.34` on 444, 4444 and 8080.
- **Eradicate persistence:** delete `Startup\persist.exe`, remove the `Run\Persistence` value and `system32\malicious.exe`, and delete `not_malicious.exe` together with its `:malware` stream.
- **Recover credentials:** reset passwords for accounts logged on to the host; because a DC is involved, rotate the `krbtgt` password twice.
- **Harden detection:** stop excluding ports such as 53 and 8080 blindly, keep the LSASS and `CreateRemoteThread` rules, and forward Sysmon logs to a SIEM.
