# Windows Threat Detection 3 – SOC Lab Report

**Analyst:** Suhas | **Platform:** TryHackMe | **Scope:** Command & Control, Persistence, Impact on a Windows host

## 1. Incident Summary

The lab simulates a compromised Windows host where the attacker moves past the initial breach to keep control of the machine. Alerts and review focused on three tactics: **Command and Control** (a phishing attachment or dropped payload beaconing to an attacker server), **Persistence** (backdoor accounts, services, scheduled tasks, Startup folder and Run keys) and **Impact** (ransomware as the end goal of a long-held foothold). Detection relied on Sysmon and Windows Security event logs.

## 2. Analysis – Key IOCs

| Technique | Behaviour observed | Detection source |
|---|---|---|
| C2 setup (TA0011) | Phishing archive downloaded; payload hidden in a folder such as `C:\Temp` and run as a new process that connects to the C2 domain | Sysmon 1, 3, 11, 22 |
| Backdoor user (T1136, T1098) | `net user "mr.backd00r" ... /add`, then `net localgroup Administrators "mr.backd00r" /add` | Security 4720, 4732; 4724 for password resets |
| Malicious service (T1543.003) | `sc create "BadService" binpath= "C:\malware.exe" start= auto`; child of `services.exe` | Sysmon 1; Security 4697; System 7045 |
| Scheduled task (T1053.005) | `schtasks /create /tn "BadTask" /tr "C:\malware.exe" /sc onstart /ru System`; parent `svchost.exe -s Schedule` | Sysmon 1; Security 4698 |
| Startup folder (T1547.001) | `malware.exe` dropped into `...\Start Menu\Programs\Startup\`, launched by `explorer.exe` | Sysmon 11 |
| Run key (T1547.001) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `BadRunKey` pointing to `C:\malware.exe` | Sysmon 13 |

Other indicators: payloads executing from user-writable paths (`Downloads`, `AppData`, `C:\Temp`), double-extension files such as `invoice.pdf.exe`, and new accounts created from an unexpected session or source IP.

## 3. Verdict & Scope

**Verdict:** True positive. Multiple independent persistence mechanisms plus a C2 channel indicate an active, deliberate compromise, not a false positive.

**Assets touched:** the compromised workstation, its local account database (new privileged user), the service control manager, the Task Scheduler, the user's Startup folder and Run key. Because persistence survives reboots and password changes, any credentials used on this host should be treated as exposed, and lateral movement toward the wider network should be assumed until ruled out.

## 4. Remediation

- Isolate the host and block the C2 domain/IP at the firewall and DNS.
- Disable and delete the backdoor account; remove it from Administrators and Remote Desktop Users; reset passwords for any reset (4724) accounts.
- Delete the malicious service, scheduled task, Startup file and Run key value; remove the dropped payloads and the original archive.
- Hunt for the same IOCs across the environment; reset credentials used on the host.
- Detection improvements: alert on Security 4720/4732/4697/4698 and Sysmon 1/11/13 hits on the paths above; flag processes launched from `Temp`, `Downloads` and `AppData`.
