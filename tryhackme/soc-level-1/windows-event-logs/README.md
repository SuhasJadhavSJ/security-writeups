Windows Event Logs (TryHackMe)

Analyst: Suhas | Source: merged.evtx | Tools: Event Viewer, wevtutil, Get-WinEvent (FilterHashtable / XPath)
1. Incident Summary

Four detection scenarios were investigated in one merged event log:

    PowerShell downgrade: the PowerShell logging test surfaced a session running on the legacy 2.0 engine.
    Log clearing: the security team's monitoring test was triggered when a colleague cleared an event log.
    Emotet: threat intel advised hunting Event ID 4104 with ScriptBlockText, which turned up an encoded PowerShell payload.
    Suspected insider: an intern's machine was reported for running unusual commands, and the analyst searched for C:\Windows\System32\net1.exe.

2. Analysis (Key IOCs)
Scenario	Event ID / Log	Key Indicators
PowerShell downgrade	400 (Windows PowerShell)	Engine version 2.0 (downgrade); occurred 12/18/2020 7:50:33 PM
Log clear	104 (System) / 1102 (Security)	Event Record ID 27736; host PC01.example.corp
Emotet payload	4104 (PowerShell/Operational)	Base64-encoded ScriptBlockText; first variable $Va5w3n8; 8/25/2020 10:09:28 PM; Execution PID 6620
Insider enumeration	4799 (Security)	net1.exe spawned; group SID S-1-5-32-544 (local Administrators)

Example queries used:
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104}
wevtutil qe Application /q:*/System[EventID=100] /f:text /c:1
3. Verdict & Scope

    Emotet script block: true positive. The encoded PowerShell matches known Emotet loader behaviour.
    Log clear and PowerShell downgrade: true positives for the detection tests. They are consistent with defence evasion (T1070.001 and T1059.001), but were lab-simulated.
    net1.exe group enumeration: confirms the intern ran Administrators-group discovery (T1069.001). Whether the intent was malicious needs HR/management follow-up.
    Scope: the hosts in merged.evtx, principally PC01.example.corp. No lateral movement was observed in the reviewed events.

4. Remediation

    Enable PowerShell Script Block Logging via Group Policy so 4104 events are captured.
    Enable Audit Process Creation with command-line logging (Event ID 4688); it was off on the lab machine.
    Disable the PowerShell 2.0 feature to prevent downgrade attacks.
    Forward logs to a SIEM and alert on 104/1102 (log clears), 400 (downgrade) and 4799 (group enumeration).
    For the Emotet host: isolate it, block the payload's IOCs, and reset credentials.
    Restrict net1.exe use for standard users, and review the intern's activity with management.


