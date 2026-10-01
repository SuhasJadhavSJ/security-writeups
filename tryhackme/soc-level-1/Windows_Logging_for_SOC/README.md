Windows Logging for SOC
Analyst: Suhas  |  Platform: TryHackMe  |  Date: October 1, 2026  |  Host: THM-PC



1. Incident Summary
The investigation started from a burst of failed logons (Security Event ID 4625, Logon Type 3/10) against THM-PC, followed by a successful RDP logon (Event ID 4624, Logon Type 10). Shortly after, a new local account was created and added to privileged groups. A second dataset (Sysmon) showed a user, Sarah, downloading a file through her browser that launched malware, persisted on the host and called out to a command-and-control server. PowerShell history on the Administrator profile was reviewed to confirm hands-on-keyboard activity.

2. Analysis
| Stage                 | Source / Event ID                      | Finding                                                                                               |
| --------------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Brute force           | Security 4625 (Type 3/10)              | Source IP: `[attacker IP]`; repeated failures on one account                                          |
| Initial access        | Security 4624 (Type 10)                | Breached user: `[user]`; malicious Logon ID: `[0x…]`                                                  |
| Persistence (account) | Security 4720, 4732                    | Backdoor user: `[user]`; added to `[group 1]`, `[group 2]`; Logon ID matches RDP session: `[Yea/Nay]` |
| Delivery              | Sysmon 1, 11                           | Browser: `[browser]`; downloaded file: `[file]`; URL: `[URL]`                                         |
| Persistence (file)    | Sysmon 11 / 13                         | File dropped by malware: `[file path]`                                                                |
| C2                    | Sysmon 3, 22                           | C2 server: `[IP:port]`; domain: `[domain]`                                                            |
| Execution             | PS history (`ConsoleHost_history.txt`) | First command: `[command]`; date: `[date]`; flag: `[THM{...}]`                                        |

Correlation key: grouping events by Logon ID (Security and Sysmon) and by ProcessId / ParentProcessId rebuilt the full attack chain.

3. Verdict & Scope
Verdict: True positive, actual breach. The brute force led to a successful RDP login, which was followed by backdoor account creation and privilege escalation. The Sysmon data shows a separate malware infection with persistence and C2 communication.
Assets touched: THM-PC; the breached account [user]; the backdoor account [user]; privileged local groups; Sarah's workstation and browser profile; outbound connection to [C2 IP/domain].

4. Remediation
• Block the brute-force source IP and the C2 IP/domain at the firewall and DNS.
• Disable and delete the backdoor account (4725 / 4726) and remove it from the privileged groups (4733).
• Reset credentials for the breached account and any account used on the affected host.
• Isolate the infected host, delete the malicious download and the persistence file, and remove related registry changes.
• Harden RDP: enforce NLA and MFA, add account lockout, and restrict exposure to the internet.
• Keep Sysmon and PowerShell history monitoring enabled, and alert on repeated 4625 events and on 4720/4732 events outside change windows.