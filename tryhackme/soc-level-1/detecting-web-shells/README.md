1. Incident Summary

Suspicious activity was reported on a WordPress site. I reviewed /var/log/apache2/access.log and found a clear attack chain from one external IP, 203.0.113.66. It started with directory probing, then an upload through a vulnerable form, then commands run through the uploaded PHP web shell. The activity matched the usual web shell indicators: repeated requests to .php files, a mix of 404 and 200 responses, and a POST following the probing.

2. Analysis: Key IOCs

| Type                  | Value                                                                        |
| --------------------- | ---------------------------------------------------------------------------- |
| Attacker IP           | `203.0.113.66`                                                               |
| First directory found | `/wordpress`                                                                 |
| Upload vector         | `upload_form.php` (abused to upload the shell)                               |
| Web shell             | `[filename and path, e.g. under /uploads/]`                                  |
| First command run     | `whoami`                                                                     |
| Second-stage tool     | `linpeas.sh` (Linux privilege escalation enumeration)                        |
| Log source            | `/var/log/apache2/access.log`                                                |
| MITRE ATT&CK          | `T1190`, `T1505.003`, `T1059` (command execution), `T1082/T1083` (discovery) |


Command lines: whoami was the first command (the shell used a ?cmd= style parameter, as the room describes). The attacker then pulled down linpeas.sh, which shows they were looking for privilege escalation paths.
Event IDs: none, since this is a Linux/Apache environment. Detection relied on access logs. In a real environment I would also check auditd for creat (file written) and execve (command run) events tied to the upload time.

3. Verdict & Scope

True Positive: confirmed compromise. The attacker found a directory, uploaded a web shell, executed commands and downloaded a privilege escalation script. This is beyond scanning, since they had remote command execution.

Assets affected:

The WordPress web server and its web root, where the shell was placed
The web server service account, whose context the commands ran under
Not confirmed: whether privilege escalation succeeded or whether the attacker moved to other systems. The logs I reviewed don't show this, so it needs a follow-up check.
4. Remediation
Block 203.0.113.66 at the firewall/WAF.
Remove the web shell and any other suspicious files (find /var/www -type f -name "*.php" -newerct <date> and grep -r "eval(" wp-content), then delete linpeas.sh.
Fix the root cause: patch or restrict upload_form.php with file type validation and no execution in the upload directory.
Check for persistence: new users, cron jobs, modified WordPress files and database content.
Rotate WordPress admin credentials and any secrets on the server, then restore from a clean backup if integrity is uncertain.
Monitor for repeat activity from the same IP or user agent, and escalate to L2/IR to confirm whether privilege escalation succeeded.