# Detecting Web Attacks - SOC Investigation Write-Up
**Platform :** TryHackMe | **Room** : Detecting Web Attacks
**Category :** Web Application Security / Log & Network Forensics


## Scenario
TryBankMe, an online banking platform, suffered a breach - Customers sensitive data was leaked on a darknet form. I was tasked with retracting the attacker's steps from web server logs and network traffic to determine the entry point and scope of compromise.

## Objective
- Identify the attack chain from access log
- Confirm finding using packet capture analysis
- Recommend a WAF rule to prevent recurrence

## Tools Used
- Apache/Nginx access log analysis (manual + grep)
- Wireshark (HTTP filtering, Follow HTTP Stream)
- URL decoding for obfuscated payloads

## Phase 1 : Log Analysis

## Investigation / Analysis :

### Reconnaissance (07:37:38 – 07:37:40) : 
All request was originated from 192.168.1.10 using the user agent 'FUFF v2.1.0' - a known directory fuzzing tool. Within the 2 minutes window the toll swept ~13 paths. Most returned 404, but three paths ('/home', '/catalog', '/product') and '/login.php' returned 200, confirming valid, unauthenticated endpoints for the attackers to target next. Notably, '/login.php' returning 200 during the fuzz flags it as the highest-value discovery path - which is exactly what the atackers pivots the next.

### Credential Brute-Force (07:38:09) :
Roughly 30 seconds after the recon the same IP returned with the new User Agent 'Mozilla/5.0 (Hydra) -- Hydra being known for credential-brute-force tool, and the UA change itself is a pivot indicator (attacker switched tool between recon and exploitation). A burst of GET and POST request were hit '/login.php' in the same second timestamps, consistent with automated, rapid fire login attempts. Of ~11 POST attempts, all returned '200' (failed-login re-renderig the form) except one, which returned '302' - an HTTP redirect, and the only status-code anomaly in the burst. This is a successful login.

### Session Confirmation :
Immediately following the '302' , the same IP and UA request '/account' (301 --> redirect to '/acccount' , then 200). This confirms the redirect from the brute force led to an authentication session - the attacker is now inside a vald user account.

### Exploitation (07:38:20) :
~11 seconds after gaining the account access, the User-Agent changes again to 'sqlmap/stable' - a third distinct tool, confirming a third phase. The request targets '/account/changeusername.php' with a URL-encoded query string. Decoding the payload :
                            `%25%27+OR+%271%27%3D%271` → `%' OR '1'='1`
This is a classic SQL Injection tautology payload, submitted against an authenticated endpoints - meaning the attacker escalated from account takeover to a database level injection attempt on a form that should have required proper session-bound input validation.


## Phase 2 : Network Traffic Analysis (Wireshark) :
**Approach:** Logs confirmed **what** happened but not full request/response content (POST bodies aren't logged). Pivoted to `traffic.pcap` to recover the missing context.

**Filter Used:** `ip.src==192.168.1.10 && http.user.agent`

## #Confirming the Timeline :
The packet captured independently confirms the three-phase sequence identified in log analysis - directory fuzz (07:37:38), credential brute-force (07:38:09) and SQLi exploitation (07:38:21) - with consistent timestamps across both sources. This cross-validation between log and packet data increases confidence that the reconstructed timeline is accurate, not an artifact of log parsing.

### Recovering the Successful Credemtials :
The access log showed one `302` among the brute-force POSTs but could not reveal what was submitted. Following the HTTP stream on that specific request recovered the full POST body, confirming the username/password pair that succeeded - information the log format alone could never provide, since POST bodies aren't recorded by default in most access log configurations. 

### Confirming Exploitation Impact :
Following the stream on the final SQLi request (packet 440) showed :
Two findings here:

Root cause: The response leaks a debug string exposing the raw SQL query:
SELECT id, username, email FROM users WHERE username LIKE '%%' OR '1'='1%'

Confirming the vulnerability is unsanitized string concatenation into a LIKE clause, with debug output left enabled in production — a separate information-disclosure issue that directly aided exploitation.

Impact: The payload %' OR '1'='1 closed the intended LIKE pattern early and appended a tautological condition, converting a single-username search into a full table dump. The response returned every row in the users table (id, username, email) — confirmed, visible data exfiltration, not a blind injection attempt.

Key Addition Over Phase 1

Packet capture revealed GET requests to /login.php immediately preceding each POST attempt — not visible in the log excerpt alone. This suggests the tool fetched the form (likely for a CSRF token) before every submission, a detail only visible at the packet level.


### Findings
Phase	            Tool (User-Agent)	        Technique	                                MITRE ATT&CK
Reconnaissance	        FFUF v2.1.0	        Forced Browsing / Directory Discovery	        T1595.003
Credential Access	    Hydra	            Brute Force	                                    T1110.001
Exploitation	        sqlmap	            SQL Injection (authenticated)	                T1190

### IOCs:

Source IP: 192.168.1.10
User-Agents: FFUF v2.1.0, Mozilla/5.0 (Hydra), sqlmap/stable
Targeted endpoints: /login.php, /account/changeusername.php


## Impact Assessment

A single unauthenticated actor progressed from recon → brute-forced credentials → authenticated SQL injection → full table dump, entirely through the public web application. The lack of rate-limiting on login, unparameterized SQL queries, and exposed debug output combined to turn one weak account password into a full database compromise.

## Recommendations
Enforce parameterized queries / prepared statements — the direct fix for the SQLi root cause
Rate-limit authentication endpoints (e.g., 5 attempts/minute/IP) to blunt brute-force tools
Disable debug/verbose query output in production — this alone revealed exact query structure to the attacker
Deploy WAF rules blocking known attack-tool User-Agents (sqlmap, Hydra, FFUF) as a compensating control
Force credential rotation and enable MFA for affected accounts post-incident
Alert on rapid sequential 404s from a single IP (fuzzing signature) to catch recon earlier in the chain
Key Takeaway

Log analysis and packet capture are complementary, not redundant. Logs gave the attack timeline; packet capture confirmed actual impact — recovered credentials and a full response body proving data exfiltration — since neither is fully visible from the other source alone.