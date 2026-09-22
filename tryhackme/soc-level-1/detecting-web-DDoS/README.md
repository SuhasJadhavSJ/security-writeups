1. Incident Summary
Two separate denial-of-service events were investigated. In the first (log-based), attacker IP 203.12.23.195 flooded the /login endpoint with repeated requests, exhausting server resources and causing legitimate users to receive 503 Service Unavailable errors. In the second (Splunk-based), a distributed botnet of 60 IPs targeted the /search endpoint, peaking at 207 requests/second, causing service degradation for legitimate traffic.

2. Analysis

    Attacker IP (single DoS): 203.12.23.195
    Targeted endpoint: /login
    Top attacking IP (DDoS, by volume to target URI): 203.0.113.7
    Botnet size: 60 unique IPs
    Common attacker User-Agent: Java/1.8.0_181
    Peak request rate: 207 requests/sec
    First legitimate IP to receive 503 post-attack: 10.10.0.27

Splunk queries used:

index="main"
| stats count by uri
| sort -count

index="main" uri="/search"
| stats count by clientip
| sort -count

index="main" uri="/search"
| stats dc(clientip)

index="main" uri="/search"
| stats count by useragent
| sort -count

index="main" uri="/search"
| timechart span=1s count

index="main" status=503
| sort _time
| table _time clientip status

3. Verdict & Scope
Confirmed actual DoS/DDoS attack (not a false positive). Scope: the /login and /search endpoints on the bicycle parts web application. Server availability was impacted, evidenced by cascading 503 errors to legitimate users (10.10.0.27 and others) following the traffic flood.

4. Remediation

    Block/rate-limit 203.12.23.195 and the identified 60-IP botnet at the WAF/firewall level.
    Implement rate-limiting rule on /login and /search (e.g., max 5 requests/min per IP).
    Deploy CAPTCHA or JS challenge on high-value endpoints (/login, /search).
    Enable CDN caching and load-balancing to absorb future traffic spikes.
    Add SIEM alert for burst patterns exceeding baseline (e.g., >50 req/sec to a single URI).

