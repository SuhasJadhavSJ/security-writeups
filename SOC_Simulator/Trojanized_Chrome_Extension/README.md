1. Incident Summary

Alerts fired on the finance workstation halv-fin-wks-217 (user priya.raman) after the Chrome extension GraphQL Network Inspector auto-updated to v2.22.6 at 13:43. The EDR flagged two new JS files (critical). The proxy then flagged the workstation contacting a never-before-seen domain (medium, then high), followed by POST requests carrying about 7 KB of data outbound to an external server (critical). No executable was dropped, so the proxy and browser telemetry were the only trail.

2. Analysis: Key IOCs

| Type                             | Value                                                              |
| -------------------------------- | ------------------------------------------------------------------ |
| C2 domain                        | `graphqlnetwork.pro` (config fetch, `/ai-graphqlnetwork`)          |
| Exfil host                       | `app.graphqlnetwork.pro/collect`                                   |
| IPs                              | `149.28.124.84`, `45.76.225.148` (config); `149.248.2.160` (exfil) |
| Beacon file (background.js)      | `b0827dc54349b10098a7370ada4ea44ba668b264ccca2db5676be1c32e6cc154` |
| Harvester (context_responder.js) | `d303047205dabec8e2d34431e920ebe3478ca80a18f57bf454da094aca0e10aa` |
| Extension ID                     | `ndlbedplllcgconngcnfmkadhokfaaln` v2.22.6                         |
| Local storage key                | `graphqlnetwork_ext_manage`                                        |
| MITRE ATT&CK                     | `T1195.002`, `T1176`, `T1071.001`, `T1539`, `T1528`, `T1041`       |


Key evidence: the exfil POSTs sent 7,340 and 2,210 bytes out with only 48-byte replies, the reverse of normal browsing. One domain was also answered by different IPs, so a single IP block is not enough. There were no command lines or Windows Event IDs in this dataset. The attack ran entirely inside the browser (fileless), so the detection relied on proxy, Chrome telemetry and EDR file inventory.

3. Verdict & Scope

True Positive: confirmed compromise. The extension beaconed to attacker infrastructure, stored its harvesting config, read session cookies and a token at 14:06, and exfiltrated them at 14:09 and 14:14.

Assets affected:

    Host: halv-fin-wks-217 (10.145.30.217)
    User: priya.raman, whose session cookies and API token were stolen
    Not confirmed: any other machines. A fleet-wide hunt is still needed.

Because a session cookie was stolen and not a password, the attacker can access the account without a password or MFA until the sessions are revoked.

4. Remediation

    Isolate halv-fin-wks-217 from the network.
    Revoke all of priya.raman's active sessions and rotate the exposed API token (a password reset alone won't stop a stolen cookie).
    Block graphqlnetwork.pro, app.graphqlnetwork.pro and all three IPs at the proxy and firewall.
    Remove the extension and add an extension allowlist policy.
    Hunt fleet-wide for the extension ID/version, both hashes, the storage key and the domain/IPs.
    Monitor priya.raman's account for the stolen session being replayed from unusual IPs after 14:09, and escalate to L2/IR.
