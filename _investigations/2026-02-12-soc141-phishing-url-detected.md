---
title: "Phishing URL Detected"
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - phishing
  - mitre/T1566-001
  - mitre/T1204-002
date: 2026-02-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC141
---
ALERT SUMMARY

MITRE ATT&CK  
T1566 – Phishing  
T1204 – User Execution

WHO:  
Internal endpoint 172.16.17.49.  
Malicious external domain mogagrocol.ru.

WHAT:  
User attempted to access a known malicious phishing URL.  
Initial outbound connection was allowed, followed by a blocked attempt by the firewall.

WHEN:  
Mar 22, 2021 at 09:23 PM.

WHERE:  
Outbound web traffic from 172.16.17.49 to mogagrocol.ru via proxy/firewall.

WHY:  
User likely clicked a phishing link, resulting in outbound connection attempt to known malicious infrastructure.

HOW:  
HTTP/HTTPS request initiated from endpoint.  
First connection allowed before firewall enforcement blocked subsequent traffic.

IMPACT:  
Partial exposure confirmed.  
Endpoint considered potentially compromised due to successful initial connection.  
Risk of payload delivery, credential harvesting, or drive-by compromise.

ACTION TAKEN:  
Escalated to L2 / Incident Response.  
Recommended:

- Perform EDR review on endpoint
    
- Run malware scan
    
- Check browser history and download artifacts
    
- Reset user credentials if necessary
    
- Block domain and related IoCs at firewall/proxy
    

OUTCOME:  
True Positive – phishing URL accessed with partial network exposure.