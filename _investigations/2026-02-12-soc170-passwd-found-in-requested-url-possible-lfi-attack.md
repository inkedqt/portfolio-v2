---
title: "Passwd Found in Requested URL - Possible LFI Attack"
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - LFI
  - mitre/T1190
  - mitre/T1006
date: 2026-02-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC170
---
## 🎯 MITRE ATT&CK
T1190 – Exploit Public-Facing Application  
T1006 – Path Traversal

WHO:  
External attacker from IP 106.55.45.162 targeting public web server.

WHAT:  
Local File Inclusion (LFI) attempt detected via directory traversal payload in HTTP request.

WHEN:  
Mar 01, 2022 at 10:10 AM.

WHERE:  
Public-facing web application. Payload observed in HTTP request parameter attempting access to /etc/passwd.

WHY:  
Attacker attempted to exploit LFI vulnerability to read sensitive system file (/etc/passwd) through directory traversal.

HOW:  
HTTP request contained traversal payload:  
?file=../../../../etc/passwd

Web server responded with HTTP 500 status code and 0-byte response size, indicating the request failed and file inclusion was not successful.

IMPACT:  
Attack attempt confirmed malicious but unsuccessful. No evidence of file disclosure.

ACTION TAKEN:  
Alert classified as True Positive (unsuccessful exploitation).  
No containment required.  
No escalation required.  
Recommended continued monitoring for repeat attempts from same source IP.

OUTCOME:  
Confirmed LFI attack attempt. Exploitation unsuccessful.
