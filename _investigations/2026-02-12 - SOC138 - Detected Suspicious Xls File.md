---
title: "Detected Suspicious Xls File"
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - malware
  - mitre/T1566-001
  - mitre/T1105
date: 2026-02-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC138
---
ALERT SUMMARY

MITRE ATT&CK  
T1566.001 – Spearphishing Attachment  
T1105 – Ingress Tool Transfer

WHO:  
Compromised internal endpoint 172.16.17.56.  
External C2 server at 177.53.143.89.

WHAT:  
Malicious XLSM (macro-enabled Excel) file named "ORDER SHEET & SPEC.xlsm" executed on the endpoint.  
Successful outbound C2 communication observed over HTTPS (port 443).

WHEN:  
Mar 13, 2021 at 08:20 PM.

WHERE:  
Internal host 172.16.17.56 initiated outbound connection to external IP 177.53.143.89 over TCP 443.

WHY:  
User executed malicious macro-enabled spreadsheet, triggering malware execution and establishing command-and-control communication.

HOW:  
XLSM file executed on endpoint.  
Malware initiated outbound HTTPS session to external infrastructure, confirming active infection and remote communication capability.

IMPACT:  
Confirmed malware infection with active C2 communication.  
High risk of data exfiltration, credential theft, or lateral movement.

ACTION TAKEN:  
Host containment required (isolate endpoint).  
Terminate malicious processes.  
Block external IoC 177.53.143.89.  
Reset potentially compromised credentials.  
Escalated to L2 for full remediation and forensic investigation.

OUTCOME:  
True Positive – confirmed active infection with successful C2 communication.
