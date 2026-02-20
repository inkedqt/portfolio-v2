---
title: "CVE‑2025‑53770 SharePoint ToolShell Auth Bypass and RCE"
type: soc-case
platform: letsdefend
status: closed
severity: critical
tags:
  - sharepoint
  - cve-2025-53770
  - mitre/T1190
  - mitre/T1059-001
  - mitre/T1505-003
date: 2026-02-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC342
---
ALERT SUMMARY

## 🎯 MITRE ATT&CK
T1190 – Exploit Public-Facing Application  
T1059.001 – Command and Scripting Interpreter: PowerShell  
T1505.003 – Server Software Component: Web Shell

---

WHO:  
External attacker from IP 107.191.58.76 targeting on-premises SharePoint server SharePoint01 (172.16.20.17). The source IP is flagged as malicious on VirusTotal, further supporting hostile activity.

WHAT:  
Confirmed exploitation of CVE-2025-53770 (ToolShell) SharePoint authentication bypass and remote code execution vulnerability. An unauthenticated POST request targeted /_layouts/15/ToolPane.aspx with a large payload. EDR telemetry confirms execution of obfuscated PowerShell commands at the same time as the web request. Base64 decoding of the payload revealed a malicious ASPX script designed to extract MachineKey configuration values.

WHEN:  
Jul 22, 2025 at 01:07 PM.

WHERE:  
SharePoint01 (172.16.20.17) – HTTP POST request to /_layouts/15/ToolPane.aspx. Malicious PowerShell execution observed locally on the same host via EDR.

WHY:  
Attacker exploited ToolShell authentication bypass to achieve remote code execution. Post-exploitation behavior focused on extracting cryptographic machine keys, likely to enable authentication token forgery, persistence, and further lateral movement.

HOW:  
Unauthenticated POST request with spoofed referer triggered the vulnerable ToolPane endpoint. Payload delivery resulted in obfuscated PowerShell execution. Decoded Base64 blob revealed ASPX code using .NET reflection to access System.Web.Configuration.MachineKeySection and extract ValidationKey and DecryptionKey values. Firewall action was allowed, confirming successful exploitation and host compromise.

IMPACT:  
Confirmed remote code execution and post-exploitation activity. Extraction of machine keys enables potential authentication bypass and persistence. Host must be treated as fully compromised.

ACTION TAKEN:  
Escalated as confirmed critical compromise.  
Immediate containment required:

- Isolate SharePoint01 from network
    
- Rotate machine keys and reset service credentials
    
- Review IIS logs for additional web shell artifacts
    
- Perform full forensic acquisition and IR investigation
    
- Block source IP at perimeter
