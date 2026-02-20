---
title: "Lumma Stealer - DLL Side-Loading via Click Fix Phishing"
type: soc-case
platform: letsdefend
status: closed
severity: critical
tags:
  - spearphishing
  - mitre/T1566-001
  - mitre/T1204-002
  - mitre/T1218
  - mitre/T1059
  - mitre/T1105
date: 2026-02-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC338
youtube: https://www.youtube.com/watch?v=9uLtQAU2Y84
---
ALERT SUMMARY

MITRE ATTCK  
T1566 Spearphishing  
T1204 User Execution  
T1218 Mshta  
T1059 PowerShell  
T1105 Ingress Tool Transfer

WHO  
External sender update at windows update site from IP 132.232.40.201 sent phishing email to dylan at letsdefend dot io  
Malicious infrastructure overcoatpassably dot shop used for payload delivery

WHAT  
Phishing email lure offering free Windows 11 upgrade led to malicious redirection and execution of Lumma Stealer via DLL side loading  
Hidden PowerShell executed mshta to download remote payload

WHEN  
Mar 13 2025 09 44 AM

WHERE  
User mailbox dylan at letsdefend dot io  
Endpoint executed PowerShell from Windows System32  
Outbound connection to overcoatpassably dot shop

WHY  
Attacker used Click Fix style phishing to trick user into executing remote payload  
Goal was to deliver Lumma Stealer for credential theft and data exfiltration

HOW  
Email contained link to windows update site  
Site redirected to overcoatpassably dot shop  
PowerShell executed command mshta exe to retrieve maloy dot mp4 payload  
Logs confirm successful GET request to malicious domain  
Endpoint telemetry confirms malicious PowerShell execution

IMPACT  
Confirmed phishing leading to remote code execution and malware delivery  
High risk of credential theft and data leakage

ACTION TAKEN  
Escalated as confirmed compromise  
Contain endpoint immediately  
Block malicious domains and IP addresses  
Reset user credentials  
Perform full malware scan and forensic investigation

OUTCOME  
True Positive confirmed Lumma Stealer infection requiring incident response