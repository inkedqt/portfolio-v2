---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1059-001
  - mitre/T1105
  - mitre/T1027
  - mitre/T1071-001
date: 2026-04-02
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC102
title: Proxy - Suspicious URL Detected
youtube: https://www.youtube.com/watch?v=lonVO0NrCUQ
---
## 🎯 MITRE ATT&CK

T1059.001 Command and Scripting Interpreter PowerShell
Obfuscated PowerShell used to download and execute remote script

T1105 Ingress Tool Transfer
Remote script retrieved from external server

T1027 Obfuscated Files or Information
Use of character encoding and string manipulation to hide command intent

T1071.001 Application Layer Protocol Web Protocols
HTTPS communication to external domain


### 🔎 What
The alert SOC102 Proxy Suspicious URL Detected triggered after host Aldo executed a PowerShell command that downloaded and executed a remote script from https://interalliance.org/come2/holme/folde/swiftcopy.ps1. The command uses obfuscation and Net.WebClient to retrieve and execute the script in memory, indicating likely malicious activity.

### 🕐 When
Dec 06 2020 01:33 PM

### 📍 Where
Host Aldo (172.16.17.51) connected to interalliance.org (66.198.240.56) over HTTPS and executed a PowerShell command to download and run swiftcopy.ps1

### 💡 Why
The alert was triggered due to access to a suspicious URL. Investigation shows obfuscated PowerShell execution using IEX style behavior to download and execute a remote script, which is a common malware technique. Although no direct threat intelligence confirms the domain or IP as malicious, the behavior strongly indicates a fileless malware execution attempt. The host was contained and escalated for further investigation
