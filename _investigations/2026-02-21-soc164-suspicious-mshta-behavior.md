---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1218-005
  - mitre/T1059-001
  - mitre/T1105
  - mitre/T1027
  - mshta
date: 2026-02-21
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC164
title: Suspicious Mshta Behavior
youtube: https://www.youtube.com/watch?v=DmN7Gg9VsYA
---

## 🎯 MITRE ATT&CK
T1218.005 Mshta  
T1059.001 PowerShell  
T1105 Ingress Tool Transfer  
T1027 Obfuscated Files or Information

### 👤 Who
Suspicious activity was observed on host Roberto 172.16.17.38 where mshta.exe executed a low reputation HTA file Ps1.hta from the user Desktop directory.

### 🔎 What
The binary C:\Windows\System32\mshta.exe was used to execute Ps1.hta. Deobfuscation of the script revealed it dynamically constructed a WebClient DownloadString call to retrieve a remote payload from [http://193.142.58.23/Server.txt](http://193.142.58.23/Server.txt). Network logs confirmed an outbound connection attempt to 193.142.58.23. VirusTotal intelligence flags 193.142.58.23 as malicious. This indicates mshta was abused as a Living Off The Land Binary to stage a remote payload.

### 🕐 When
Mar 05 2022 10:29 AM

### 📍 Where
Hostname Roberto  
IP Address 172.16.17.38  
Binary Path C:\Windows\System32\mshta.exe  

The alert was confirmed as a True Positive. The host Roberto was isolated for containment. Malicious file Ps1.hta was removed. Indicators of compromise including 193.142.58.23 were blocked.