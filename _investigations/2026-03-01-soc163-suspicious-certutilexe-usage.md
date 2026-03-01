---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1105
  - mitre/T1218
  - LOLBin
  - certutil
date: 2026-03-01
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC163
title: Suspicious Certutil.exe Usage
youtube: https://www.youtube.com/watch?v=06CnROH8rVM
---
## 🎯 MITRE ATT&CK
T1105 Ingress Tool Transfer  
T1218 Signed Binary Proxy Execution

### 👤 Who
User on host EricProd 172.16.17.22 executed certutil.exe via cmd.exe spawned from explorer.exe indicating user initiated activity

### 🔎 What
certutil.exe was used with -urlcache -split -f parameters to download external tools including nmap-7.92-win32.zip from nmap.org and windows-exploit-suggester.py from GitHub. This is Living Off The Land Binary abuse to download tooling.

### 🕐 When
Mar 01 2022 11:06 AM initial certutil execution. Subsequent outbound connections observed at 11:15 AM and 11:16 AM to internal hosts over port 80.

### 📍 Where
Host EricProd IP 172.16.17.22 downloaded files from external domains and initiated HTTP connections to 192.168.0.15 and 192.168.0.16 indicating internal network scanning activity.

### 💡 Why
User likely used certutil as a LOLBin to download reconnaissance tools and scan the local network. Activity appears user driven rather than automated malware. No evidence of persistence or command and control.

Conclusion  
True Positive. Suspicious certutil usage confirmed for tool download and internal scanning. Recommend user validation and monitoring for further lateral movement or privilege escalation attempts.
