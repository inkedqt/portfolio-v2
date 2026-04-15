---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
date: 2026-04-14
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC106
title: Found Suspicious File - TI Data
youtube: https://www.youtube.com/watch?v=-A9x3R0V0b0
---
### 🔎 What
The alert SOC106 Found Suspicious File - TI Data triggered after detection of ChromeSetup.exe on host ChanProd. The file was flagged by threat intelligence but analysis shows the hash is clean on VirusTotal. Static analysis (strings) indicates valid DigiCert signing, and sandbox execution shows normal Chrome installer behavior with no malicious activity.

### 🕐 When
Sep 22 2020 11:10 AM

### 📍 Where
Host ChanProd (172.16.17.150) detected ChromeSetup.exe locally

### 💡 Why
The alert was triggered due to a threat intelligence match on the file. However, further investigation confirms the file is a legitimate Chrome installer. No malicious behavior or suspicious network activity was observed during sandbox execution. The activity is classified as a false positive
