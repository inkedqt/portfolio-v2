---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1566-001
  - mitre/T1204
  - mitre/T1059-001
  - mitre/T1105
  - phishing
  - powershell
date: 2026-02-28
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC205
title: Malicious Macro has been executed
youtube: https://www.youtube.com/watch?v=4YHuizOa60k
---
## 🎯 MITRE ATT&CK
T1566 Phishing
T1204 User Execution
T1059.001 PowerShell
T1105 Ingress Tool Transfer

### 👤 Who
User Jayne on host 172.16.17.198 opened malicious attachment edit1-invoice.docm sent from jake.admin@cybercommunity.info

### 🔎 What
Macro executed via InkEdit1_GotFocus which launched cmd.exe and PowerShell to download messbox.exe from http://www.greyhathacker.net/tools/messbox.exe and save as mess.exe

### 🕐 When
Feb 28 2024 08:42 AM

### 📍 Where
File located in Downloads folder. Outbound HTTP GET request to http://www.greyhathacker.net/tools/messbox.exe from powershell.exe

### 💡 Why
Phishing email delivering macro enabled document to download and execute remote malware

## 🧠 Analysis
olevba confirmed auto execution and PowerShell DownloadFile behavior. Network logs show HTTP 404 response so payload not retrieved. No evidence of successful execution. True Positive macro execution without second stage compromise

Action
Host contained email removed file deleted and monitoring continued