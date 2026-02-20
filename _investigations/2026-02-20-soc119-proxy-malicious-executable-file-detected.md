---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1204
date: 2026-01-22
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC119
title: SOC119 - Proxy - Malicious Executable File Detected
youtube: https://www.youtube.com/watch?v=ad9d4YNMy_8
---
## 🎯 MITRE ATT&CK
T1204 User Execution

### 👤 Who
Endpoint 172.16.17.5 accessed a URL that triggered the SOC119 Proxy Malicious Executable File Detected alert.

### 🔎 What
The alert was generated after the endpoint accessed [https://www.win-rar.com/postdownload.html?&L=0&Version=32bit](https://www.win-rar.com/postdownload.html?&L=0&Version=32bit) which was flagged as a potential malicious executable download. The URL was analyzed in VirusTotal and returned no malicious detections. Investigation confirmed the domain win-rar.com is the legitimate WinRAR distribution website used for archive extraction software. No malicious file execution or suspicious endpoint activity was observed.

### 🕐 When
Event Time Mar 21 2021 01:02 PM  
Alert Closed Jan 22 2026 09:34 AM

### 📍 Where
Endpoint 172.16.17.5  
URL [https://www.win-rar.com/postdownload.html?&L=0&Version=32bit](https://www.win-rar.com/postdownload.html?&L=0&Version=32bit)  
Event ID 83  
Rule SOC119 Proxy Malicious Executable File Detected

### 💡 Why
The alert was triggered due to proxy detection logic identifying an executable download pattern. Analysis confirmed the URL is legitimate and no malicious behavior occurred on the endpoint. No indicators of compromise were identified. The alert was assessed as a False Positive and no further action was required.
