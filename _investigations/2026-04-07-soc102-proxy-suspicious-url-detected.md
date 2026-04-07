---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1204-001
  - mitre/T1105
  - mitre/T1071-001
date: 2026-04-07
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC102
title: Proxy - Suspicious URL Detected
youtube: https://www.youtube.com/watch?v=S4qZ2K2cEzE
---
## 🎯 MITRE ATT&CK

T1204.001 User Execution Malicious Link
User interaction likely initiated the request

T1105 Ingress Tool Transfer
Attempted download of malicious executable

T1071.001 Application Layer Protocol Web Protocols
HTTP communication to external malicious infrastructure

### 🔎 What
The alert SOC102 Proxy Suspicious URL Detected triggered after host BillPRD attempted to download ac.exe from jamesrlongacre.ac.ug. The request was made via chrome.exe and was blocked by security controls. VirusTotal confirms the URL is malicious.

### 🕐 When
Oct 29 2020 07:05 PM

### 📍 Where
Host BillPRD (172.16.17.47), user Bill, attempted connection to jamesrlongacre.ac.ug (217.8.117.77)

### 💡 Why
The alert was triggered due to a request to a suspicious URL hosting a malicious executable. Although the user agent suggests a firewall test, prior notification only referenced testing against IP 115.99.150.132 and not this domain or IP. VirusTotal confirms the requested URL is malicious, and the request was successfully blocked before execution. The activity is classified as a true positive with no evidence of compromise

