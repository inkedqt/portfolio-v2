---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1566-001
  - mitre/T1204-002
  - mitre/T1071-001
  - phishing
date: 2026-01-22
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC114
title: SOC114 - Malicious Attachment Detected - Phishing
youtube: https://www.youtube.com/watch?v=4Iy8K7yG9qo
---
## 🎯 MITRE ATT&CK
T1566.001 Phishing Attachment  
T1204.002 Malicious File  
T1071.001 Application Layer Protocol

### 👤 Who
A phishing email containing a malicious PowerPoint attachment was delivered to a user on endpoint richardPRD with IP address 172.16.17.45.

### 🔎 What
SOC114 Malicious Attachment Detected Phishing Alert was triggered after the attachment was identified as malicious. The file hash 44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795 was flagged in VirusTotal as a trojan. The attachment was detonated in ANY.RUN but was password protected and did not display runtime behavior during sandbox analysis. However, review of command and control indicators listed on VirusTotal revealed matching outbound network connections from endpoint richardPRD to known malicious infrastructure, confirming compromise.

### 🕐 When
Event Time Jan 31 2021 03:48 PM  
Alert Closed Jan 22 2026 02:04 AM

### 📍 Where
Endpoint richardPRD  
IP Address 172.16.17.45  
Malicious Attachment PowerPoint file  
MD5 44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795  
Event ID 45  
Rule SOC114 Malicious Attachment Detected Phishing Alert

### 💡 Why
The email contained a malicious attachment that was confirmed as a trojan through threat intelligence analysis. Although sandbox execution did not immediately reveal behavior due to password protection, log analysis confirmed outbound communication to known malicious infrastructure. The endpoint was contained to prevent further impact and the incident was escalated for remediation. The alert was assessed as a True Positive.
