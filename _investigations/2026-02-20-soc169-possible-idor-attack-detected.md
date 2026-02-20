---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1190
  - mitre/T1087
date: 2026-01-20
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC169
title: SOC169 - Possible IDOR Attack Detected
youtube: https://www.youtube.com/watch?v=FNAWgTI8BOU
---

## 🎯 MITRE ATT&CK
T1190 Exploit Public Facing Application  
T1087 Account Discovery

### 👤 Who
External source IP address 134.209.118.137 associated with AS14061 DIGITALOCEAN ASN initiated suspicious web requests against WebServer1005 with IP 172.16.17.15.

### 🔎 What
SOC169 Possible IDOR Attack Detected alert was triggered after multiple HTTP requests showed modified object identifier values in application parameters. Log analysis confirmed the attacker manipulated ID values to access data belonging to different users. The server returned HTTP 200 status codes with varying response sizes, indicating successful retrieval of unauthorized data. This confirms an Insecure Direct Object Reference vulnerability was exploited.

### 🕐 When
Event Time Feb 28 2022 10:48 PM  
Alert Closed Jan 20 2026 08:42 AM

### 📍 Where
Affected Host WebServer1005  
IP Address 172.16.17.15  
Source IP 134.209.118.137  
Event ID 119  
Rule SOC169 Possible IDOR Attack Detected

### 💡 Why
The attacker modified object identifiers in web requests to access other users data. The HTTP 200 responses and differing response sizes confirm the attack was successful. The affected host was contained and the incident requires escalation to Tier 2 for remediation of the IDOR vulnerability and further impact assessment. The alert was assessed as a True Positive.