---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1190
  - mitre/T1059
date: 2026-03-19
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC127e60
title: SQL Injection Detected event 60
youtube: https://www.youtube.com/watch?v=Zi-NlBVcSKY
---
T1190 Exploit Public-Facing Application
T1059 Command and Scripting Interpreter

### 👤 Who
The activity originated from host PentestMachine (IP address 172.16.20.5) by user kali as part of an internal penetration test.

### 🔎 What
The alert SOC127 SQL Injection Detected triggered due to a crafted SQL injection payload sent to the web application hosted on gitServer (IP address 172.16.20.4). The request URL contained a UNION-based SQL injection attempt:
https://172.16.20.4/?id=1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)
The user agent explicitly indicates "Penetration Test - Do not Contain", confirming the activity is part of an authorized security assessment.

### 🕐 When
Feb 14 2021 01:05 PM

### 📍 Where
Source Hostname: PentestMachine
Source IP Address: 172.16.20.5
Destination Hostname: gitServer
Destination IP Address: 172.16.20.4
Target URL: https://172.16.20.4/

### 💡 Why
The alert was triggered due to detection of a SQL injection payload targeting a public-facing web application. The activity is confirmed malicious in nature as it attempts to exploit a database vulnerability. However, based on the user agent and context, the activity is part of an authorized internal penetration test. Therefore, the alert is classified as a true positive but expected behavior and does not require containment.
