---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1105
  - mitre/T1078
  - bruteforce
date: 2026-03-05
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC346
title: Forced Authentication Detected
youtube: https://www.youtube.com/watch?v=YCC3rYv0UIM
---

T1110 Brute Force  
T1078 Valid Accounts

### 👤 Who
An external attacker from IP address 120.48.36.175 targeted the web application hosted on WebServer_Test (104.26.15.61). The attacker attempted authentication against the admin account on the web application.

### 🔎 What
The alert SOC246 Forced Authentication Detected triggered due to multiple POST requests sent to the /accounts/login endpoint. Log analysis confirmed a brute force attempt against the login page. The attacker eventually succeeded in authenticating using the credentials admin:password. The requests originated from a browser user-agent Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0 and resulted in a successful login to the admin account, indicating a compromise through weak credentials.

### 🕐 When
Dec 12 2023 02:15 PM

### 📍 Where
Source IP 120.48.36.175  
Destination IP 104.26.15.61  
Host WebServer_Test  
Target Endpoint [http://test-frontend.letsdefend.io/accounts/login](http://test-frontend.letsdefend.io/accounts/login)

### 💡 Why
The alert was triggered because multiple authentication attempts were detected from the same source IP against the login endpoint. Investigation confirmed the activity was a brute force attack which resulted in a successful login to the admin account using weak credentials. The web server appears to be an external development server and the SOC analyst does not have access to endpoint controls to immediately contain the system. The incident should be escalated to the Level 2 security team to reset compromised credentials, investigate potential malicious activity performed after login, and implement mitigation measures such as account lockout policies and stronger password requirements.