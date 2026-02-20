---
title: "Application Token Steal Attempt Detected"
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - phishing
  - mitre/T1566-002
  - mitre/T1056
  - mitre/T1078
date: 2026-02-08
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC275
youtube: https://www.youtube.com/watch?v=Sr_fc_LakM0
---
## 🎯 MITRE ATT&CK
T1566.002 Phishing Link  
T1056 Input Capture  
T1078 Valid Accounts

### 🔎 What
User gloriana@letsdefend.io interacted with a phishing reset-password link hosted on homespottersf.com over port 8081. The user first issued a GET request resulting in a 302 redirect, followed by a POST request to /reset-password with a token parameter, receiving HTTP 200. This indicates form submission to a suspicious external domain.

### 🕐 When
19 Apr 2024 08:23 UTC

### 📍 Where
Source IP 172.16.17.172  
Destination IP 23.82.12.29  
Destination Port 8081  
Domain homespottersf.com

### 👤 Who
User gloriana@letsdefend.io  
Internal host 172.16.17.172

### 💡 Why
The POST request confirms user interaction beyond simply clicking the phishing link. The reset-password endpoint and token parameter strongly indicate credential harvesting or account takeover attempt. The HTTP 200 response suggests the malicious server successfully received the submitted data.

How  
The user accessed a phishing reset-password link. After redirection, the user submitted data via HTTP POST to the malicious server. This behavior is consistent with credential phishing and possible compromise.

Containment Action  
The affected machine was isolated to prevent further malicious communication and reduce risk of lateral movement or credential abuse.

Conclusion  
This is a confirmed phishing interaction with form submission. There is high risk of credential compromise. Immediate containment was appropriate to prevent further impact.