---
type: soc-case
platform: letsdefend
status: closed
severity: critical
tags:
  - mitre/T1071-001
  - mitre/T1036
date: 2026-03-31
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC110
title: Proxy - Cryptojacking Detected
youtube: https://www.youtube.com/watch?v=OBtvgBEQi9I
---
## 🎯 MITRE ATT&CK

T1071.001 – Application Layer Protocol: Web Protocols
HTTP/HTTPS communication to external web services (bit.ly and YouTube).

T1036 – Masquerading
Use of URL shortening services can obscure final destinations, commonly used in phishing campaigns, but no malicious intent observed here.

### 🔎 What
The alert SOC110 Proxy Cryptojacking Detected triggered after host BillPRD accessed a shortened URL https://bit.ly/3hNuByx. Analysis of the URL using curl and historical VirusTotal data confirms it redirects to a YouTube video (Rick Astley – Never Gonna Give You Up) and is not associated with cryptojacking or malicious activity.

### 🕐 When
Jan 02 2021 04:33 AM

### 📍 Where
Host BillPRD (172.16.17.47), user Bill, accessed bit.ly (67.199.248.10). The shortened URL redirected to youtube.com, a legitimate domain.

### 💡 Why
The alert was triggered due to detection rules flagging shortened URLs (bit.ly), which are commonly abused for malicious redirection. However, investigation confirms the destination is a legitimate YouTube video with no evidence of cryptojacking, malicious scripts, or further suspicious network activity. No additional connections or payload delivery were observed. The activity is classified as a false positive.
