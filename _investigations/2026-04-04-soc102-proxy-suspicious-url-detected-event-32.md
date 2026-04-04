---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1071-001
date: 2026-04-04
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC102
title: Proxy - Suspicious URL Detected event 32
youtube: https://www.youtube.com/watch?v=1PMK6j7896c
---
## 🎯 MITRE ATT&CK

T1071.001 Application Layer Protocol Web Protocols


### 🔎 What
The alert SOC102 Proxy Suspicious URL Detected triggered after host MikeComputer attempted to access a URL on encrypted-tbn0.gstatic.com. Analysis confirms the URL points to a static image file (image.jpg) with no malicious content or behavior.

### 🕐 When
Dec 01 2020 05:50 AM

### 📍 Where
Host MikeComputer (172.148.17.14), user Mike01, attempted connection to encrypted-tbn0.gstatic.com (172.217.17.174)

### 💡 Why
The alert was triggered due to the domain pattern and detection rules flagging the request as suspicious. Investigation using sandbox and file analysis confirms the content is a legitimate image with no malicious indicators. No additional suspicious activity or follow-on connections were observed. The activity is classified as a false positive

