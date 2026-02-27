---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1566-001
  - mitre/T1056
  - phishing
date: 2026-02-27
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC143
title: Password Stealer Detected
youtube: https://www.youtube.com/watch?v=BS44B5w17KI
---
## 🎯 MITRE ATT&CK
T1566 Phishing  
T1056 Credential Harvesting

### 👤 Who
External sender bill@microsoft.com using SMTP IP 180.76.101.229 targeted ellie@letsdefend.io

### 🔎 What
Malicious HTML attachment delivering a password stealer phishing page. Dynamic analysis in AnyRun confirmed credential harvesting behavior and C2 domain tecyardit.com

### 🕐 When
Apr 26 2021 23:03 PM

### 📍 Where
Email delivered through Exchange to ellie@letsdefend.io. Phished credentials configured to be sent to tecyardit.com

### 💡 Why
Credential harvesting attempt to steal username and password for account compromise

## 🧠 Analysis
Attachment executed in sandbox showed fake login page capturing credentials and posting to tecyardit.com. No outbound connections to tecyardit.com observed in network logs. User did not open attachment. True Positive malicious attachment but no successful compromise

Action  
Email contained. Indicators documented including tecyardit.com and 180.76.101.229. No endpoint isolation required. Monitoring continued for related activity.
