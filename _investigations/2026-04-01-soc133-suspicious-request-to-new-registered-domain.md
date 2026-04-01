---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1583-001
date: 2026-04-01
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC133
title: Suspicious Request to New Registered Domain
youtube: https://www.youtube.com/watch?v=ZI8eYRerTbU
---
### 🔎 What
The alert SOC133 Suspicious Request to New Registered Domain triggered after host KatharinePRD accessed the domain amesiana.com, which was registered one day prior. Analysis shows a single connection with no further suspicious activity or follow-on requests.

### 🕐 When
Feb 28 2021 07:57 PM

### 📍 Where
Host KatharinePRD (172.16.15.78), user Leo, connected to amesiana.com (23.227.38.71)

### 💡 Why
The alert was triggered because the domain was newly registered, which can indicate potential malicious infrastructure. However, investigation shows no malicious indicators. VirusTotal and IP reputation checks are clean, no additional connections were observed, and no evidence of phishing or malware delivery was found. The activity is classified as a false positive.

## 🎯 MITRE ATT&CK

T1583.001 Acquire Infrastructure Domains
Newly registered domain characteristic often used by attackers (contextual only, no confirmed malicious use)
