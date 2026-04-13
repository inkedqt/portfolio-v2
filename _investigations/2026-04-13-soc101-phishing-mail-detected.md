---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1566-001
  - mitre/T1105
  - mitre/T1071-001
  - phishing
date: 2026-04-13
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC101
title: Phishing Mail Detected Event 29
youtube: https://www.youtube.com/watch?v=kHKBA6JkeB4
---
## 🎯 MITRE ATT&CK

T1566.001 Phishing Attachment
Malicious email attachment used as initial infection vector

T1105 Ingress Tool Transfer
Payload delivery mechanism via attachment

T1071.001 Application Layer Protocol Web Protocols
Potential communication channel for C2 if executed

### 🔎 What
The alert SOC101 Phishing Mail Detected triggered after an email with subject Invoice was sent from icianb@hotmail.com to sofia@letsdefend.io. The email contained an attachment identified as malicious and associated with Cobalt Strike based on VirusTotal and sandbox analysis.

### 🕐 When
Oct 29 2020 07:43 PM

### 📍 Where
Email sent from 191.233.193.73 to sofia@letsdefend.io

### 💡 Why
The alert was triggered due to detection of a phishing email containing a malicious attachment. Threat intelligence confirms the file is associated with Cobalt Strike. The email was blocked by security controls and no network connections or execution activity were observed on the endpoint. The activity is classified as a true positive phishing attempt with no successful compromise

