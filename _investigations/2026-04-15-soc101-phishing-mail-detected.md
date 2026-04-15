---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
date: 2026-04-15
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC101
title: SOC101 - Phishing Mail Detected Event 24
youtube: https://www.youtube.com/watch?v=RbRc1K-a6Og
---
## 🎯 MITRE ATT&CK

T1566.001 Phishing Attachment
Malicious email attachment used as initial infection vector

T1204.002 User Execution Malicious File
User execution would be required to trigger infection

T1059.001 Command and Scripting Interpreter PowerShell
Emotet commonly uses PowerShell for payload execution

T1105 Ingress Tool Transfer
Payload delivery via malicious attachment

T1071.001 Application Layer Protocol Web Protocols
Communication with command and control infrastructure

### 🔎 What
The alert SOC101 Phishing Mail Detected triggered after an email with subject Covid-19 News! was sent from darcy.downey@gmail.com to james@letsdefend.io. The email contained an attachment (hash 1ceda3ccc4e450088204e23409904fa8) identified as Emotet malware. Sandbox analysis revealed associated C2 infrastructure including kpfniaga.com and IP 218.208.91.143.

### 🕐 When
Oct 25 2020 09:32 PM

### 📍 Where
Email sent from 173.194.68.27 to james@letsdefend.io. Associated infrastructure includes kpfniaga.com and 218.208.91.143

### 💡 Why
The alert was triggered due to detection of a phishing email containing a malicious attachment. Threat intelligence confirms the file is Emotet malware. The email was blocked and no connections to the identified C2 infrastructure were observed, indicating the attachment was not executed. The activity is classified as a true positive phishing attempt with no successful compromise
