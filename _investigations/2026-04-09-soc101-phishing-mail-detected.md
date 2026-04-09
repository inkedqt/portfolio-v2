---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1566-001
  - mitre/T1204-002
  - mitre/T1059-001
  - mitre/T1105
  - mitre/T1071-001
  - phishing
date: 2026-04-09
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC101
title: SOC101 - Phishing Mail Detected Event 25
youtube: https://www.youtube.com/watch?v=AYIkPMy_brg
---
## 🎯 MITRE ATT&CK

T1566.001 Phishing Attachment
Malicious email attachment used as initial infection vector

T1204.002 User Execution Malicious File
User would need to open attachment to trigger execution

T1059.001 Command and Scripting Interpreter PowerShell
Macro executes PowerShell payload

T1105 Ingress Tool Transfer
Payload delivery from external infrastructure

T1071.001 Application Layer Protocol Web Protocols
Communication with command and control servers

### 🔎 What
The alert SOC101 Phishing Mail Detected triggered after an email with subject UPS Your Packages Status Has Changed was sent from aaronluo@cmail.carleton.ca to mark@letsdefend.io. Analysis of the attachment using olevba confirms it contains malicious macros that execute a PowerShell script. VirusTotal identifies the file as Emotet malware. Detonation in sandbox revealed command and control IPs 15.197.142.173, 51.79.149.160, and 2.57.91.92.

### 🕐 When
Oct 29 2020 06:40 PM

### 📍 Where
Email sent from 157.230.109.166 to mark@letsdefend.io. Associated C2 infrastructure includes IPs 15.197.142.173, 51.79.149.160, and 2.57.91.92

### 💡 Why
The alert was triggered due to detection of a phishing email containing a malicious attachment. Analysis confirms the attachment executes a PowerShell-based payload and is associated with Emotet malware. The email was blocked and no connections to the identified C2 infrastructure were observed, indicating the payload was not executed. The activity is classified as a true positive with no successful compromise

