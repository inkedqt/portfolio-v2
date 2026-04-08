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
date: 2026-04-08
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC101
title: Phishing Mail Detected
youtube: https://www.youtube.com/watch?v=9C3J5QxIOhk
---

## 🎯 MITRE ATT&CK

T1566.001 Phishing Attachment
Malicious email attachment used as initial infection vector

T1204.002 User Execution Malicious File
User would need to open attachment to trigger execution

T1059.001 Command and Scripting Interpreter PowerShell
Attachment executes PowerShell to retrieve payloads

T1105 Ingress Tool Transfer
Stage 2 payloads downloaded from external infrastructure

T1071.001 Application Layer Protocol Web Protocols
HTTP HTTPS communication to external sources

### 🔎 What
The alert SOC101 Phishing Mail Detected triggered after an email with subject Credit Card Statement was sent from david@cashbank.com to mark@letsdefend.io. The email contained a malicious attachment (hash 3cc33ce58536242bc9b2029cd9475a287351a379ccbd12da6b8b7bf2cc68be89) designed to execute a PowerShell script and download additional payloads.

### 🕐 When
Jan 02 2021 03:39 PM

### 📍 Where
Email sent from 104.140.188.46 to mark@letsdefend.io. Payloads hosted on GitHub URLs associated with PhoenixMiner.exe and bild.exe

### 💡 Why
The alert was triggered due to detection of a phishing email with a malicious attachment. Analysis confirms the attachment executes PowerShell to retrieve additional payloads. No network connections to the payload URLs were observed, indicating the attachment was not executed. The activity is classified as a true positive phishing attempt with no successful compromise