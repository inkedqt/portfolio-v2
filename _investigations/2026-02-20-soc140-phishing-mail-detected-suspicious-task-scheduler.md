---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1566-001
  - mitre/T1204-002
  - mitre/T1053
date: 2026-01-21
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC140
title: SOC140 - Phishing Mail Detected - Suspicious Task Scheduler
youtube: https://www.youtube.com/watch?v=1lWhnfYLDDw
---

## 🎯 MITRE ATT&CK
T1566.001 Phishing Attachment  
T1204.002 Malicious File  
T1053 Scheduled Task

### 👤 Who
An email from aaronluo at cmail carleton ca was sent to mark at letsdefend io and triggered the SOC140 Phishing Mail Detected Suspicious Task Scheduler alert.

### 🔎 What
The email contained a PDF attachment that was flagged as malicious. The file hash 39fb927c32221134a423760c5d1f58bca4cbbcc87c891c79e390a22b63608eb4 was analyzed in VirusTotal and classified as Trojan PDF Fraud AD. Dynamic analysis in ANY.RUN revealed the PDF attempts to communicate with command and control infrastructure at IP address 69.39.225.3 associated with domain a pomf cat. Email security controls blocked the message before delivery. Log review confirmed no outbound network communication to the identified C2 server.

### 🕐 When
Event Time Mar 21 2021 12:26 PM  
Alert Closed Jan 21 2026 03:23 PM

### 📍 Where
Recipient mark at letsdefend io  
Malicious Attachment PDF file  
C2 IP 69.39.225.3  
Event ID 82  
Rule SOC140 Phishing Mail Detected Suspicious Task Scheduler

### 💡 Why
The phishing email contained a malicious PDF attachment designed to establish command and control communication. Email security controls successfully blocked delivery and no endpoint communication to malicious infrastructure was observed. The threat was contained before execution. The alert was assessed as a True Positive.