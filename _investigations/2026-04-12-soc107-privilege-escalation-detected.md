---
type: soc-case
platform: letsdefend
status: closed
severity: critical
tags:
  - phishing
  - privesc
  - mitre/T1068
  - mitre/T1204-002
  - mitre/T1566-001
date: 2026-04-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC107
title: Privilege Escalation Detected Event 19
youtube: https://www.youtube.com/watch?v=nshjmOzdxEs
---
## 🎯 MITRE ATT&CK
  
T1068 Exploitation for Privilege Escalation  
T1204.002 User Execution Malicious File    
T1566.001 Phishing Attachment  


### 👤 Who
User on host KatharinePRD (172.16.15.78)

### 🔎 What
The alert SOC107 Privilege Escalation Detected triggered after execution of a malicious file named creditcard on the endpoint. The file hash is confirmed malicious via VirusTotal and Hybrid Analysis, identifying it as a Linux privilege escalation tool. The process was observed running on the endpoint, indicating successful execution.

### 🕐 When
Sep 22 2020 03:40 PM

### 📍 Where
Host KatharinePRD (172.16.15.78). File delivered via email from david@cashback.com and executed locally on the system

### 💡 Why
The alert was triggered due to detection of privilege escalation activity. Investigation confirms the file is malicious and was executed on the endpoint, likely following delivery via phishing email. Although no outbound network connections were observed, the presence and execution of the privilege escalation tool indicates a successful compromise attempt. The host was contained to prevent further impact and escalation
