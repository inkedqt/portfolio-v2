---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1547
  - mitre/T1105
date: 2026-03-15
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC126
title: Suspicious New Autorun Value Detected
youtube: https://www.youtube.com/watch?v=GGnWsMwyLwQ
---
T1547 Boot or Logon Autostart Execution  
T1105 Ingress Tool Transfer

### 👤 Who
Malicious activity was detected on host KatharinePRD (IP address 172.16.15.78). The event involved a suspicious executable named OliwciaPrivInstaller.exe detected on the endpoint.

### 🔎 What
The alert SOC126 Suspicious New Autorun Value Detected triggered after the file OliwciaPrivInstaller.exe (hash 436fa243bbfed63a99b8e9f866cd80e5) was identified attempting to establish persistence through an autorun mechanism. The file is confirmed malicious based on threat intelligence and malware analysis. Endpoint protection detected the file and automatically removed it before further activity could occur.

### 🕐 When
Feb 14 2021 06:40 PM

### 📍 Where
Source Hostname KatharinePRD  
Source IP Address 172.16.15.78  
Malicious file OliwciaPrivInstaller.exe detected on the endpoint. Network logs show one outbound connection to IP address 23.227.38.71.

### 💡 Why
The alert was triggered due to the creation of a suspicious autorun persistence entry associated with a malicious executable. Although the endpoint is running Linux and the file is a Windows executable, the file itself is confirmed malicious and therefore the alert represents a true positive detection. Endpoint security successfully cleaned the file before it could execute or establish persistence, and no additional signs of compromise were observed on the system.
