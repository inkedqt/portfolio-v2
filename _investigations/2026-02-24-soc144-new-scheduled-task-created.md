---
type: soc-case
platform: letsdefend
status: closed
severity: critical
tags:
  - mitre/T1053-005
  - mitre/T1105
  - mitre/T1071-001
  - persistance
date: 2026-02-24
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC144
title: SOC144 - New scheduled task created
youtube: https://www.youtube.com/watch?v=O_5Z0bZbGHc
---

## 🎯 MITRE ATT&CK
T1053.005 Scheduled Task  
T1105 Ingress Tool Transfer  
T1071.001 Web Protocols

### 👤 Who
Source host Helena with IP address 172.16.17.36 created a new scheduled task. The activity involved execution of Sorted-Algorithm.py. The script initiated outbound communication to external IP 92.27.116.104.

### 🔎 What
SOC144 alert triggered for creation of a new scheduled task. Investigation revealed the Python script Sorted-Algorithm.py with hash 65d880c7f474720dafb84c1e93c51e11 was configured to create a daily scheduled task that executes a setup file retrieved from malicious IP 92.27.116.104. HTTP logs confirmed outbound connections to the external IP. Process logs confirmed execution of the Python script on the endpoint. This indicates malware persistence via scheduled task and remote payload retrieval.

### 🕐 When
Event Time May 14, 2021 03:22 PM

### 📍 Where
Affected Host Helena  
Source IP 172.16.17.36  
External IP 92.27.116.104  
Event ID 91  
Rule SOC144 New scheduled task created

### 💡 Why
The scheduled task was created to establish persistence and execute a secondary payload downloaded from a malicious external server. Outbound HTTP traffic and endpoint process logs confirm malicious activity. The machine was contained to prevent further compromise and the incident escalated for deeper forensic analysis. The alert is assessed as a True Positive.