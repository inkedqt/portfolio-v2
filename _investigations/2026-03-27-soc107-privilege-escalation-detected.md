---
type: soc-case
platform: letsdefend
status: closed
severity: critical
tags:
  - mitre/T1068
  - mitre/T1204
  - mitre/T1105
date: 2026-03-27
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC107
title: Privilege Escalation Detected
youtube: https://www.youtube.com/watch?v=NOqKpjDGsjc
---
T1068 Exploitation for Privilege Escalation
T1204 User Execution
T1105 Ingress Tool Transfer

### 👤 Who
Malicious activity was detected on host RichardPRD (IP address 172.16.17.45). The initial access likely involved a user interacting with a malicious Excel document.

### 🔎 What
The alert SOC107 Privilege Escalation Detected triggered after execution of JuicyPotato.exe (hash 808502752ca0492aca995e9b620d507b), a known privilege escalation tool used to abuse token impersonation vulnerabilities on Windows systems. Investigation shows the infection chain began when excel.exe spawned EQNEDT32.EXE, which then downloaded a malicious payload from http://andaluciabeach.net/image/network.exe. This indicates exploitation of a malicious Office document leading to execution of attacker-controlled code. The attacker then used JuicyPotato to escalate privileges on the system.

### 🕐 When
Jan 31 2021 04:20 PM

### 📍 Where
Source Hostname: RichardPRD
Source IP Address: 172.16.17.45
Initial payload source: http://andaluciabeach.net/image/network.exe
Processes involved: excel.exe → EQNEDT32.EXE → JuicyPotato.exe

### 💡 Why
The alert was triggered due to detection of a known privilege escalation tool on the endpoint. Analysis confirms a malicious document-based infection chain leading to execution of a payload and subsequent use of JuicyPotato for privilege escalation. The external URL is confirmed malicious, and the process chain is consistent with exploitation of Office vulnerabilities. The affected endpoint was isolated to contain the incident and prevent further attacker activity.
