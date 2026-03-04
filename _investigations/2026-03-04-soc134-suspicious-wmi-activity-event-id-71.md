---
type: soc-case
platform: letsdefend
status: closed
severity: critical
tags:
  - mitre/T1047
  - mitre/T1021-002
  - mitre/T1059
  - mitre/T1041
  - WMI
date: 2026-03-04
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC134_id71
title: Suspicious WMI Activity event 71
youtube: https://www.youtube.com/watch?v=J8puwgZFgHM
---

T1047 Windows Management Instrumentation  
T1021.002 Remote Services SMB Windows Admin Shares  
T1059 Command and Scripting Interpreter  
T1041 Exfiltration Over C2 Channel

### 👤 Who
Suspicious activity originated from host Desktop-Anderson (IP 172.16.17.54). The activity appears to involve unauthorized use of administrative credentials associated with the Anderson and Administrator accounts.

### 🔎 What
The alert SOC134 Suspicious WMI Activity triggered due to execution of a batch file exec.bat containing the command python wmiexec.py LetsDefend/Administrator@127.0.0.1%. The tool wmiexec.py is part of the Impacket framework and is commonly used by attackers to execute remote commands via Windows Management Instrumentation. Network proxy logs show outbound communication from 172.16.17.54 to external IP 161.35.41.241 on port 4444, which is commonly used for reverse shells or data exfiltration. Encoded network traffic captured in logs was decoded using CyberChef and revealed system reconnaissance output including hostname DESKTOP-ANDERSON and enumeration of local user accounts. The decoded data also exposed plaintext credentials Anderson:ander12son! and Administrator:mys3r3tP@ss!, indicating credential harvesting and potential lateral movement activity.

### 🕐 When
Mar 07 2021 04:50 PM

### 📍 Where
Source Hostname Desktop-Anderson  
Source IP Address 172.16.17.54  
File exec.bat with hash 50459310eded4c520ab5c9e3626a9300 executed on the host. Network traffic observed communicating with malicious external IP 161.35.41.241 over port 4444. The endpoint is also running VMware which may indicate the activity originated from a virtual machine, explaining the absence of suspicious processes on the primary host system.

### 💡 Why
The alert was triggered due to suspicious WMI execution behavior consistent with remote command execution using Impacket. Investigation confirmed the batch file executes wmiexec.py, a known offensive tool used for remote administration and lateral movement. Network logs confirm communication with a malicious external IP and base64 encoded traffic containing system reconnaissance and credential information. The presence of VMware suggests the malicious activity may have been conducted from a virtual machine running on the host, which could explain the lack of visible malicious processes on the main operating system. The activity indicates attempted credential harvesting and potential command and control communication.