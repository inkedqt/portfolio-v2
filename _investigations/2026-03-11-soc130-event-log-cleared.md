---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1070
date: 2026-03-11
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC130
title: Event Log Cleared
youtube: https://www.youtube.com/watch?v=KoEhkdWi8og
---

T1070 Indicator Removal on Host

### 👤 Who
Activity was observed on host Exchange Server (IP address 172.16.20.3). The event involved execution of the legitimate Windows process powershell.exe.

### 🔎 What
The alert SOC130 Event Log Cleared triggered when a PowerShell process (hash 7353f60b1739074eb17c5f4dddefe239) was detected on the Exchange Server. The hash corresponds to a legitimate Microsoft PowerShell binary. Investigation did not reveal any associated commands commonly used to clear Windows event logs such as wevtutil.exe or Clear-EventLog. No suspicious scripts or additional malicious processes were observed running on the endpoint.

### 🕐 When
Feb 21 2021 07:23 PM

### 📍 Where
Source Hostname Exchange Server  
Source IP Address 172.16.20.3  
Process powershell.exe executed on the endpoint.

### 💡 Why
The alert was triggered due to a detection rule related to potential event log clearing activity. However, analysis of process activity on the endpoint did not reveal any commands or utilities that would indicate Windows event logs were cleared. The PowerShell binary detected is a legitimate system component and no malicious activity or suspicious behavior was observed on the host. Based on the available evidence, this alert is assessed as a false positive.