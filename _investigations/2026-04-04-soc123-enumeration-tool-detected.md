---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1082
  - mitre/T1069
  - mitre/T1083
  - mitre/T1105
  - mitre/T1071-001
date: 2026-04-04
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC123
title: Enumeration Tool Detected
youtube: https://www.youtube.com/watch?v=FdbET7tWpgk
---
## 🎯 MITRE ATT&CK

T1082 System Information Discovery
LinEnum gathers detailed system and environment information

T1069 Permission Groups Discovery
Enumeration of user groups and privileges

T1083 File and Directory Discovery
Script enumerates file system contents and permissions

T1105 Ingress Tool Transfer
Tool downloaded from external source

T1071.001 Application Layer Protocol Web Protocols
Download performed over HTTP/HTTPS

### 🔎 What
The alert SOC123 Enumeration Tool Detected triggered after host gitServer downloaded and executed LinEnum.sh from GitHub. Terminal history confirms the script was downloaded, renamed to /tmp/ah22idah.sh, made executable, and run. LinEnum is a known enumeration tool commonly used for privilege escalation and post-compromise reconnaissance.

### 🕐 When
Feb 13 2021 04:47 PM

### 📍 Where
Host gitServer (172.16.20.4), user Jack, downloaded the script from githubusercontent.com (185.199.109.133) and executed it locally from /tmp

### 💡 Why
The alert was triggered due to detection of an enumeration tool download. Execution of LinEnum and renaming to a temporary file suggests potential attacker activity performing system reconnaissance after initial access. Although the source is a legitimate GitHub repository, the behavior is suspicious and consistent with post-exploitation activity. The host was contained and escalated for further investigation

