---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1059-003
  - mitre/T1105
  - mitre/T1071-001
date: 2026-04-05
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC132
title: Same Malicious File Found on Multiple Sources
youtube: https://www.youtube.com/watch?v=kjvK2DsdzZU
---
## 🎯 MITRE ATT&CK

T1059.003 Command and Scripting Interpreter Windows Command Shell
Batch script execution used for malicious activity

T1105 Ingress Tool Transfer
Malicious file delivered to multiple endpoints

T1071.001 Application Layer Protocol Web Protocols
Intended communication with external C2 infrastructure

### 🔎 What
The alert SOC132 Same Malicious File Found on Multiple Sources triggered after the file msi.bat was identified on multiple hosts including MikeComputer, JohnComputer, and Sofia. Analysis of the batch file reveals a hardcoded IP address 81.68.99.93, consistent with reverse shell behavior.

### 🕐 When
Mar 01 2021 03:16 PM

### 📍 Where
Hosts MikeComputer, JohnComputer, and Sofia (172.16.17.14) were found to contain the file msi.bat associated with external IP 81.68.99.93

### 💡 Why
The alert was triggered due to the same malicious file being detected across multiple systems. The batch file contains indicators of reverse shell functionality pointing to a known external IP. Although no successful network connections to the C2 address were observed and the file was cleaned by security controls, the presence of the file across multiple hosts confirms a true positive malware event. The activity indicates attempted compromise but no confirmed execution or communication
