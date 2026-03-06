---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1059-003
  - mitre/T1059-006
  - revshell
date: 2026-03-06
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC131
title: Reverse TCP Backdoor Detected
youtube: https://www.youtube.com/watch?v=GiClVeUY7Qc
---
**T1059.003** Windows Command Shell 
**T1059.006** Python

### 👤 Who
Suspicious activity originated from host MikeComputer (IP address 172.16.17.14). The activity involved execution of a batch file named msi.bat which attempted to launch a Python-based reverse connection to an external IP address.

### 🔎 What
The alert SOC131 Reverse TCP Backdoor Detected triggered after the file msi.bat (hash 3dc649bc1be6f4881d386e679b7b60c8) was detected on the endpoint. Analysis of the batch file showed that it attempted to execute a Python script designed to establish a reverse TCP connection to the external IP address 81.68.99.93, which is indicative of backdoor behavior commonly used to provide remote attacker access. Endpoint protection logs indicate the file was automatically cleaned before execution could complete.

### 🕐 When
Mar 01 2021 03:15 PM

### 📍 Where
Source Hostname MikeComputer  
Source IP Address 172.16.17.14  
Malicious file msi.bat detected on the endpoint attempting to communicate with external IP 81.68.99.93.

### 💡 Why
The alert was generated due to detection of a batch file attempting to launch a reverse TCP backdoor using Python. Investigation showed no successful outbound connection to the external IP address in network logs, and the endpoint security control reported the file as cleaned. No evidence of the Python script running was found on the endpoint. This indicates the security control successfully removed the malicious file before the reverse connection could be established, preventing attacker access. The alert is considered contained but the system should continue to be monitored for any additional malicious artifacts or follow-up activity.