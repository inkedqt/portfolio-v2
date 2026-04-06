---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1204-001
  - mitre/T1105
  - mitre/T1071-001
date: 2026-04-06
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC121
title: Proxy - Malicious Executable File Detected event 79
youtube: https://www.youtube.com/watch?v=ZK5e98UmIHM
---
## 🎯 MITRE ATT&CK

T1204.001 User Execution Malicious Link
User likely clicked a malicious link initiating the download

T1105 Ingress Tool Transfer
Attempted download of malicious executable

T1071.001 Application Layer Protocol Web Protocols
HTTP communication to external malicious domain

### 👤 Who
User Susie on host SusieHost (172.16.17.5)

### 🔎 What
The alert SOC121 Proxy Malicious Executable File Detected triggered after an attempt to download pianificazione.exe from gavrilobtcapikey2884238984928.netsons.org. The request originated from chrome.exe launched by explorer.exe, indicating user interaction. The file is identified as a malicious executable.

### 🕐 When
Feb 07 2021 12:19 PM

### 📍 Where
Host SusieHost (172.16.17.5) attempted connection to gavrilobtcapikey2884238984928.netsons.org (89.40.172.121)

### 💡 Why
The alert was triggered due to a request for a known malicious executable file. The download attempt was blocked by security controls and no further connections or execution activity were observed. This indicates the threat was prevented before compromise. The activity is classified as a true positive with no further action required

