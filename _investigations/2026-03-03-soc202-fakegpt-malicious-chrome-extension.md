---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1071-001
  - mitre/T1557
  - mitre/T1539
  - mitre/T1041
date: 2026-03-03
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC202
title: FakeGPT Malicious Chrome Extension
youtube: https://www.youtube.com/watch?v=j97apnHGKmU
---
T1071.001 Application Layer Protocol Web Protocols  
T1557 Adversary in the Middle  
T1539 Steal Web Session Cookie  
T1041 Exfiltration Over C2 Channel

### 👤 Who
A malicious Chrome extension named ChatGPT for Google was installed and executed on host Samuel by user LetsDefend. The extension is confirmed malicious via VirusTotal analysis and internal investigation.

### 🔎 What
The extension hacfaophiklaeolhnmckojjjjbnappen.crx was executed via chrome.exe. It uses chrome.cookies.getAll API to collect browser cookies, filters Facebook-related cookies, encrypts them using AES with key chatgpt4google, and exfiltrates them to version.chatgpt4google.workers.dev via HTTP header X-Cached-Key. This activity constitutes credential theft and data leakage.

### 🕐 When
May 29 2023 01:01 PM

### 📍 Where
Hostname Samuel  
IP Address 172.16.17.173  
File Path C:\Users\LetsDefend\Download\hacfaophiklaeolhnmckojjjjbnappen.crx  
Outbound connection to version.chatgpt4google.workers.dev known C2 infrastructure

### 💡 Why
The alert SOC202 FakeGPT Malicious Chrome Extension triggered due to suspicious browser extension installation. Log analysis confirmed execution via chrome.exe with extension parameter. Network logs confirmed connection to known C2 domain. VirusTotal analysis verified the extension performs Facebook cookie harvesting and exfiltration. The activity is classified as Data Leakage. The endpoint was isolated to prevent further credential theft and lateral movement.
