---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1105
date: 2026-03-25
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC119
title: Proxy - Malicious Executable File Detected event 79
youtube: https://www.youtube.com/watch?v=gk9CzLM3NEs
---
T1105 Ingress Tool Transfer

### 👤 Who
The activity originated from host PentestMachine (IP address 172.16.20.5) by user kali as part of an internal penetration test.

### 🔎 What
The alert SOC119 Proxy Malicious Executable File Detected triggered due to access to a GitHub repository hosting BloodHoundAD releases:
https://github.com/BloodHoundAD/BloodHound/releases
BloodHound is a legitimate tool commonly used for Active Directory analysis during security assessments. The user agent explicitly states "Penetration Test - Do not Contain", confirming the activity is part of an authorized penetration test.

### 🕐 When
Mar 15 2021 09:30 PM

### 📍 Where
Source Hostname: PentestMachine
Source IP Address: 172.16.20.5
Destination Hostname: github.com
Destination IP Address: 140.82.121.4
Request URL: https://github.com/BloodHoundAD/BloodHound/releases

### 💡 Why
The alert was triggered because the detection rule flagged the download or access of a tool that can be used maliciously. However, investigation confirms the activity originated from an authorized penetration testing system and is expected behavior. The user agent and context clearly indicate this is part of a controlled security test. The alert is classified as a false positive.
