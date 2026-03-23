---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1565-001
  - mitre/T1546-008
  - mitre/T1036
  - dnshijack
date: 2026-03-23
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC116
title: DNS Hijacking Detected
youtube: https://www.youtube.com/watch?v=GZ68RZ-BWZ0
---
T1565.001 Data Manipulation Stored Data
T1568 Dynamic Resolution
T1036 Masquerading

### 👤 Who
Malicious activity was detected on host WilsonPRD (IP address 172.16.17.34). The activity involved execution of a Python script named update.py on the endpoint.

### 🔎 What
The alert SOC116 DNS Hijacking Detected triggered after the script update.py (hash 307b47d1217f267a47cee8dd86c2f191) modified the system hosts file to redirect traffic for github.com to a malicious IP address 49.233.160.217. This effectively hijacks DNS resolution locally, allowing the attacker to intercept or manipulate traffic intended for GitHub. Endpoint analysis confirmed the script was actively running and performing the modification.

### 🕐 When
Feb 06 2021 12:42 PM

### 📍 Where
Source Hostname: WilsonPRD
Source IP Address: 172.16.17.34
Affected resource: hosts file on endpoint
Redirected domain: github.com
Malicious IP: 49.233.160.217

### 💡 Why
The alert was triggered due to unauthorized modification of DNS resolution via the hosts file, a known technique used for DNS hijacking and traffic redirection. Investigation confirmed that HTTP requests intended for github.com were redirected to the malicious IP address, indicating successful exploitation. The activity is classified as a true positive malware incident. The affected endpoint was isolated to prevent further traffic interception or credential compromise.
