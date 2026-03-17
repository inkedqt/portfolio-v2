---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1218-011
  - mitre/T1566-002
  - mitre/T1105
  - mitre/T1071
  - emotet
date: 2026-03-17
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC125
title: Suspicious Rundll32 Activity
youtube: https://www.youtube.com/watch?v=-TtRQU3s5Vg
---
T1218.011 Signed Binary Proxy Execution Rundll32
T1566.002 Phishing Link
T1105 Ingress Tool Transfer
T1071 Application Layer Protocol

### 👤 Who
Malicious activity originated from host EmilyComp (IP address 172.16.17.49). The user appears to have interacted with a phishing email sent from admin@netflix-payments.com.

### 🔎 What
The alert SOC125 Suspicious Rundll32 Activity triggered after execution of the file KBDYAK.exe (hash a4513379dad5233afa402cc56a8b9222). Investigation shows the user clicked a phishing link http://bit.ly/3ecXem52 which redirected to a malicious payload download from http://ru-uid-507352920.pp.ru/KBDYAK.exe. The file is confirmed malicious and identified as an Emotet trojan. Following execution, the malware initiated outbound communication to multiple command and control URLs:
http://67.68.210.95/2SjAcA5VhhJiFjBQ/vvszin6AicmidnG5bg/DaDVVYvfEHlcIIcgcu/0U5UiIkaHankrHGa/FYSJmdQDj2ejni1UI/
http://162.241.242.173:8080/HQ9TemntfBzghL/3wz57awaSHlQrrnP/S78n2aUqY7U/
Both URLs are confirmed malicious and associated with Emotet infrastructure.

### 🕐 When
Feb 14 2021 12:13 PM

### 📍 Where
Source Hostname: EmilyComp
Source IP Address: 172.16.17.49
Malicious file: KBDYAK.exe
Download source: http://ru-uid-507352920.pp.ru/KBDYAK.exe
Command and control:
http://67.68.210.95/2SjAcA5VhhJiFjBQ/vvszin6AicmidnG5bg/DaDVVYvfEHlcIIcgcu/0U5UiIkaHankrHGa/FYSJmdQDj2ejni1UI/
http://162.241.242.173:8080/HQ9TemntfBzghL/3wz57awaSHlQrrnP/S78n2aUqY7U/

### 💡 Why
The alert was triggered due to suspicious rundll32 activity associated with execution of a malicious payload. Investigation confirmed the infection chain began with a phishing email, leading to download and execution of an Emotet trojan. The malware established communication with known malicious command and control infrastructure. The affected endpoint was isolated to contain the incident and prevent further spread or data exfiltration. The alert is classified as a true positive malware infection.