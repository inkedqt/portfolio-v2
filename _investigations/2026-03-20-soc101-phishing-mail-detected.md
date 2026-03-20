---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1566-002
  - mitre/T1204
  - phishing
date: 2026-03-20
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC101
title: Phishing Mail Detected
youtube: https://www.youtube.com/watch?v=xQyj9NqCf-o
---

T1566.002 Phishing Link
T1204 User Execution

### 👤 Who
A phishing email was sent from external address lethuyan852@gmail.com to internal user mark@letsdefend.io via SMTP server 146.56.195.192.

### 🔎 What
The alert SOC101 Phishing Mail Detected triggered due to a suspicious email with subject "Its a Must have for your Phone". Analysis of the embedded URL using VirusTotal and Joe Sandbox confirmed the link is malicious. Logs indicate the user accessed the URL from the endpoint, confirming user interaction with the phishing content and potential compromise risk.

### 🕐 When
Apr 04 2021 11:00 PM

### 📍 Where
Source Address: lethuyan852@gmail.com
Destination Address: mark@letsdefend.io
SMTP Server: 146.56.195.192
Affected Endpoint: User system associated with mark@letsdefend.io

### 💡 Why
The alert was triggered due to detection of a phishing email containing a malicious URL. Threat intelligence confirmed the URL is associated with malicious activity, and endpoint logs show the user accessed the link, increasing the risk of compromise. The activity is classified as a true positive phishing incident and the affected endpoint should be contained and further investigated for potential malware execution or credential theft.