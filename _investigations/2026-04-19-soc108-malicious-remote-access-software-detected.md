---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
date: 2026-04-19
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC108
title: Malicious Remote Access Software Detected
youtube: https://www.youtube.com/watch?v=NTq1Kuczq3M
---
### 🔎 What
The alert SOC108 Malicious Remote Access Software Detected triggered after AnyDesk.exe was downloaded on host DanielPRD. Log analysis confirms the file was sourced from the official anydesk.com website. VirusTotal shows no malicious detections for the file hash.

### 🕐 When
Jan 01 2021 05:36 PM

### 📍 Where
Host DanielPRD (172.16.17.33) downloaded AnyDesk.exe from anydesk.com

### 💡 Why
The alert was triggered due to detection of remote access software, which can be abused by attackers. However, investigation confirms the file was downloaded from a legitimate source and is not flagged as malicious. No suspicious behavior or unauthorized usage was observed. The activity is classified as a false positive

sources
https://app.any.run/browses/3a5a3bdd-783f-488a-93c3-132e64b31613
https://www.filescan.io/reports/6f4a78da5c19afba57637bd344213d5ff55fb69dc343d6a6c79b0696ce53eaa0/ff07e27b-74e0-4aa0-8b25-f828c413283f/details
https://www.virustotal.com/gui/domain/anydesk.com