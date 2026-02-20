---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1566-001
  - mitre/T1204-002
  - mitre/T1071-001
  - mitre/T1105
  - phishing
date: 2026-01-21
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC282
title: SOC282 - Phishing Alert - Deceptive Mail Detected
youtube: https://www.youtube.com/watch?v=t9YJ4-IAxdk
---

## 🎯 MITRE ATT&CK
T1566.001 Phishing Attachment  
T1204.002 Malicious File  
T1071.001 Application Layer Protocol  
T1105 Ingress Tool Transfer

### 👤 Who
A phishing email was delivered to a user whose endpoint felix with IP address 172.16.20.151 executed a malicious attachment. The malicious file was identified as Trojan AsyncRAT MSIL. The SHA256 hash of the file is cd903ad2211cf7d166646d75e57fb866000f4a3b870b5ec759929be2fd81d334.

### 🔎 What
SOC282 Phishing Alert Deceptive Mail Detected was triggered due to a suspicious email attachment. Static analysis in VirusTotal flagged the file as Trojan AsyncRAT MSIL. Dynamic analysis in ANY.RUN confirmed malicious behavior and identified command and control IP address 37.120.233.226. Log review showed outbound communication from endpoint felix to the C2 server. Process telemetry identified Coffee.exe with PID 6697 spawned by explorer.exe running on the host, consistent with AsyncRAT activity. The attachment was successfully executed indicating user interaction.

### 🕐 When
Event Time May 13 2024 09:22 AM  
Malicious process observed May 13 2024 13:00:38  
Alert Closed Jan 21 2026 09:47 AM

### 📍 Where
Endpoint felix  
IP Address 172.16.20.151  
Malicious Process Coffee.exe  
Parent Process C Windows Explorer EXE  
C2 IP Address 37.120.233.226  
Event ID 257  
Rule SOC282 Phishing Alert Deceptive Mail Detected

### 💡 Why
The phishing email contained a malicious attachment that was executed by the user, resulting in AsyncRAT infection. Confirmed C2 communication to 37.120.233.226 demonstrates active compromise. The endpoint was contained to prevent further malicious activity. Firewall blocking of the C2 IP and environment wide hunting for the file hash and related indicators is required. The alert was assessed as a True Positive