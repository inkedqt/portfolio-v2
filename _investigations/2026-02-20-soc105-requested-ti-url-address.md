---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1566-001
  - mitre/T1204-002
  - mitre/T1105
  - phishing
date: 2026-02-07
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC105
title: SOC105 - Requested T.I. URL address
youtube: https://www.youtube.com/watch?v=FjovKdW5zPQ
---
## 🎯 MITRE ATT&CK
T1566.001 Phishing Attachment  
T1204.002 Malicious File  
T1105 Ingress Tool Transfer

### 👤 Who
The activity was observed on endpoint X where a user accessed a malicious URL pssd-ltdgroup.com. The alert was triggered by SOC105 Requested T.I. URL address after the domain matched known Threat Intelligence data.

### 🔎 What
The endpoint made a request to the malicious domain [https://pssd-ltdgroup.com](https://pssd-ltdgroup.com) which is flagged in Threat Intelligence feeds. Investigation of the endpoint confirmed that a malicious Excel document was downloaded from the site and executed on the host. The file execution indicates user interaction with a phishing attachment leading to potential compromise.

### 🕐 When
Event Time Sep 20 2020 10:54 PM  
Alert Closed Feb 07 2026 11:30 AM

### 📍 Where
Endpoint X  
Malicious URL [https://pssd-ltdgroup.com](https://pssd-ltdgroup.com)  
Alert Rule SOC105 Requested T.I. URL address  
Event ID 16

### 💡 Why
The user accessed a known malicious URL that is present in Threat Intelligence databases. The downloaded Excel document executed on the endpoint, indicating successful delivery and execution of a malicious payload. This confirms a True Positive and containment was required to prevent further compromise or lateral movement.
