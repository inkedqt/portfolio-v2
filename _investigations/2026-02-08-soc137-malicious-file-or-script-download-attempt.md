---
title: "Malicious File or Script Download Attempt"
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1059
  - malware
  - mitre/T1204-002
date: 2026-02-08
outcome: true-positive
alert_id: SOC137
youtube: https://www.youtube.com/watch?v=fQUIvukK9qU
---
## 🧾 Alert Summary
SOC137 - Malicious File or Script Download Attempt
## 🧩 MITRE ATT&CK
- **T1204.002** – Malicious File
- **T1059** – Command and Scripting Interpreter (PowerShell)
## 🔍 Investigation
- Endpoint attempted to access **`INVOICE PACKAGE LINK TO DOWNLOAD.docm`** from internal IP **172.16.17.37**
    
- SIEM alert confirmed the download attempt was **blocked**
    
- File hash checked on **VirusTotal** and confirmed **malicious**
    
- Endpoint review showed:
    
- **No active signs of compromise on March 14**
        
- **Historical IOC detected on March 7**, including obfuscated PowerShell execution via `wmic process call create`
        
- Command observed included execution policy bypass, hidden window, and non-interactive PowerShell execution
-
- IOCs:
- **MD5:** `f2d0c66b801244c059f636d08a474079`
    
- **Filename:** `INVOICE PACKAGE LINK TO DOWNLOAD.docm`

## 🧠 Analysis
The alert corresponds to a confirmed malicious document delivery attempt. While the initial download was blocked, historical telemetry indicates prior suspicious PowerShell activity consistent with malware execution techniques. The lack of current malicious activity suggests either partial remediation or inactive persistence.
## 🛑 Response
- Endpoint identified as **previously compromised**
    
- Security agent not reporting since **March 7**
    
- Escalation recommended for endpoint re-enrollment or isolation review
## ✅ Outcome
**True Positive**