---
title: "Ransomware Detected"
type: soc-case
platform: letsdefend
status: closed
severity: critical
tags:
  - ransomware
  - mitre/T1486
  - mitre/T1490
  - mitre/T1021-002
date: 2026-02-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC145
---


MITRE ATTACK
T1486 – Data Encrypted for Impact  
T1490 – Inhibit System Recovery  
T1021.002 – Remote Services: SMB/Windows Admin Shares

INVESTIGATION

WHO:  
Infection observed on internal host MarkPRD (172.16.17.88). Malware identified as ab.exe (ransomware). No confirmed external C2 traffic observed in available logs.

WHAT:  
Ransomware execution detected. Malicious file ab.exe downloaded and executed on host. Malware behavior confirmed via VirusTotal and ANY.RUN detonation analysis.

WHEN:  
May 23, 2021 at 07:32 PM.

WHERE:  
Host MarkPRD (172.16.17.88) within internal network environment.

WHY:  
Malware executed with intent to encrypt files and disrupt system recovery. Detonation analysis shows execution of wbadmin.exe to delete system backups and attempted lateral movement via SMB shares.

HOW:  
Malicious executable ab.exe was downloaded and allowed on endpoint. File executed and spawned wbadmin.exe to delete backups. Behavior consistent with ransomware attempting impact and lateral propagation.

IMPACT:  
Confirmed ransomware execution. Backup deletion attempt observed. High risk of file encryption and lateral spread.

ACTION TAKEN:  
Host contained immediately.  
Incident escalated to L2/L3 for full ransomware response procedure.  
Recommended actions:

- Full forensic investigation
    
- Password resets for affected user
    
- Network-wide SMB review
    
- Backup integrity validation
    
- Enterprise-wide IOC sweep
    

OUTCOME:  
True Positive – Confirmed ransomware infection requiring urgent escalation.

