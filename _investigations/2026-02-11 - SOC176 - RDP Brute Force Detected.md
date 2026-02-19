---
title: "RDP Brute Force Detected"
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1110
  - mitre/T1078
  - bruteforce
date: 2026-02-08
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC176
---
## 🧾 Alert Summary

##  MITRE ATT&CK
- **T1110** – Brute Force
    
- **T1078** – Valid Accounts
## Investigation (5W Format)

**WHO:**  
External attacker from IP **218.92.0.56** targeting host **Matthew (172.16.17.148)**.
IP also has a malicious reputation on virustotal - https://www.virustotal.com/gui/ip-address/218.92.0.56/detection

**WHAT:**  
RDP brute-force attack observed. Multiple failed login attempts (EventID 4625) against different accounts followed by a successful login (EventID 4624, Logon Type 10 – RemoteInteractive).

**WHEN:**  
Mar 07, 2024 at ~11:44 AM.

**WHERE:**  
Windows host _Matthew_ (172.16.17.148) over RDP (TCP 3389).

**WHY:**  
Attacker attempted credential guessing via RDP and successfully authenticated to account **Matthew**, indicating potential account compromise.

**HOW:**  
Automated brute-force attempts from a single external IP. After repeated login failures, valid credentials were used resulting in successful remote interactive logon.



Successful external RDP authentication strongly indicates compromised credentials and potential host compromise.


## ACTION TAKEN

- Escalated as confirmed compromise.
    
- Recommended immediate containment:
    
- Disable or reset compromised account (Matthew)
        
- Isolate host from network
        
- Review additional logons and lateral movement activity
        
- Block source IP at firewall
        
- Investigate for persistence mechanisms