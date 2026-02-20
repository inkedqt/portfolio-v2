---
title: "APT35 HyperScrape Data Exfiltration Tool Detected"
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1567
  - mitre/T1041
  - mitre/T1059
  - mitre/T1078
date: 2026-02-08
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC250
youtube: https://www.youtube.com/watch?v=SNroeSufrG0
---
## 🎯 MITRE ATT&CK
T1567 Exfiltration Over Web Service  
T1041 Exfiltration Over C2 Channel  
T1059 Command and Scripting Interpreter  
T1078 Valid Accounts
### 🔎 What
SOC250 alert triggered for detection of APT35 HyperScrape data exfiltration tool. The process EmailDownloader.exe was executed on host Arthur from the Downloads directory. The file hash cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa is associated with Hyperscrape, a known APT35 tool used to extract victim mailboxes. Exchange logs confirm successful mailbox download activity.
### 🕐 When
27 Dec 2023 11:22 AM
### 📍 Where
Hostname Arthur  
Internal IP 172.16.17.72  
Remote login IP 173.209.51.54 confirmed malicious via VirusTotal  
File download source 136.243.108.14 confirmed malicious  
Mailbox arthur@letsdefend.io
### 👤 Who
User Arthur  
Host Arthur 172.16.17.72  
Threat Actor APT35 also known as Charming Kitten
### 💡 Why
The malicious executable EmailDownloader.exe was downloaded and executed from the user Downloads folder. The file hash matches a known HyperScrape data theft tool used by APT35 to extract entire mailboxes. Exchange logs confirm successful mailbox download operation. The alert was allowed by the device, meaning the malicious activity was not blocked at execution time.
How  
Attacker performed remote login from malicious IP 173.209.51.54. The tool was downloaded from 136.243.108.14 and executed locally. The HyperScrape tool extracted mailbox data as confirmed by Exchange logs showing Download operation succeeded for mailbox arthur@letsdefend.io.
Evidence  
Process EmailDownloader.exe PID 6315  
File path C:\Users\LetsDefend\Downloads\EmailDownloader.exe  
File hash cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa  
Exchange log Operation Download succeeded  
MailboxGuid 6d4fbdae-e3ae-4530-8d0b-f62a14687939
Action Taken  
Escalated incident  
Isolated affected host  
Blocked malicious IP addresses  
Credential reset required for affected account  
Further investigation initiated
Conclusion  
This is a confirmed data exfiltration incident involving APT35 HyperScrape tool. Malicious remote access and mailbox extraction were successful. Immediate containment and escalation were appropriate to prevent further compromise.


