---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1204
  - mitre/T1059-003
  - mitre/T1203
  - mitre/T1105
  - mitre/T1218
date: 2026-02-22
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC173
title: Follina 0-Day Detected
youtube: https://www.youtube.com/watch?v=
---
## 🎯 MITRE ATT&CK
T1204 User Execution  
T1059.003 Windows Command Shell  
T1203 Exploitation for Client Execution  
T1105 Ingress Tool Transfer
T1218 System Binary Proxy Execution

### 👤 Who
A malicious email was received by user jonas@letsdefend.io from radiosputnik@ria.ru containing a password protected ZIP attachment. The file 05-2022-0438.doc was opened on host JonasPRD 172.16.17.39 which triggered execution of msdt.exe.

### 🔎 What
The Office document 05-2022-0438.doc exploited the Follina vulnerability CVE-2022-30190 which abuses the Microsoft Windows Support Diagnostic Tool MSDT to achieve remote code execution. Following document execution msdt.exe was spawned. Further investigation confirmed outbound communication to 141.105.65.149 which is associated with malicious activity. HTTP logs validated the C2 connection and sandbox analysis in any.run confirmed exploitation behavior.

### 🕐 When
Jun 02 2022 03:22 PM

### 📍 Where
Hostname JonasPRD  
Source IP 172.16.17.39  
File Name 05-2022-0438.doc  
File Hash 52945af1def85b171870b31fa4782e52  
C2 IP 141.105.65.149

### 💡 Why
CVE-2022-30190 known as Follina allows remote code execution via MSDT when a specially crafted Office document is opened. The attachment was delivered via phishing email and required user interaction to open the password protected archive and document. Execution of msdt.exe after Office activity combined with confirmed C2 communication indicates successful exploitation and payload staging.

Evidence  
Phishing email with password protected ZIP attachment  
Execution of msdt.exe following document open  
File hash flagged malicious  
HTTP logs show connection to 141.105.65.149  
Sandbox analysis confirms exploit behavior  
AV Action Allowed

## 📋 Response
The alert was confirmed as a True Positive. The affected host JonasPRD was isolated for containment. Malicious file artifacts were removed and indicators of compromise including 141.105.65.149 were blocked.
