---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1218-005
  - mitre/T1105
  - mitre/T1071-001
  - mitre/T1027
  - mitre/T1046
  - LOLBin
date: 2026-03-30
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC115
title: Wscript.exe Usage as Dropper
youtube: https://www.youtube.com/watch?v=-Hb5Nyo6zbU
---

### 🔎 What
The alert SOC115 Wscript.exe Usage as Dropper triggered after execution of injector.vbs via wscript.exe on host DanielPRD. Wscript.exe is a known LOLBIN commonly abused to execute malicious scripts. Network logs show outbound connections to 105.103.253.204 on non-standard port 2017 and additional communication with 209.216.230.240, which is flagged as malicious. This indicates the script likely acted as a dropper establishing external communication.

### 🕐 When
Jan 31 2021 06:14 PM

### 📍 Where
Host DanielPRD (172.16.17.33) executed injector.vbs via wscript.exe. Outbound connections observed to 105.103.253.204:2017 and 209.216.230.240.

### 💡 Why
The alert was triggered due to suspicious use of wscript.exe, a commonly abused Windows binary for executing malicious scripts. Endpoint and network evidence confirm execution of a potentially malicious VBS dropper and communication with known malicious infrastructure. Initial infection vector is unknown due to lack of email or additional logs. The host was contained and escalated for further investigation.

## 🎯 MITRE ATT&CK

T1218.005 – Signed Binary Proxy Execution: Mshta/Wscript
Use of wscript.exe as a LOLBIN to execute malicious VBS script.

T1105 – Ingress Tool Transfer
Dropper behavior likely used to retrieve or stage additional payloads.

T1071.001 – Application Layer Protocol: Web Protocols
Outbound communication to external IPs over non-standard port.

T1027 – Obfuscated Files or Information
Likely obfuscation within VBS script (common in dropper behavior, inferred).

T1046 – Network Service Discovery (optional/low confidence)
Suspicious outbound connections may indicate scanning or staging behavior (not fully confirmed).