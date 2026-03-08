---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1059
  - mitre/T1105
  - mitre/T1071-001
  - cobaltstrike
date: 2026-03-08
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC139
title: Meterpreter or Empire Activity
youtube: https://www.youtube.com/watch?v=9xnJ_2gDDe8
---
T1059 Command and Scripting Interpreter
T1105 Ingress Tool Transfer
T1071.001 Web Protocols

### 👤 Who
Malicious activity originated from host Alex - HP (IP address 172.16.17.55). The endpoint executed a suspicious executable identified as cobaltstrike_shellcode.exe, which is associated with offensive security frameworks such as Meterpreter or Cobalt Strike.

### 🔎 What
The alert SOC139 Meterpreter or Empire Activity triggered after the file cobaltstrike_shellcode.exe (hash 24d99ba5654cdf31141c66fd9417b7e0) was detected executing on the endpoint. Detonation of the executable in a sandbox environment confirmed it attempts to establish command and control communication with external IP address 120.79.181.138. HTTP logs also confirmed outbound connections from the endpoint to this C2 infrastructure. VirusTotal intelligence indicates the destination IP is malicious and associated with attacker infrastructure.

### 🕐 When
Mar 15 2021 02:15 PM

### 📍 Where
Source Hostname Alex - HP
Source IP Address 172.16.17.55
Malicious file cobaltstrike_shellcode.exe executed on the endpoint and communicated with external command and control server 120.79.181.138.

### 💡 Why
The alert was triggered due to behavior consistent with Meterpreter or Cobalt Strike activity. Investigation confirmed the executable establishes outbound communication to a known malicious C2 server and EDR telemetry shows the malicious process running on the system. This indicates the endpoint was successfully compromised and attempting to establish attacker remote control. The affected machine was isolated to contain the incident and prevent further command and control communication or lateral movement within the network.
