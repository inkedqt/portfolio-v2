---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1190
  - mitre/T1505-003
  - mitre/T1059
  - mitre/T1071-001
  - revshell
  - sqli
date: 2026-03-02
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC142
title: Multiple HTTP 500 Response
youtube: https://www.youtube.com/watch?v=Yn7bDAFPtEY
---
# MITRE ATT&CK

T1190 Exploit Public-Facing Application  
T1505.003 Web Shell  
T1059 Command and Scripting Interpreter  
T1105 Ingress Tool Transfer  
T1071.001 Application Layer Protocol

---

### 👤 Who
External IP 101.32.223.119 targeted internal web server 172.16.20.6 (SQLServer).

### 🔎 What
Attacker performed SQL injection via URL parameter userNumber. Using UNION SELECT, they wrote a PHP web shell (cmd.php) to /var/www/html. The web shell was then used to execute commands and spawn a reverse shell using netcat back to 101.32.223.119 on port 1234.

### 🕐 When
Apr 18, 2021 at 01:00 PM.

### 📍 Where
Proxy logs show HTTP requests targeting internal web server SQLServer (172.16.20.6).

### 💡 Why
Attacker exploited SQL injection vulnerability to gain remote code execution and establish persistence via web shell, then executed a reverse shell to gain interactive access.

True Positive

Confirmed SQL injection exploitation resulting in web shell deployment and reverse shell connection. Endpoint isolated. Malicious IP 101.32.223.119 identified.
