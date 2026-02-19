---
title: "SQL Injection Detected"
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - sqli
  - mitre/T1190
  - mitre/T1059
date: 2026-02-08
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC127
---
## 🧾 Alert Summary

## 🧩 MITRE ATT&CK
- T1190 – Exploit Public-Facing Application

- T1059 – Command and Scripting Interpreter

## 🔍 Investigation
WHO:
External attacker originating from 118.194.247.28 using automated exploitation tooling (sqlmap).

WHAT:
SQL Injection attempt observed against web application, including UNION-based queries and OS command execution attempts.

WHEN:
Mar 07, 2024 at ~12:51 PM.

WHERE:
Web application hosted on WebServer1000 (172.16.20.12) over HTTP (port 80).

WHY:
Attacker attempted to enumerate database tables and execute OS-level commands via SQL injection (xp_cmdshell).

HOW:
Malicious SQL payloads delivered via HTTP GET requests and processed by the web server. Requests were allowed and returned HTTP 200 responses.

IMPACT:
Exploitation success cannot be confirmed due to lack of endpoint or database telemetry. Attack classified as suspected successful SQL injection.

ACTION TAKEN:
Alert escalated for further investigation. Recommendation to review web server and database logs and enable EDR/WAF controls.

