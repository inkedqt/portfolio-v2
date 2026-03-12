---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1190
  - mitre/T1505-003
  - mitre/T1059
  - webshell
  - RCE
date: 2026-03-13
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC128
title: Malicious File Upload Attempt
youtube: https://www.youtube.com/watch?v=Ph_4qwzCcZA
---
T1190 Exploit Public Facing Application  
T1505.003 Web Shell  
T1059 Command and Scripting Interpreter

### 👤 Who
An external attacker exploited the web server hosted on gitServer (IP address 172.16.20.4). The malicious activity targeted the web application upload functionality and resulted in the execution of commands through a web shell.

### 🔎 What
The alert SOC128 Malicious File Upload Attempt triggered after a malicious PHP file named phpshell.php (hash 756215a64e7d43153298f1a5a5fde295) was uploaded to the server through the endpoint /srcCode/upload.php. The uploaded file contained a PHP web shell capable of executing system commands provided through the cmd parameter. HTTP logs confirmed the attacker accessed the uploaded web shell and executed commands such as whoami and cat /etc/passwd, demonstrating successful remote command execution on the server. VirusTotal analysis confirms the file hash is malicious and the script content matches a typical PHP command shell.

### 🕐 When
Feb 22 2021 04:31 PM

### 📍 Where
Source Hostname gitServer  
Source IP Address 172.16.20.4  
Compromised Endpoint /srcCode/upload.php  
Malicious Web Shell /srcCode/phpshell.php  
Command Execution Request /srcCode/phpshell.php?cmd=whoami

### 💡 Why
The alert was triggered due to detection of a malicious file upload to the web server. Investigation confirmed the attacker successfully uploaded and executed a PHP web shell which allowed arbitrary command execution on the host. Endpoint logs show commands being executed through the web shell, confirming system compromise. The affected endpoint was isolated to contain the incident and prevent further attacker activity.
