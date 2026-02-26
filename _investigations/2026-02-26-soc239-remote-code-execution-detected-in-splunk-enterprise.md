---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1190
  - mitre/T1059
  - mitre/T1105
  - mitre/T1136
  - mitre/T1505-003
  - CVE-2023-46214
date: 2026-02-26
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC239
title: Remote Code Execution Detected in Splunk Enterprise
youtube: https://www.youtube.com/watch?v=yUexYuQlrVs
---
## 🎯 MITRE ATT&CK
T1190 Exploit Public-Facing Application  
T1059 Command and Scripting Interpreter  
T1105 Ingress Tool Transfer  
T1136 Create Account  
T1505.003 Server Software Component

### 👤 Who
External Source IP 180.101.88.240 (geolocated to China) accessed Splunk Enterprise hosted at 172.16.20.13 / 18.219.80.54. The actor authenticated to Splunk using admin credentials and subsequently uploaded a malicious XSLT file to achieve remote code execution.

### 🔎 What
A high severity alert (SOC239) detected exploitation of a Splunk Enterprise vulnerability via malicious XSLT upload (Splunk App for Lookup File Editing RCE). The attacker performed a POST request to:

/en-US/splunkd/__upload/indexing/preview?output_mode=json&props.NO_BINARY_CHECK=1&input.path=shell.xsl

The upload triggered remote code execution, resulting in shell access. Post-exploitation activity included:

whoami  
groups  
useradd -m analsyt  
passwd analsyt

The attacker created a new user account for persistence and executed commands indicating interactive shell access. Reverse shell activity was observed. Device action was Allowed.

### 🕐 When
Event Time Nov 21, 2023 12:24 PM  
Initial Login Nov 21, 2023 12:23:56  
Command Execution 12:24:33 – 12:24:48  
User Account Creation 12:24:40  
Containment initiated shortly after detection

### 📍 Where
Affected Host Splunk Enterprise  
Internal IP 172.16.20.13  
Public IP 18.219.80.54  
Malicious Source IP 180.101.88.240  
Uploaded File Path /opt/splunk/var/run/splunk/dispatch/1700556926.3/shell.xsl  
Access Vector Splunk Web Interface (Port 8000)

### 💡 Why
The threat actor exploited a remote code execution vulnerability in Splunk Enterprise via malicious XSLT upload to gain shell access. Following successful exploitation, the attacker enumerated privileges and established persistence by creating a new local user account. The activity demonstrates full interactive command execution capability and potential for lateral movement or data exfiltration.

Assessment  
True Positive. Confirmed remote code execution with interactive shell access and persistence established via local user creation. Immediate containment performed, including host isolation and escalation for incident response, credential rotation, and forensic acquisition.
