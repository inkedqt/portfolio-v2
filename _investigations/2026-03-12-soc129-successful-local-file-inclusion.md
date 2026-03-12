---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1190
  - mitre/T1006
  - LFI
date: 2026-03-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC129
title: Successful Local File Inclusion
youtube: https://www.youtube.com/watch?v=9C3J5QxIOhk
---
T1190 Exploit Public Facing Application  
T1006 Path Traversal

### 👤 Who
An external attacker from IP address 49.234.71.65 attempted to access the internal web server gitServer (IP address 172.16.20.4). The request was made using a web client with user agent Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4).

### 🔎 What
The alert SOC129 Successful Local File Inclusion triggered after a request attempted to exploit a Local File Inclusion vulnerability in the application endpoint /srcCode/show.php. The attacker attempted directory traversal using the parameter page=../../../../../../../etc/passwd to access the system file /etc/passwd on the server. HTTP logs show the request was processed by the server but the application responded with a 404 error, indicating the file was not successfully retrieved.

### 🕐 When
Feb 21 2021 05:02 PM

### 📍 Where
Source IP Address 49.234.71.65  
Destination Hostname gitServer  
Destination IP Address 172.16.20.4  
Target Endpoint /srcCode/show.php?page=../../../../../../../etc/passwd

### 💡 Why
The alert was triggered due to a request pattern commonly associated with Local File Inclusion and directory traversal attacks targeting web applications. Threat intelligence indicates the source IP address is malicious and geolocated to China. However, server logs show the request resulted in a 404 response and no sensitive files were returned, suggesting the exploitation attempt was unsuccessful. The activity is classified as a failed web exploitation attempt targeting a public facing application.
