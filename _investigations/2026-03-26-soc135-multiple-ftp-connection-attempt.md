---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
date: 2026-03-26
MITRE ATT&CK: mitre/T1110
outcome: true-positive
alert_id: SOC135
title: Multiple FTP Connection Attempt
youtube: https://www.youtube.com/watch?v=8P7Ofu4yOu4
---
T1110 Brute Force

### 👤 Who
An external attacker from IP address 42.192.84.19 targeted the internal server gitServer (IP address 172.16.20.4).

### 🔎 What
The alert SOC135 Multiple FTP Connection Attempt triggered due to repeated authentication attempts against the FTP web interface endpoint /ftp/webUI.php. Log analysis shows multiple login attempts using common credential combinations such as admin/admin, admin/123456, and admin/root, which is indicative of a brute force attack attempting to gain unauthorized access.

### 🕐 When
Mar 07 2021 05:09 PM

### 📍 Where
Source IP Address: 42.192.84.19
Destination Hostname: gitServer
Destination IP Address: 172.16.20.4
Target Endpoint: http://172.16.20.4/ftp/webUI.php

### 💡 Why
The alert was triggered due to multiple authentication attempts from a single external IP address targeting an FTP login interface. The use of common default credentials confirms this is a brute force attempt. There is no indication of a successful login in the logs, suggesting the attack was unsuccessful. The activity is classified as a true positive brute force attempt with no confirmed compromise.
