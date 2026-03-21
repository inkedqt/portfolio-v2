---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1219
date: 2026-03-21
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC108
title: Malicious Remote Access Software Detected
youtube: https://www.youtube.com/watch?v=nCWnN5enrmo
---
T1219 Remote Access Software

### 👤 Who
User Mark on host MarksPhone (IP address 10.15.15.12) initiated the connection.

### 🔎 What
The alert SOC108 Malicious Remote Access Software Detected triggered due to access to https://www.teamviewer.com from a mobile Chrome browser. TeamViewer is a legitimate remote access software, but it is commonly flagged by detection rules due to its potential misuse by attackers. No suspicious parameters, downloads of modified binaries, or abnormal behavior were observed in the request.

### 🕐 When
Feb 07 2021 01:21 PM

### 📍 Where
Source Hostname: MarksPhone
Source IP Address: 10.15.15.12
Destination IP Address: 13.95.16.245
Destination Hostname: teamviewer.com
Request URL: https://www.teamviewer.com

### 💡 Why
The alert was triggered because TeamViewer is categorized as remote access software that can be abused for unauthorized access. However, investigation shows the connection was made to the official TeamViewer website using a standard mobile browser and there is no evidence of malicious activity or compromise. This activity is classified as a false positive representing legitimate software access.
