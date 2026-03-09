---
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1046
  - nmap
date: 2026-03-10
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC147
title: SSH Scan Activity
youtube: https://www.youtube.com/watch?v=voqNx10QUy4
---
T1046 Network Service Discovery

### 👤 Who
The activity originated from host PentestMachine (IP address 172.16.20.5). The scan was conducted by an internal user Ellie as part of a planned security assessment.

### 🔎 What
The alert SOC147 SSH Scan Activity triggered due to the execution of the tool nmap (hash 3361bf0051cc657ba90b46be53fe5b36) on the host PentestMachine. The tool attempted to scan SSH services across the network, resulting in two SSH scan detections in HTTP logs. Nmap is a common network reconnaissance tool used to identify open ports and running services.

### 🕐 When
Jun 13 2021 04:23 PM

### 📍 Where
Source Hostname PentestMachine
Source IP Address 172.16.20.5
Scanning activity observed across the internal LetsDefend network targeting SSH services.

### 💡 Why
Prior communication was received by the SOC team indicating that Ellie would be conducting authorized network scanning from host PentestMachine starting after 12:00 on Jun 13 2021 and continuing throughout the day. The alert was triggered due to normal detection rules identifying SSH scanning behavior. However, the activity corresponds with the scheduled internal penetration test and is therefore classified as legitimate security testing rather than malicious activity.
