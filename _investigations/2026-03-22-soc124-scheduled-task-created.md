---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1053-005
date: 2026-03-22
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC124
title: SOC144 - New scheduled task created
youtube: https://www.youtube.com/watch?v=xcPDt4EsI8M
---

T1053.005 Scheduled Task

### 👤 Who
Activity was detected on host Maxim (IP address 172.16.17.83). The process involved the executable GoogleUpdate.exe on the endpoint.

### 🔎 What
The alert SOC124 Scheduled Task Created triggered due to the creation of a scheduled task associated with GoogleUpdate.exe (hash 82f657b0aee67a6a560321cf0927f9f7). Scheduled tasks are commonly used by both legitimate software and malware for persistence. In this case, the executable name and behavior align with Google’s legitimate update mechanism.

### 🕐 When
Feb 14 2021 11:17 AM

### 📍 Where
Source Hostname: Maxim
Source IP Address: 172.16.17.83
Process: GoogleUpdate.exe
Activity: Scheduled task creation on the endpoint

### 💡 Why
The alert was triggered due to detection of a scheduled task creation event, which is often associated with persistence techniques. However, investigation shows that GoogleUpdate.exe is a legitimate Google component used to maintain automatic updates via scheduled tasks. The hash and behavior are consistent with normal Google update operations, and no additional suspicious activity was observed. The alert is classified as a false positive representing legitimate system activity.