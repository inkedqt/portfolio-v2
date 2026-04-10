---
type: soc-case
platform: letsdefend
status: closed
severity: Low
tags:
date: 2026-04-10
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC113
title: "- Suspicious hh.exe Usage"
youtube: https://www.youtube.com/watch?v=BaNDu0kKsvA
---

### 🔎 What
The alert SOC113 Suspicious hh.exe Usage triggered after execution of WinRAR.chm on host BillPRD. The file was downloaded and opened using hh.exe, which is commonly flagged as a LOLBIN. Analysis of the file hash and sandbox detonation confirms the file is a legitimate WinRAR help file with no malicious behavior.

### 🕐 When
Jan 31 2021 04:59 PM

### 📍 Where
Host BillPRD (172.16.17.47) accessed and executed WinRAR.chm using hh.exe

### 💡 Why
The alert was triggered due to hh.exe being used to open a CHM file, which can be abused for malicious execution. However, VirusTotal and sandbox analysis confirm the file is clean and no malicious activity was observed. The activity is classified as a false positivek