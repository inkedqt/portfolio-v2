---
title: "Possible Brute Force Detected on VPN"
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1105
  - mitre/T1078
  - bruteforce
date: 2026-02-08
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC210
---

MITRE ATTACK  
T1110 Brute Force  
T1078 Valid Accounts

Who  
An external IP address 37.19.221.229 attempted multiple VPN logins against user accounts including tane@letsdefend.io, sane@letsdefend.io, fane@letsdefend.io and mane@letsdefend.io

What  
Multiple failed VPN authentication attempts were detected from the same source IP, followed by a successful login to mane@letsdefend.io. The activity indicates a brute force attempt that resulted in valid account access.

When  
Jun 21, 2023, 01:51 PM

Where  
Source IP: 37.19.221.229  
Destination: vpn-letsdefend.io (Host: Mane)

Why  
Authentication logs show repeated failed login attempts against multiple usernames from the same IP address, followed by a successful login shortly after. This pattern is consistent with brute force or credential stuffing activity leading to account compromise.

Response  
The affected account and associated host were isolated and contained.



---

_If you made it this far and you speak a little hex..._ `0x74617465.sh`