---
title: "VPN Connection Detected from Unauthorized Country"
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - mitre/T1078
  - mitre/T1621
date: 2026-02-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC257
---
ALERT SUMMARY
MITRE ATTCK  
T1078 Valid Accounts  
T1621 Multi Factor Authentication Request Generation

WHO  
External IP 113.161.158.12 located in Hanoi Vietnam.  
Target account monica@letsdefend.io.  
Destination host Monica 33.33.33.33.

WHAT  
VPN login attempt detected from unauthorized country.  
Three MFA OTP emails generated for Monica account.  
Firewall and VPN logs show Incorrect OTP Code responses.  
No successful authentication observed.

WHEN  
Feb 13 2024 at approximately 02:03 AM.

WHERE  
VPN portal https vpn letsdefend.io.  
Source IP 113.161.158.12.  
Destination 33.33.33.33 over port 443.

WHY  
Attacker likely attempting to use stolen credentials to access VPN.  
Repeated OTP generation suggests password guessing or credential stuffing attempt.  
Unauthorized geographic location triggered alert.

HOW  
Attacker submitted VPN login requests using Monica account.  
System generated OTP codes for MFA validation.  
VPN logs confirm Incorrect OTP Code for each attempt.  
No evidence of successful login session.

IMPACT  
Multiple unauthorized login attempts confirmed.  
No successful VPN access detected.  
Account not compromised based on current logs.

ACTION TAKEN  
Confirm with Monica whether activity was legitimate.  
Recommend password reset as precaution.  
Monitor account for additional suspicious attempts.  
Block source IP if policy allows.
