---
title: "Quishing Detected (QR Code Phishing)"
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - quishing
  - mitre/T1556
  - mitre/T1566-001
  - mitre/T1021-002
  - mitre/T1036
date: 2026-02-13
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC251
---
MITRE ATTACK Mapping

Initial Access  
T1566 Phishing  
QR code redirected the user to an external credential harvesting page.

Credential Access  
T1556 Modify Authentication Process  
The phishing page impersonated MFA implementation to capture credentials.  

Command and Control  
T1102 Web Service  
Malicious content hosted on ipfs.io web service infrastructure.

Defense Evasion  
T1036 Masquerading  
Email impersonated a legitimate security update and spoofed sender address.

### 👤 Who
An external sender using SMTP address 158.69.201.47 and spoofed email security microsecmfa com sent a phishing email to claire at letsdefend.io. The alert was generated for the recipient Claire who is an employee at letsdefend.io.

### 🔎 What
SIEM triggered alert SOC251 Quishing Detected QR Code Phishing with EventID 214. The email subject was New Years Mandatory Security Update Implementing Multi Factor Authentication MFA. The email contained a QR code. Decoding the QR code revealed a malicious phishing URL hosted on ipfs.io. The URL was previously confirmed as a credential harvesting page via VirusTotal and AnyRun sandbox analysis. The device action was allowed so the email was delivered to the user inbox.

### 🕐 When
The event occurred on Jan 01 2024 at 12 37 PM.

### 📍 Where
The email was received in the Exchange environment for letsdefend.io. The malicious URL resolved through ipfs.io infrastructure contacting IP addresses 169.150.247.38 and 209.94.90.1. Log review shows no access from the corporate network to these IP addresses. Endpoint review of Claires workstation shows no signs of compromise.

### 💡 Why
This alert was triggered because the email contained a QR code leading to a known phishing site designed to harvest username and password credentials. Although no evidence of access was found from the corporate network or endpoint, users commonly scan QR codes using personal mobile devices which may bypass enterprise logging and controls. As a precaution password reset and user awareness were recommended to mitigate potential credential compromise.
