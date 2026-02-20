---
title: "Impersonating Domain MX Record Change Detected"
type: soc-case
platform: letsdefend
status: closed
severity: Medium
tags:
  - phishing
  - mitre/T1566-001
  - mitre/T1584
  - mitre/T1589
  - mitre/T1598
  - spearphishing
date: 2026-02-12
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC326
youtube: https://www.youtube.com/watch?v=Oinrp7zOSAg
---
ALERT SUMMARY

45.33.23.183
MITRE ATTCK

T1584 Compromise Infrastructure  
T1566 Spearphishing Link  
T1589 Gather Victim Identity Information  
T1598 Phishing for Information


Threat actor registered typosquat domain letsdefwnd.io impersonating letsdefend.io and configured MX records to mail.mailerhost.net to send phishing emails. Email was delivered to internal user Mateo. User clicked the malicious link. At time of investigation the site was inactive and no payload was delivered.

WHEN

Alert time September 17 2024 12 05 PM  
User accessed malicious URL shortly after email delivery  
Detection occurred via threat intelligence monitoring and log correlation

WHERE

Malicious domain letsdefwnd.io  
MX record mail.mailerhost.net  
Target user Mateo  
Endpoint 172.16.17.162  
URL accessed http letsdefwnd.io

WHO

Unknown threat actor controlling letsdefwnd.io and mail.mailerhost.net  
Target user Mateo  
Affected endpoint 172.16.17.162  
Detection source CTI report

WHY

Attack used typosquatting and social engineering to impersonate legitimate company domain.  
Lure was voucher reward to trick user into clicking link.  
Likely goal was credential harvesting or voucher scam.

HOW

Threat actor registered lookalike domain replacing letter e with w.  
Configured mail infrastructure to send phishing email.  
User received email with subject Congratulations You Have Won a Voucher.  
User clicked link to letsdefwnd.io.  
Network logs confirm outbound HTTP connection from endpoint.  
Browser history confirms URL visit.  
Endpoint review shows no malware execution and no persistence.  
Site was inactive at time of access.

IMPACT

User interaction confirmed.  
No malware installation detected.  
No credential theft detected.  
Endpoint currently clean.  
Security awareness issue identified.

ACTION TAKEN

Investigated Exchange email logs.  
Confirmed network connection to malicious domain.  
Reviewed endpoint for malware and persistence.  
Blocked domain letsdefwnd.io.  
Recommended blocking mail.mailerhost.net at email gateway.  
User notified and advised on phishing awareness.  
Monitoring endpoint for 48 hours.

OUTCOME

True Positive phishing attempt.  
No active compromise detected.  
Case closed with monitoring and preventive controls implemented.