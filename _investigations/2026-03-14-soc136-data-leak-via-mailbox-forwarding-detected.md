---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1567
  - mitre/T114
  - data-exfil
date: 2026-03-14
MITRE ATT&CK:
outcome: true-positive
alert_id: SOC136
title: Data Leak via Mailbox Forwarding Detected
youtube: https://www.youtube.com/watch?v=KIhPosT3u7w
---

T1567 Exfiltration Over Web Service  
T1114 Email Collection

### 👤 Who
The activity involved user katharine@letsdefend.io on the internal mail server (IP address 172.16.20.3). The mailbox attempted to forward an email to an external address katharine.isabell@yandex.ru.

### 🔎 What
The alert SOC136 Data Leak via Mailbox Forwarding Detected triggered when an email containing sensitive information was detected attempting to be forwarded externally. The email included credential pairs such as root, john, bill, and admin with associated passwords, which indicates potential credential leakage. The forwarding attempt targeted an external Yandex email address, which is outside the organization.

### 🕐 When
Mar 07 2021 05:31 PM

### 📍 Where
Source Address katharine@letsdefend.io  
Destination Address katharine.isabell@yandex.ru  
Mail server SMTP address 172.16.20.3

### 💡 Why
The alert triggered due to detection of sensitive credential information being forwarded externally via email. The mail security control successfully blocked the transmission, preventing potential data exfiltration. No additional suspicious activity was observed on Katharine’s endpoint, suggesting the event may have been accidental or part of testing. However, since credentials were involved and the action attempted to send them outside the organization, the activity is classified as a true positive and should be escalated to confirm with the user whether the forwarding was intentional and to ensure credentials are rotated if necessary.
