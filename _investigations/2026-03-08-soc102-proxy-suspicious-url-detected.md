---
type: soc-case
platform: letsdefend
status: closed
severity: High
tags:
  - mitre/T1071
date: 2026-03-08
MITRE ATT&CK:
outcome: False-positive
alert_id: SOC102
title: Proxy - Suspicious URL Detected
youtube: https://www.youtube.com/watch?v=a3YLgVEd-yg
---
T1071 Application Layer Protocol Web Protocols

### 👤 Who
User Chan on host ChanProd (IP address 172.16.17.150) accessed an external website using the Chrome browser.

### 🔎 What
The alert SOC102 Proxy Suspicious URL Detected triggered when the user accessed the URL [https://threatpost.com/malformed-url-prefix-phishing-attacks-spike-6000/164132/](https://threatpost.com/malformed-url-prefix-phishing-attacks-spike-6000/164132/) via a GET request. Investigation shows the request originated from chrome.exe with parent process explorer.exe, indicating normal user initiated browsing activity. Analysis of the URL in a sandbox environment confirmed the site threatpost.com is a legitimate cybersecurity news website discussing phishing trends.

### 🕐 When
Feb 22 2021 08:36 PM

### 📍 Where
Source Hostname ChanProd  
Source IP Address 172.16.17.150  
Destination IP Address 35.173.160.135  
Destination Hostname threatpost.com  
Request URL

The alert was triggered due to the URL containing the keyword phishing which caused the proxy detection rule to flag it as suspicious. Further investigation showed the request was a legitimate user browsing event. HTTP logs confirmed only a single connection to the website, sandbox analysis indicated the site is a trusted cybersecurity news source, and no malicious processes or suspicious activity were observed on the endpoint. The activity is classified as a false positive.
