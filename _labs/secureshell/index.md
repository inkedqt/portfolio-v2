---
layout: lab
title: secure shell
platform: BTLO
difficulty: Hard
category: Incident Response
skill: Incident Response
tools: "[linux-cli]"
tactics:
mitre: "[T1110, T1078, T1021.004]"
proof: https://blueteamlabs.online/achievement/share/challenge/144656/17
challenge_url: https://blueteamlabs.online/home/challenge/secure-shell-1aecac55c3
permalink: /blue-team/labs/secureshell/
summary: '"We had a SSH service on a system and noticed unusual change in size of the log file. "'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/f938ccab8738797243659e599219f6b978126441.png
type: challenge
points:
youtube:
locked: tate
---
# Secure Shell — Blue Team Labs Online

## Overview

This challenge involves analyzing SSH logs to investigate suspicious activity. The objective is to identify the attacker, determine how access was gained, and extract key forensic details from the log file.

---

## MITRE ATT&CK Mapping

- T1078 Valid Accounts
- T1110 Brute Force
- T1036 Masquerading (internal source blending in)
- T1021.004 Remote Services: SSH
- T1087 Account Discovery

---

## Scenario

A system running an SSH service experienced an unusual increase in log file size. The logs were provided for analysis to determine whether the activity was malicious.

---

## Analysis

### 1. Attacker Source

Command:  
cat sshlog.log | grep -i "connection from"

Finding:

- IP Address: 192.168.1.17
- Classification: Internal attack

The attacker originated from a private IP address, indicating lateral movement or insider activity.

---

### 2. Valid User Enumeration

Commands:  
cat sshlog.log | grep -i "userauth" | cut -d " " -f 8 | sort -u  
cat sshlog.log | grep "does not exist" | cut -d " " -f 13 | sort -u

Finding:

- Valid accounts: 1
- Username: sophia

The attacker performed username enumeration to identify valid accounts.

---

### 3. Successful Logins

Command:  
cat sshlog.log | grep "Accepted password"

Finding:

- Successful logins: 2

This confirms the attacker successfully authenticated to the system.

---

### 4. First Observed Activity

Command:  
cat sshlog.log | grep -i "connection from"

Finding:

- First request timestamp: 2021-04-29 23:52:25.989

This marks the initial access attempt.

---

### 5. Log Level

Command:  
cat sshlog.log

Finding:

- Log level: debug

The debug level provided detailed logging, which assisted in the investigation.

---

### 6. Log File Location (Windows)

Path:  
C:\ProgramData\ssh\logs\sshd.log

---

## Summary

- Attack Type: Internal (lateral movement or insider activity)
- Attacker IP: 192.168.1.17
- Valid Accounts Identified: 1 (sophia)
- Successful Logins: 2
- First Activity: 2021-04-29 23:52:25.989
- Log Level: debug

---

## Conclusion

The investigation shows an internal attacker enumerated users, identified a valid account, and successfully logged in multiple times via SSH. This demonstrates the risk of weak credentials and lack of monitoring on internal network activity. Proper logging, alerting, and account security controls are critical to detect and prevent similar incidents.




<div class="qa-item"> <div class="qa-question-text">Is it an internal or external attack, what is the attacker IP?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">internal:192.168.1.17</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">How many valid accounts did the attacker find, and what are the usernames?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">1:sophia</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">How many times did the attacker login to these accounts?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">2</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">When was the first request from the attacker recorded?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">2021-04-29 23:52:25.989</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the log level for the log file?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">debug</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Where is the log file located in Windows?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">C:\ProgramData\ssh\logs\sshd.log</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>
