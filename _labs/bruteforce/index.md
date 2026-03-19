---
layout: lab
title: bruteforce
platform: BTLO
difficulty: Medium
category: Network Forensics
skill: Network Forensics
tools: "[grep, excel]"
tactics:
mitre: "[T1110.001, T1078]"
proof: https://blueteamlabs.online/achievement/share/challenge/144656/40
challenge_url: https://blueteamlabs.online/home/challenge/bruteforce-16629bf9a2
permalink: /blue-team/labs/bruteforce/
summary: '"Analysis of Windows Security Event logs revealing an RDP brute force attack targeting the local Administrator account from a Vietnamese IP address, generating over 3000 Audit Failure events."'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/801436163080cfe8f2ebc6f2de48607f6001144d.png
type: challenge
points:
youtube:
locked: tate
---
## Overview

A system administrator flagged a high volume of Audit Failure events in the Windows Security Event log. The task is to analyse the logs, identify the attacker, characterise the brute force campaign, and extract key IOCs.

---

## Investigation

### Scope of the Attack

The first step is quantifying the noise. A quick grep against the logs reveals the scale of the campaign:

```zsh
cat * | grep -a -i "audit failure" | wc -l
```

**3103** Audit Failure events — a clear indicator of an automated brute force tool rather than manual attempts.

### Target Account and Failure Reason

Filtering for account information points directly to the targeted user:

```zsh
cat * | grep -a -i "account"
```

The attacker was hammering the **Administrator** account — the default privileged local account and a predictable brute force target. Every failure logged the reason as **"Unknown user name or bad password."**, confirming credential stuffing or password spraying rather than a lockout-based error. These events are recorded under Windows Event ID **4625** — the standard logon failure event.

### Attacker IP and Geolocation

Pulling the source address from the logs:

```zsh
cat * | grep -a -i "address"
```

All 3103 failures originate from a single IP: `113[.]161[.]192[.]227`. A lookup via `ipinfo.io` geolocates this address to **Vietnam**.

### Source Port Range

With an attack of this volume, the attacker cycled through ephemeral source ports across the session. Extracting the full range:

```zsh
cat * | grep -a "Source Port" | grep -oP '\d+' | sort -n | awk 'NR==1{low=$1} {high=$1} END{print low"-"high}'
```

The ports spanned **49162–65534**, consistent with the Windows dynamic port range and indicative of a sustained, high-volume automated tool running over an extended period.

---

## IOCs

| Type              | Value                   |
| ----------------- | ----------------------- |
| IP — Attacker     | `113[.]161[.]192[.]227` |
| Country           | Vietnam                 |
| Target Account    | `Administrator`         |
| Event ID          | `4625`                  |
| Source Port Range | `49162–65534`           |

---

<div class="qa-item"> <div class="qa-question-text">Question 1) How many Audit Failure events are there? (Format: Count of Events)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">3103</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 2) What is the username of the local account that is being targeted? (Format: Username)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">administrator</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 3) What is the failure reason related to the Audit Failure logs? (Format: String)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Unknown user name or bad password.</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 4) What is the Windows Event ID associated with these logon failures? (Format: ID)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">4625</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 5) What is the source IP conducting this attack? (Format: X.X.X.X)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">113.161.192.227</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 6) What country is this IP address associated with? (Format: Country)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">vietnam</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 7) What is the range of source ports that were used by the attacker to make these login requests? (LowestPort-HighestPort - Ex: 100-541)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">49162-65534</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>
