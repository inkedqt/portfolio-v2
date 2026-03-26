---
layout: lab
title: Crack
platform: BTLO
difficulty: Easy
category: Incident Response
skill: Incident Response
tools: "[JSON Crack]"
tactics:
mitre: "[T1078.003, T1133]"
proof: https://blueteamlabs.online/achievement/share/144656/145
challenge_url: https://blueteamlabs.online/home/investigation/crack-e5326ef2f8
permalink: /blue-team/labs/crack/
summary: '"Use JSON Crack to investigate failed login attempts to a website."'
art: https://blueteamlabs.online/storage/labs/4cceaf428a5ad5129e4e813b58fe3610ac5cd976.png
type:
points:
youtube:
locked: tate
---
## Scenario

Investigate failed login attempts to a web application using a provided JSON log file. The lab suggests using JSON Crack (a visual JSON explorer via Docker) but this was non-functional in the VM. All analysis was completed using standard command-line tools — `grep`, `wc`, and `base64`.

---

## Methodology

### Environment Note

The lab provides a Docker-based JSON Crack GUI:

```zsh
sudo docker run -p 8888:8080 jsoncrack
```

accessible at `http://localhost:8888`. This was non-functional in the lab VM. Fortunately `grep` handles JSON log analysis perfectly well and is arguably faster for targeted queries.

### Identifying the Attacker IP

A quick grep for all IP addresses in the log reveals the distribution of requests:

```zsh
cat application-logs.json | grep -i '"ip_address"'
```

Output shows `198.51.100.100` appearing on 10 consecutive entries, with a single outlier `198.23.200.101` at the end. The pattern is clear — one IP is hammering the login endpoint repeatedly.

**Attacker IP: `198.51.100.100`**

The second IP (`198.23.200.101`) is significant — it appears in a successful login event, suggesting the attacker logged in from a different address after cracking the credentials, or this is a legitimate user whose credentials were compromised.

### Enumerating Non-Existent Accounts

The log uses two distinct failure reasons for accounts that don't exist. Searching for each separately:

```zsh
cat application-logs.json | grep -i "Username not found" | wc -l
# 5

cat application-logs.json | grep -i "User not found" | wc -l
# 4
```

Extracting the actual usernames for each failure type using `-A 1` to grab the line following the match:

bash

```zsh
cat application-logs.json | grep -i '"failure_reason": "Username not found"' -A 1
```

Returns:

- `adminpanel`
- `loginpage`
- `adminpage`
- `adminservice`
- `websupport`

bash

```zsh
cat application-logs.json | grep -i '"failure_reason": "User not found"' -A 1
```

Returns:

- `webmaster`
- `websitedev`
- `websitedbadmin`
- `websitebackup`

**Total non-existent accounts: 9** (5 + 4)

The two different error messages for the same condition is a minor application information disclosure — ideally both should return an identical generic message to prevent username enumeration.

### Accounts That Do Exist — Incorrect Password Failures

Accounts that returned "Incorrect password" are confirmed to exist on the application:

```zsh
cat application-logs.json | grep -i '"Incorrect password"' -A 1
```

Returns attempts against:

- `websitemanager`
- `webadmin` (multiple attempts)
- `ftp`

**Existing accounts (alphabetical): `ftp`, `webadmin`, `websitemanager`**

### Successful Login

```bash
cat application-logs.json | grep -i '"success"' -A 2
```

Reveals a successful authentication:


```json
"status": "Success",
"failure_reason": "N/A",
"username": "webadmin"
```

The attacker successfully brute-forced the `webadmin` account after multiple incorrect password attempts. The successful login timestamp was **2023-06-29T10:00:10**.

### Decoding the Password

The log stores passwords as Base64-encoded strings. The successful login entry contains:

```
"hashed_password": "d2ViYWRtaW4xMjM0"
```

Decoding:

```zsh
echo "d2ViYWRtaW4xMjM0" | base64 -d
# webadmin1234
```

**Decoded password: `webadmin1234`** — a trivially weak credential for an admin account, and exactly what the attacker was counting on.

Note: the field is labelled `hashed_password` but Base64 is encoding, not hashing. A real hash (bcrypt, Argon2, etc.) would be irreversible. This is a significant application security flaw — if this log were exfiltrated, all passwords would be instantly recoverable.

### Attack Summary

The full credential stuffing/brute force sequence from `198.51.100.100`:

1. Enumerated 9 non-existent usernames across two error message variants
2. Identified 3 valid accounts via "Incorrect password" responses
3. Successfully brute-forced `webadmin` with password `webadmin1234`
4. A subsequent successful login from `198.23.200.101` suggests either the attacker pivoted IPs or the legitimate user logged in after the compromise

---

## IOCs

|Type|Value|
|---|---|
|IP (Attacker)|198.51.100.100|
|IP (Post-compromise / legitimate)|198.23.200.101|
|Compromised Account|webadmin|
|Compromised Password|webadmin1234|
|Auth Endpoint|/api/login|
|User-Agent|Mozilla/5.0 ... Chrome/91.0.4472.124 Safari/537.36|

---

## MITRE ATT&CK

|Technique|ID|Description|
|---|---|---|
|Brute Force: Password Guessing|T1110.001|Sequential password attempts against webadmin|
|Brute Force: Credential Stuffing|T1110.003|Wordlist of web-themed usernames attempted|
|Valid Accounts|T1078|Successful login with webadmin:webadmin1234|

---

## Defender Takeaways

**Username enumeration** — The application returns different error messages for "username not found" vs "incorrect password". This allows attackers to confirm valid accounts before focusing brute force attempts. All failed login attempts should return an identical generic message.

**Weak credentials** — `webadmin1234` is a predictable credential for an admin account. Password complexity requirements and a banned password list would have prevented this.

**No rate limiting** — 10+ sequential failed attempts from the same IP with no lockout or CAPTCHA. IP-based rate limiting and account lockout after N failures are standard controls.

**Base64 is not hashing** — Storing passwords encoded rather than properly hashed (bcrypt/Argon2) means log exfiltration equals instant credential recovery. Logs should never contain passwords in any form.

**No MFA** — A second factor on the webadmin account would have rendered the brute-forced password useless.

---

<div class="qa-item"> <div class="qa-question-text">What IP address is performing the attack? (Format: X.X.X.X)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">198.51.100.100</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the end of the user-agent string? (Format: Chrome/...</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Chrome/91.0.4472.124 Safari/537.36</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">How many accounts have authentication attempts, but don't exist on the application? (Format: Number of accounts)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">9</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What are the usernames (in alphabetical order) of accounts that do exist on the application? (Format: name, name, ...)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">ftp, webadmin, websitemanager</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the username for the account that has successful logins seen? (Format: user)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">webadmin</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the IP address of the other system that has logged into this account? (Format: X.X.X.X)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">198.23.200.101</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the endpoint being used to make these authentication attempts? (Format: Endpoint)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">/api/login</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the timestamp of the first successful login? (Format: YYYY-MM-DDTHH:MM:SS)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">2023-06-29T10:00:10</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Decode the password, what is the value? (Format: Password)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">ANSWER</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

