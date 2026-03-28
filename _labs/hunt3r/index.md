---
layout: lab
title: HUNT3R
platform: BTLO
difficulty: Medium
category: Incident Response
skill: Incident Response
tools: "[Linux CLI, Sublime Text 2, OSINT, Gnumeric, CyberChef]"
tactics:
mitre: "[T1584.006, T1595.003, T1190, T1083]"
proof: https://blueteamlabs.online/achievement/share/144656/127
challenge_url: https://blueteamlabs.online/home/investigation/hunt3r-e329432fc3
permalink: /blue-team/labs/hunt3r/
summary: '"Analyse an IIS web server log dump to identify anomalous traffic, attribute the source IP via OSINT, and characterise a directory traversal/enumeration attack that successfully exfiltrated a configuration archive in under 20 seconds."'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/a7ab8e94a27d6e20040a2041a13a5a8ef096be3d.png
type:
points:
youtube:
locked: tate
---
## Scenario

During routine threat hunting activities, web logs from an IIS server are retrieved for analysis. The task is to identify malicious activity within the log dump, attribute the source, and reconstruct the attack timeline using command-line tooling and OSINT.

---

## Methodology

### Stage 1 — Log Structure and Initial Triage

The provided `iis-log-dump.log` is opened in Gnumeric to understand the field structure. The IIS W3C log format header confirms the column order:

```
date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```

Key fields for analysis: `s-ip` (server), `c-ip` (client), `cs-uri-stem` (requested resource), `sc-status` (response code), and `cs(User-Agent)`.

From the log header and early entries, the web server is immediately identifiable: `194.77.176.185` serving `https://DicksonUnited.co.uk`.

### Stage 2 — Identifying the Malicious Source IP

Rather than manually reviewing thousands of log entries, `awk` and `uniq` are used to rank all client IPs by request volume:

```bash
grep -v "^#" iis-log-dump.log | awk '{print $9}' | sort | uniq -c | sort -rn
```

One IP generates dramatically more requests than all others in the log — `200.10.209.169` with 833 lines, dwarfing every other source. The volume disparity alone is a strong indicator of automated scanning or enumeration activity.

### Stage 3 — Attacker Attribution via OSINT

The IP `200.10.209.169` is submitted to [ipinfo.io](https://ipinfo.io/200.10.209.169), returning a geolocation of **Ecuador**. While geolocation alone is not attribution, it is inconsistent with expected traffic patterns for a UK-hosted domain and confirms the IP is externally sourced.

### Stage 4 — User-Agent Analysis


```zsh
grep "200.10.209.169" iis-log-dump.log | awk '{print $10}' | sort -u
```

A single user-agent is used across all 833 requests:

```
Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/78.0.3904.108+Safari/537.36
```

Chrome 78 was released in October 2019 — using a three-year-old browser version in 2022 is a weak attempt at blending in. Automated scanners and enumeration tools frequently use outdated or generic user-agent strings. The single consistent user-agent across 833 requests with no variation is itself a behavioural indicator — legitimate browser sessions produce varied request patterns.

### Stage 5 — Quantifying the Attack Surface

```zsh
grep -c "200.10.209.169" iis-log-dump.log
```

**833 total log lines** reference the attacker IP. Extracting unique URIs accessed:

```zsh
grep "200.10.209.169" iis-log-dump.log | awk '{print $5}' | sort -u | wc -l
```

**653 unique URIs** — 653 distinct paths probed in a single session. This is consistent with a web content discovery or directory enumeration tool such as `gobuster`, `ffuf`, or `dirbuster` running a wordlist against the target.

### Stage 6 — Identifying the Successful Request

Of 833 requests, only one returned a 200 status code — everything else received 404s or other error responses consistent with enumeration against non-existent paths:

```zsh
grep "200.10.209.169" iis-log-dump.log | awk '$12 == 200'
```

```
2022-10-17 18:18:59 194.77.176.185 GET /settings.tgz - 443 - 200.10.209.169 Mozilla/5.0+... - 200 0 0 29
```

The attacker successfully retrieved `/settings.tgz` — a configuration archive. `.tgz` files on a web server represent a serious misconfiguration: configuration archives frequently contain credentials, API keys, database connection strings, or infrastructure details. This single successful hit in the middle of 832 failed attempts is the crown jewel of the attack.

### Stage 7 — Attack Timeline

```bash
grep "200.10.209.169" iis-log-dump.log | awk '{print $1, $2}' | sort | sed -n '1p;$p'
```

```
2022-10-17 18:18:59
2022-10-17 18:19:15
```

First request: `18:18:59` — Last request: `18:19:15` — **16 seconds total duration**. 833 requests across 653 unique paths in 16 seconds is only achievable with an automated tool running at high concurrency. The successful hit on `settings.tgz` occurred at the very first timestamp, meaning the tool hit the target on its first pass and continued enumerating regardless.

### Stage 8 — Total Unique Source IPs

```bash
grep -v "^#" iis-log-dump.log | awk '{print $9}' | sort -u | wc -l
```

**243 unique source IPs** in the full log file, confirming the attacker IP stands out against a large pool of otherwise legitimate traffic.

---

## Attack Summary

|Phase|Action|
|---|---|
|Reconnaissance|Automated enumeration from 200.10.209.169 against DicksonUnited.co.uk|
|Discovery|653 unique URIs probed across 833 requests in 16 seconds|
|Collection|GET /settings.tgz returned HTTP 200 — configuration archive retrieved|
|Attribution|Ecuador-geolocated IP; Chrome 78 UA string; single consistent user-agent|

---

## IOCs

|Type|Value|
|---|---|
|IP (Attacker)|200[.]10[.]209[.]169|
|Geolocation|Ecuador|
|User-Agent|Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/78.0.3904.108+Safari/537.36|
|Target Server|194[.]77[.]176[.]185|
|FQDN|hxxps[://]DicksonUnited[.]co[.]uk|
|File Accessed|/settings.tgz|
|URL (Successful)|hxxps[://]DicksonUnited[.]co[.]uk/settings.tgz|
|Timestamp (Hit)|2022-10-17 18:18:59|
|Attack Duration|16 seconds|

---

## MITRE ATT&CK

|Technique|ID|Description|
|---|---|---|
|Active Scanning: Wordlist Scanning|T1595.003|653 unique URIs probed via automated enumeration tool in 16 seconds|
|Exploit Public-Facing Application|T1190|Successful retrieval of exposed configuration archive via HTTP GET|
|File and Directory Discovery|T1083|Systematic enumeration of web server paths to identify accessible resources|

---

## Defender Takeaways

**Sensitive file exposure** — `settings.tgz` being accessible via a direct GET request on a public-facing web server is the core failure here. Configuration archives, backups, and any file with extensions like `.tgz`, `.zip`, `.bak`, `.sql`, or `.env` should never reside in the web root. A WAF rule blocking requests to these extensions is a quick compensating control, but the root fix is keeping configuration material out of directories served by the web server entirely.

**Volume-based anomaly detection** — 833 requests from a single IP in 16 seconds is trivially detectable with a rate-limiting rule or SIEM alert. A threshold of even 100 requests per minute from a single source should trigger automated review or temporary block. The attack succeeded before any human could respond — automated countermeasures are the only realistic defence at this speed.

**User-agent anomaly detection** — Chrome 78 in 2022 is a low-effort indicator. Maintaining a rolling baseline of expected user-agent strings and alerting on statistically rare or outdated versions adds a lightweight detection layer. A single user-agent across hundreds of requests with no referer variation is an additional signal.

**404 storm as a pre-compromise signal** — 832 consecutive 404 responses from one IP before a successful hit is a textbook enumeration pattern. SIEM rules correlating high 404 rates from a single source against the same target host surface this activity before the successful request occurs, enabling blocking mid-enumeration rather than post-exfiltration.


---

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 1) What is the IP address of the web server, and what is the FQDN? (Format: X.X.X.X, https://domain.tld)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">194.77.176.185, https://DicksonUnited.co.uk</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 2) Investigate the logs to identify what is expected traffic, and what isn't. What is the source IP related to malicious activity? (Format: X.X.X.X)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">200.10.209.169</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 3) Use OSINT tools to find the country associated with this IP (Format: Country Name)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Ecuador</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 4) What is the user-agent string used by the malicious actor? (Format: User-agent)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/78.0.3904.108+Safari/537.36</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 5) How many lines in the log file reference the malicious IP address? (Format: Number of Lines)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">833</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 6) Which request made by the malicious IP resulted in a successful connection? Provide the URL that was accessed (including the FQDN) (Format: https://domain.tld/somethinghere)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">https://DicksonUnited.co.uk/settings.tgz</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 7) What is the timestamp for this successful request? (Format: YYYY-MM-DD HH:MM:SS)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">2022-10-17 18:18:59</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 8) Looking at only requests for this IP, based on the timestamps of the first and last events, what was the duration of the attack in seconds? (Format: Seconds Duration)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">16</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 9) How many URIs accessed by this IP are unique? (Format: Number of Unique URIs Accessed)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">653</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">iis-log-dump.log Question 10) How many unique source IPs are observed within the log file? (including the malicious IP) (Format: Count of Unique IPs)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">243</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

