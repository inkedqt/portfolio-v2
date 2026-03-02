---
layout: lab
title: Ramnit
platform: CyberDefenders
difficulty: Easy
category: "[Endpoint Forensics]"
tools: "[Volatility 3, VirusTotal]"
tactics: "[Execution, Defense Evasion, Command and Control]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/ramnit/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/ramnit/
permalink: /blue-team/labs/ramnit/
summary: '"Analyze a memory dump using Volatility to identify a malicious process, extract network IOCs, file hash, and compilation timestamp, correlating with external threat intelligence."'
art: https://cyberdefenders.org/media/terraform/Ramnit/Ramnit.webp
---
# Ramnit – Memory Forensics Investigation
## Scenario

An intrusion detection system alerted on suspicious behavior on a workstation indicating a likely malware intrusion. A memory dump was captured for analysis. The objective was to identify the malicious process, trace network activity, and extract file artifacts.

---
## Tooling

- Volatility 3 Framework 2.28.0 
- VirusTotal 
- SHA1sum / SHA256sum
---
## Investigation Findings
### 1. Process Analysis
Initial triage using process tree and scan plugins revealed a suspicious process: 
```
vol -f memory.dmp windows.pstree 
vol -f memory.dmp windows.psscan 
vol -f memory.dmp windows.cmdline
```

A process named `ChromeSetup.exe` was identified running from an unusual path: `C:\Users\alex\Downloads\ChromeSetup.exe` Legitimate Chrome installers do not persist as running processes from the Downloads folder. This immediately flagged as suspicious.


![ramnit_pstree.png](ramnit_pstree.png)

---
### 2. Network Connections
```bash
vol -f memory.dmp windows.netscan.NetScan
```
Network scan revealed active and closed connections associated with `ChromeSetup.exe` (PID 4628):
![ramnit_netscan.png](ramnit_netscan.png)

Geolocation of `58.64.204.181` resolves to **Hong Kong**. This is consistent with Ramnit C2 infrastructure.

---
### 3. File Extraction and Hashing
Located the malicious file in memory using filescan:
```bash
vol -f memory.dmp windows.filescan | grep "ChromeSetup"
```
Extracted the file using the virtual address:
```bash
vol -f memory.dmp windows.dumpfiles --virtaddr 0xca82b85325a0
```
![ramnit_filescan.png](ramnit_filescan.png)
![ramnit_dump.png](ramnit_dump.png)

Generated hashes for VirusTotal submission:
```bash
sha256sum file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img
sha1sum file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img
```
![ramnit_sha1.png](ramnit_sha1.png)

VirusTotal results: **67/72 vendors flagged as malicious**
Compilation timestamp from VirusTotal Details: **2019-12-01 08:36:04 UTC** — indicating the malware predates the infection significantly, suggesting it is a known persistent threat.
![ramnit_vt_date.png](ramnit_vt_date.png)

---
### 4. C2 Infrastructure
VirusTotal Relations tab revealed the C2 domain:
**dnsnb8[.]net**
Contacted URLs followed the pattern: `http://ddos.dnsnb8.net:799/cj/k[1-5].rar` This is consistent with Ramnit's known behaviour of downloading additional payloads via RAR archives.
![ramnit_c2.png](ramnit_c2.png)

---

## IOCs 


| Type   | Value                                                            |
| ------ | ---------------------------------------------------------------- |
| File   | ChromeSetup.exe                                                  |
| IP     | 58.64.204.181                                                    |
| C2     | dnsnb8[.]net                                                     |
| SHA1   | 280c9d36039f9432433893dee6126d72b9112ad2                         |
| Path   | C:\Users\alex\Downloads\ChromeSetup.exe                          |
| SHA256 | 1ac890f5fa78c857de42a112983357b0892537b73223d7ec1e1f43f8fc6b7496 |
| MD5    | 11318cc3a3613fb679e25973a0a701fc                                 |

## Conclusion 

> Ramnit malware was deployed on the workstation disguised as a Chrome installer. Memory forensics confirmed active C2 communication to Hong Kong infrastructure and identified staged payload delivery via dnsnb8[.]net.


{% include flag.html question="What is the name of the process responsible for the suspicious activity?" answer="ChromeSetup.exe" %}

{% include answer.html question="What is the exact path of the executable for the malicious process?" answer="`C:\Users\alex\Downloads\ChromeSetup.exe`" %}

{% include flag.html question="Identifying network connections is crucial for understanding the malware's communication strategy. What IP address did the malware attempt to connect to?" answer="58.64.204.181" %}

{% include answer.html question="To determine the specific geographical origin of the attack, Which city is associated with the IP address the malware communicated with?" answer="hong kong" %}

{% include flag.html question="Hashes serve as unique identifiers for files, assisting in the detection of similar threats across different machines. What is the SHA1 hash of the malware executable?" answer="280c9d36039f9432433893dee6126d72b9112ad2" %}

{% include answer.html question="Examining the malware's development timeline can provide insights into its deployment. What is the compilation timestamp for the malware?" answer="2019-12-01 08:36" %}

{% include flag.html question="Identifying the domains associated with this malware is crucial for blocking future malicious communications and detecting any ongoing interactions with those domains within our network. Can you provide the domain connected to the malware?" answer="dnsnb8[.]net" %}

I successfully completed Ramnit Blue Team Lab at @CyberDefenders!
https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/ramnit/
 
#CyberDefenders #CyberSecurity #BlueYard #BlueTeam #InfoSec #SOC #SOCAnalyst #DFIR #CCD #CyberDefender
