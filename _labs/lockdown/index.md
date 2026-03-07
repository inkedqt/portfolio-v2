---
layout: lab
title: Lockdown
platform: CyberDefenders
difficulty: Easy
category: Network Forensics
tools: "[CyberChef, Wireshark, VirusTotal, Volatility]"
tactics: "[Execution, Persistence, Privilege Escalation, Defense Evasion, Discovery, Lateral Movement, Command and Control]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/lockdown/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/lockdown/
permalink: /blue-team/labs/lockdown/
summary: '"Reconstruct a multi-stage intrusion by analyzing network traffic, memory, and malware artifacts using Wireshark, Volatility, and VirusTotal, mapping findings to MITRE ATT&CK."'
art: https://cyberdefenders.org/media/terraform/Lockdown/terraform/Lockdown/lockdown.webp
---
## Scenario

TechNova Systems' SOC detected suspicious outbound traffic from a public-facing IIS server. Three artefacts were provided for analysis: a PCAP of the initial traffic, a full memory image of the server, and a malware sample recovered from disk. The goal was to reconstruct the full intrusion timeline and identify all attacker activity.

---

## Tooling

- Wireshark
- Volatility
- CyberChef
- VirusTotal

---

## Investigation

### Reconnaissance — Network Service Discovery

Conversation statistics in Wireshark immediately revealed a high volume of traffic originating from `10.0.2.4`, consistent with rapid-fire probing of the IIS host.
![lockdown_conversions.png](lockdown_conversions.png)

Filtering for SMB2 traffic from the attacker IP exposed targeted share enumeration:
```bash
ip.addr==10.0.2.4 && smb2
```

The attacker connected to two UNC paths on the IIS host:

- `\\10.0.2.15\IPC$`
- `\\10.0.2.15\Documents`

This activity maps to **MITRE T1046 — Network Service Discovery**.

---
### Initial Access — Webshell Upload via SMB

Continuing to follow attacker SMB2 traffic revealed an SMB2 Write Request uploading a malicious file to the Documents share:

- **Filename:** `shell.aspx`
- **Size:** 1,015,024 bytes

Show Image
![lockdown_smb_upload.png](lockdown_smb_upload.png)
The uploaded ASPX webshell provided the attacker with remote code execution on the IIS server.

---
### Execution — Reverse Shell

Reviewing conversation statistics confirmed outbound callback traffic from the IIS host to the attacker on an uncommon but firewall-friendly port:

- **Reverse shell port:** `4443`

The uploaded hex blob was extracted and decoded in CyberChef using **From Hex**, revealing an MZ PE executable — confirming the shell uploaded a binary payload. The reconstructed file MD5:

`94bf1fafad9c0b1b3570922da19ed68f4930ea855c54fbf844fe4d9be8d6a133`

VirusTotal identified the sample as **Trojan.Meterpreter/Shellcode**.

### Memory Forensics — Volatility Analysis

With the memory image acquired, Volatility was used to examine the running system state.

**System information:**

bash

```bash
vol -f memdump.mem windows.info
```

- **Kernel Base:** `0xf80079213000`

**Process tree analysis:**

bash

```bash
vol -f memdump.mem windows.pstree
```

![lockdown_pstree.png](lockdown_pstree.png)
The process tree revealed `w3wp.exe` (IIS worker process, PID 4332) spawning a suspicious child process — a clear indicator of webshell-driven execution.

**Command line enumeration:**

bash

```bash
vol -f memdump.mem windows.cmdline
```

This confirmed the persistence implant path:

`900 updatenow.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe"`

Dropping an executable into the Startup folder maps to **MITRE T1547 — Boot or Logon Autostart Execution**, ensuring the implant survives reboots.

---
### Malware Analysis — AgentTesla

Static analysis of `updatenow.exe` revealed the binary was packed with **UPX** to hinder analysis and evade signature-based detection.

Dynamic and threat intelligence analysis showed the malware beaconing to its C2 infrastructure:

- **C2 FQDN:** `cp8nl[.]hyperhost[.]ua`

VirusTotal open-source intelligence attributed the sample to the **AgentTesla** malware family — a well-known commodity RAT used for credential theft and keylogging.

![lockdown_family.png](lockdown_family.png)

## IOCs 

| Type               | Value                                                                      |
| ------------------ | -------------------------------------------------------------------------- |
| Attacker IP        | 10[.]0[.]2[.]4                                                             |
| IIS Host           | 10[.]0[.]2[.]15                                                            |
| Webshell           | shell.aspx                                                                 |
| Reverse Shell Port | 4443                                                                       |
| SHA256             | 94bf1fafad9c0b1b3570922da19ed68f4930ea855c54fbf844fe4d9be8d6a133           |
| Malware Family     | AgentTesla                                                                 |
| C2 FQDN            | cp8nl[.]hyperhost[.]ua                                                     |
| Persistence Path   | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe |
| Packer             | UPX                                                                        |
| Kernel Base        | 0xf80079213000                                                             |
## Conclusion

> The attacker conducted network service discovery against a public-facing IIS server, then used SMB to upload a Meterpreter ASPX webshell. The webshell provided code execution via the IIS worker process w3wp.exe, which was used to drop a UPX-packed AgentTesla implant into the Startup folder for persistence. Memory forensics confirmed the execution chain and identified the full on-disk path of the persistence mechanism. The malware beaconed to a Ukrainian hosting provider for C2 communications.

---

## References

- [MITRE T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE T1547 — Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [MITRE T1027.002 — Software Packing](https://attack.mitre.org/techniques/T1027/002/)
- [LOLBAS — w3wp.exe](https://lolbas-project.github.io/lolbas/OtherMSBinaries/W3wp/)
- [CyberDefenders — Lockdown Lab](https://cyberdefenders.org/blueteam-ctf-challenges/lockdown/)

{% include flag.html question="After flooding the IIS host with rapid-fire probes, the attacker reveals their origin. Which IP address generated this reconnaissance traffic?" answer="10.0.2.4" %}

{% include answer.html question="Zeroing in on a single open service to gain a foothold, the attacker carries out targeted enumeration. Which MITRE ATT&CK technique ID covers this activity?" answer="T1046" %}

{% include flag.html question="While reviewing the SMB traffic, you observe two consecutive Tree Connect requests that expose the first shares the intruder probes on the IIS host. Which two full UNC paths are accessed?" answer="\\10.0.2.15\Documents, \\10.0.2.15\IPC$" %}

{% include answer.html question="Inside the share, the attacker plants a web-accessible payload that will grant remote code execution. What is the filename of the malicious file they uploaded, and what byte length is specified in the corresponding SMB2 Write Request?" answer="shell.aspx, 1015024" %}

{% include flag.html question="The newly planted shell calls back to the attacker over an uncommon but firewall-friendly port. Which listening port did the attacker use for the reverse shell?" answer="4443" %}

{% include answer.html question="Your memory snapshot captures the system’s kernel in situ, providing vital context for the breach. What is the kernel base address in the dump?" answer="0xf80079213000" %}

{% include flag.html question="A trusted service launches an unfamiliar executable residing outside the usual IIS stack, signalling a persistence implant. What is the final full on-disk path of that executable, and which MITRE ATT&CK persistence technique ID corresponds to this behaviour?" answer="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe, T1547" %}

{% include answer.html question="The reverse shell’s outbound traffic is handled by a built-in Windows process that also spawns the implanted executable. What is the name of this process, and what PID does it run under?" answer="w3wp.exe, 4332" %}

{% include flag.html question="Static inspection reveals the binary has been packed to hinder analysis. Which packer was used to obfuscate it?" answer="UPX" %}

{% include answer.html question="Threat-intel analysis shows the malware beaconing to its command-and-control host. Which fully qualified domain name FQDN does it contact?" answer="cp8nl.hyperhost.ua" %}

{% include flag.html question="Open-source intel associates that hash with a well-known commodity RAT. To which malware family does the sample belong?" answer="" %}

