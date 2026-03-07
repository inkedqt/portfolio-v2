---
layout: lab
title: Maranhao Lab
platform: CyberDefenders
difficulty: Easy
category: Endpoint Forensics
tools: "[FTK Imager]"
tactics: "[Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Collection]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/maranhao/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/maranhao/
permalink: /blue-team/labs/maranhao/
summary: "Investigate a trojanized game installer by analyzing browser history, logs, registry hives, and filesystem artifacts to map the full attack chain and extract IOCs."
art: https://cyberdefenders.org/media/terraform/Maranh%C3%A3o/terraform/Maranh%C3%A3o/maranhao.webp
---
## Scenario

A gaming enthusiast at GOAT Company downloaded what appeared to be a free mod launcher for a popular survival game. The archive contained a trojanized installer that silently dropped hidden files, established registry persistence, and began communicating with malicious infrastructure. The machine was isolated and a full disk image was provided for forensic analysis.

---

## Tooling

- FTK Imager
- VirusTotal

---

## Investigation

### Delivery — Trojanized Game Launcher

Browser history analysis revealed the download URL and timestamp of the initial compromise vector:

- **URL:** `hxxps[://]drive[.]google[.]com/file/d/1mIxhfZXmcUT2mbKNuahsRI4S_rzVUFKW/view`
- **Timestamp:** 2025-09-17 10:10
- **Filename:** `Fnafdoomlauncher.exe` (delivered as `fnafdoomlauncher.d7z`)

The archive was disguised as a legitimate FNAF Doom game launcher to trick the victim into executing it willingly.

VirusTotal confirmed the dropper binary as malicious:

- **SHA1:** `FCB94C06FA80CE277B47E545B3805AB38BB6ACF4`
![[maranhao_virus_total.png]]

---
### Execution — Silent Installation

The installer was executed with the `/VERYSILENT` flag to suppress all user-facing prompts during deployment, preventing the victim from observing any installation activity. This is a common abuse of legitimate NSIS/Inno Setup installer flags.

---

### Persistence — Registry Autorun

Event log analysis revealed the secondary payload was staged in a user-space directory masquerading as a legitimate Microsoft component:

`C:\Users\Levi\AppData\Local\Programs\Microsoft Updater\Updater.exe`

The payload was invoked with a victim-tagging UUID for C2 identification:

`C:\Users\Levi\AppData\Local\Programs\Microsoft Updater\updater.exe e90de8b2-eb79-4614-94f8-308f0f81573b`

A registry autorun key was created to ensure re-execution on every reboot, with the persistence entry timestamped at **2025-09-17 10:13** — just three minutes after initial delivery.

![[maranhao_eventlog.png]]
### Defense Evasion — File Hiding

Following payload deployment, the malware used a native Windows utility to conceal its artifacts at the filesystem level:

`attrib +h +s`

The `+h` flag marks files as hidden and `+s` marks them as system-protected, rendering them invisible to standard directory listings and basic user inspection. This maps to **MITRE T1564.001 — Hidden Files and Directories**.

---

### Discovery — WMI Reconnaissance & Sandbox Evasion

The malware performed extensive WMI-based host fingerprinting to profile the victim environment and determine whether it was running in a sandbox or analyst VM:

|Command|Purpose|
|---|---|
|`wmic os get Caption`|Identify Windows edition|
|`wmic cpu get Name`|Enumerate CPU model — detect sandbox/VM|
|`wmic path win32_VideoController get Name`|Identify GPU — detect low-resource VM|
|`wmic csproduct get UUID`|Generate stable hardware-based victim UUID|
|`wmic logicaldisk get Caption,FreeSpace,Size,Description /format:list`|Assess disk inventory for exfiltration feasibility|

The malware also retrieved a static Windows activation backup key from the registry:

`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\BackupProductKeyDefault`

---

### Credential Access — Browser Data Theft

To harvest browser credentials and session cookies, the malware forcibly terminated Microsoft Edge before injecting into the browser process:

`taskkill /F /IM msedge.exe`

A named pipe was then created to ferry stolen browser data between processes:

`ChromeDecryptIPC_e7e223c5-50d5-40ae-8513-64c9962789c2`

This maps to **MITRE T1539 — Steal Web Session Cookie** and **MITRE T1056 — Input Capture**.

---

### Command and Control

The malware beaconed to two C2 endpoints:

- **Geolocation enrichment:** `ip-api[.]com` (resolved to `208[.]95[.]112[.]1`)
- **Primary C2:** `api[.]maranhaogang[.]fun` (resolved via Cloudflare edge to `172[.]67[.]144[.]96` and `104[.]21[.]71[.]100`)

Using Cloudflare as a front for C2 infrastructure is a common technique to obscure the true origin of attacker-controlled servers and complicate blocking by IP.

![[maranhao_virustotal_ip.png]]
malicious ip ``208.95.112.1``


## IOCs 

| Type                  | Value                                                                        |
| --------------------- | ---------------------------------------------------------------------------- |
| Delivery URL          | hxxps[://]drive[.]google[.]com/file/d/1mIxhfZXmcUT2mbKNuahsRI4S_rzVUFKW/view |
| Dropper               | Fnafdoomlauncher.exe                                                         |
| SHA1                  | FCB94C06FA80CE277B47E545B3805AB38BB6ACF4                                     |
| Delivery Timestamp    | 2025-09-17 10:10                                                             |
| Persistence Timestamp | 2025-09-17 10:13                                                             |
| Secondary Payload     | C:\Users\Levi\AppData\Local\Programs\Microsoft Updater\Updater.exe           |
| Victim UUID           | e90de8b2-eb79-4614-94f8-308f0f81573b                                         |
| C2 Domain             | api[.]maranhaogang[.]fun                                                     |
| Geolocation API       | ip-api[.]com                                                                 |
| Malicious IP          | 208[.]95[.]112[.]1                                                           |
| Cloudflare IPs        | 172[.]67[.]144[.]96, 104[.]21[.]71[.]100                                     |
| Named Pipe            | ChromeDecryptIPC_e7e223c5-50d5-40ae-8513-64c9962789c2                        |

## Conclusion

> A trojanized game mod launcher delivered via Google Drive silently installed a secondary payload disguised as a Microsoft Updater component, establishing registry persistence within three minutes of delivery. The malware performed extensive WMI-based sandbox evasion before terminating browser processes to steal credentials via a named pipe. C2 communications were routed through Cloudflare's edge network to obscure attacker infrastructure, with geolocation enrichment via ip-api.com used to profile the victim's location.

---

## References

- [MITRE T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE T1547 — Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [MITRE T1564.001 — Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/)
- [MITRE T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [CyberDefenders — Maranhao Lab](https://cyberdefenders.org/blueteam-ctf-challenges/maranhao/)

{% include flag.html question="Analysts identified an external object that acted as the patient-zero delivery mechanism. Which remote resource URL initiated the chain of compromise by providing the archive disguised as a legitimate game utility?" answer="https://drive.usercontent.google.com/uc?id=1mIxhfZXmcUT2mbKNuahsRI4S_rzVUFKW&export=download" %}

{% include answer.html question="In reconstructing the timeline of compromise, which precise timestamp correlates to the adversary's delivery vector entering the victim environment as a ZIP file?" answer="2025-09-17 10:10" %}

{% include flag.html question="The ZIP archive's decompression exposed a loader binary that masqueraded as a legitimate launcher. What was the executable responsible for initializing this staged intrusion?" answer="Fnafdoomlauncher.exe" %}

{% include answer.html question="Adversaries often alter installer behavior to remain invisible during deployment. Which installer flag was leveraged to suppress user-facing prompts during execution of the trojanized setup?" answer="/VERYSILENT" %}

{% include flag.html question="Forensic correlation across endpoints requires file-level fingerprinting. What SHA1 hash uniquely represents the dropper binary that initiated further payload deployment?" answer="FCB94C06FA80CE277B47E545B3805AB38BB6ACF4" %}

{% include answer.html question="Post-installation, the secondary payload did not remain in temporary directories but was staged in a user-space program folder. Identify the exact directory path used for this execution pivot." answer="C:\Users\Levi\AppData\Local\Programs\Microsoft Updater\" %}

{% include flag.html question="During execution, the secondary component was invoked with a victim-tagging token for C2 identification. What globally unique string was provided as the argument?" answer="e90de8b2-eb79-4614-94f8-308f0f81573b" %}

{% include answer.html question="What was the complete file path of the binary embedded within the persistence mechanism to guarantee re-execution after reboot?" answer="C:\Users\Levi\AppData\Local\Programs\Microsoft Updater\Updater.exe" %}

{% include flag.html question="Temporal analysis of registry modifications showed the exact moment persistence was locked in. What is the date and time this key entry was created?" answer="2025-09-17 10:13" %}

{% include answer.html question="Post-installation, the adversary concealed its artifacts at the file-system level. Which native Windows utility and attribute combination was used to render both files and directories hidden and system-protected?" answer="attrib +h +s" %}

{% include flag.html question="Investigators observed the malware pulling system-level metadata that revealed the installed edition of Windows e.g., Microsoft Windows 10 Pro. This information could later be used by the attacker to determine compatibility with payload execution. Which exact query facilitated this operating system enumeration?" answer="wmic os get Caption" %}

{% include answer.html question="To assess whether the compromised system had sufficient processing resources or was running in a sandbox with emulated hardware, the malware issued a command to extract the processor's vendor and model string. What specific query enabled this reconnaissance?" answer="wmic cpu get Name" %}

{% include flag.html question="As part of its environment fingerprinting, the malware attempted to identify graphics hardware to help distinguish between a physical workstation and a low-resource virtual machine. Which query would return the video controller model?" answer="wmic path win32_VideoController get Name" %}

{% include answer.html question="The malware generated a unique victim identifier that would remain stable across reboots and reinstalls by retrieving a machine's hardware UUID. Which WMI command was responsible for collecting this globally unique identifier?" answer="wmic csproduct get UUID" %}

{% include flag.html question="During host triage, analysts identified a query that enumerated logical drives along with their free space and size. This could help an attacker determine whether the host was worth further exploitation e.g., data exfiltration feasibility. Which WMI command produced this disk inventory?" answer="wmic logicaldisk get Caption,FreeSpace,Size,Description /format:list" %}

{% include answer.html question="Unlike transient licensing tokens stored in tokens.dat, the malware pursued a static registry artifact used as a backup for Windows activation. Identify the precise registry entry (hive, key path, and value) that serves as a fallback product key reference." answer="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\BackupProductKeyDefault" %}

{% include flag.html question="Attackers often terminate browsers before attempting to steal session data, cookies, or inject a malicious browser extension. What is the command that was used to forcibly terminate all browser processes?" answer="taskkill  /F /IM msedge.exe" %}

{% include answer.html question="After injection, the malware established an interprocess channel for credential theft. What named pipe was created to ferry stolen browser data?" answer="ChromeDecryptIPC_e7e223c5-50d5-40ae-8513-64c9962789c2" %}

{% include flag.html question="To enrich host discovery with geolocation data, the malware beaconed to an external resolver. Which service endpoint did it query?" answer="ip-api.com" %}

{% include answer.html question="Blocking by domain is insufficient; analysts confirmed the resolved address of the geolocation API. Which single IP must be blacklisted?" answer="208.95.112.1" %}

{% include flag.html question="During network traffic analysis, the malware's outbound request did not resolve to a direct host but instead terminated at Cloudflare's edge network, a common tactic to conceal attacker infrastructure. Which two IP addresses were returned as part of this resolution?" answer="172.67.144.96, 104.21.71.100" %}

