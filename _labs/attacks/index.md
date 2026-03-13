---
layout: lab
title: Attacks
platform: BTLO
difficulty: Easy
category: Incident Response
skill: Incident Response
tools: Event Viewer
tactics: Credential Access, Collection
proof: https://blueteamlabs.online/achievement/share/144656/154
challenge_url: https://www.youtube.com/watch?v=Ph_4qwzCcZA
permalink: /blue-team/labs/attacks/
summary: '"Test your knowledge of MITRE ATT&CK while investigating the logs from a compromised Windows host"'
art: https://blueteamlabs.online/storage/labs/87ce43ac64eac1038e48ef0c5f96b953cf2eace5.png
type:
points:
youtube:
---
## Overview

ATTACKS is a straightforward MITRE ATT&CK mapping lab built around a compromised Windows host. The scenario provides firewall logs, Windows Event Logs, and Sysmon telemetry, and tasks you with tracing the full attack chain from initial reconnaissance through to malware persistence. It's a solid exercise in correlating events across multiple log sources while mapping each action to the ATT&CK framework.

Tools used: Windows Event Viewer, Sysmon, Firewall Logs, Netstat, GitHub OSINT.

---

## Reconnaissance

### Active Scanning

The firewall log on the Desktop is the starting point. Reviewing it reveals the source IP `192[.]168[.]1[.]33` systematically probing ports on the target — classic active scanning behaviour.

MITRE: **T1595 — Active Scanning**

To confirm what ports are exposed on the endpoint from the victim's perspective, the command `netstat -an` lists all listening ports and active connections without resolving hostnames — a quick way to see the attack surface.

Reviewing the output reveals **SSH on port 22** is open, which becomes the attacker's entry point.

---
## Initial Access & Credential Access

### Brute Force SSH

With SSH exposed, the attacker targeted the **Administrator** account with a brute force attack. Filtering the Windows Security logs reveals repeated failed logon attempts followed by a successful authentication at:
![attacks_ssh_bruteforce.png](attacks_ssh_bruteforce.png)
**11/18/2022 5:14:08 PM**

The credential access technique is **T1110 — Brute Force**. Once the password was obtained, the attacker authenticated using those credentials, making the initial access technique **T1078 — Valid Accounts**. The distinction matters: T1110 describes how the credentials were obtained, T1078 describes how they were used to gain entry.

---

## Persistence — Account Creation

### New Local Account

Filtering Security Event logs for **Event ID 4720** (user account created) reveals the attacker created a new local account: **sysadmin**.

MITRE: **T1136 — Create Account**

Following that, **Event ID 4732** (user added to local group) confirms the sysadmin account was added to the Administrators group at:

**11/18/2022 5:15:33 PM**

---

## Impact — Account Deletion

### Deleting User drb

Filtering for **Event ID 4726** (user account deleted) shows the attacker deleted the account **drb** — likely to remove a legitimate user and limit recovery options or cover tracks.

MITRE: **T1531 — Account Access Removal**

The relevant MITRE detection data source for account-based activity is **DS0002 — User Account**.

---

## Execution — Malware Deployment

### Keylogger Extraction

Filtering Sysmon for **Event ID 1** (Process Create) and looking for 7-Zip activity reveals the command:

`7z e keylogger.rar`
![attacks_keylogger.png](attacks_keylogger.png)
The compressed file **keylogger.rar** was extracted using 7-Zip, producing two files dropped into `C:\Users\Administrator\AppData\Roaming\WPDNSE\`:

- `rundell33.exe` — note the triple e, masquerading as the legitimate rundll33
- `svchost.exe` — masquerading as the Windows system process

Sysmon **Event ID 11** (File Created) confirms both file creation events in that path.

The keylogger maps to **T1056 — Input Capture**, specifically sub-technique **T1056.001 — Keylogging**.

### atapi.sys

Also visible in the Event ID 11 entries is the creation of **atapi.sys** — a driver file dropped by the malware, mimicking the legitimate Windows ATAPI storage driver name.
![attacks_atapi.png](attacks_atapi.png)

---
## Defense Evasion — Defender Tampering

### Disabling WdNisDrv

Sysmon **Event ID 13** (Registry Value Set) at **11/18/2022 5:24:18 PM** reveals a modification to:

`HKLM\System\CurrentControlSet\Services\WdNisDrv\Start`

The value was set to `DWORD 0x00000003` (Manual), effectively disabling automatic startup of the **Windows Defender Network Inspection Service** — a targeted defense evasion move to reduce detection capability.

MITRE: **T1562.001 — Impair Defenses: Disable or Modify Tools**
![attacks_event13.png](attacks_event13.png)

---
## Persistence — Registry Run Keys

### Malware Autostart Entries

Continuing through the Event ID 13 entries reveals two registry values written to the `CurrentVersion\Run` key, establishing persistence across reboots. In order of creation:

1. **Windows SCR Manager** — pointing to `rundell33.exe` in WPDNSE
2. **Windows Atapi x86_64 Driver** — pointing to `svchost.exe` in WPDNSE

Both use legitimate-sounding names to blend in during casual registry inspection.

MITRE: **T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**
![attacks_reg.png](attacks_reg.png)

---
## Malware Attribution

Searching GitHub for the keylogger's characteristics leads to the repository:

`hxxps[://]github[.]com/ajayrandhawa/Keylogger`

The malware author's GitHub username is **ajayrandhawa**.

---

## IOCs

|Type|Value|
|---|---|
|Attacker IP|`192[.]168[.]1[.]33`|
|Malicious Archive|`keylogger.rar`|
|Dropped Executable|`rundell33.exe`|
|Dropped Executable|`svchost.exe` (fake)|
|Dropped Driver|`atapi.sys`|
|Drop Path|`C:\Users\Administrator\AppData\Roaming\WPDNSE\`|
|C2 / Attribution|`hxxps[://]github[.]com/ajayrandhawa/Keylogger`|

---

## MITRE ATT&CK

|Technique|ID|Tactic|
|---|---|---|
|Active Scanning|T1595|Reconnaissance|
|Brute Force|T1110|Credential Access|
|Valid Accounts|T1078|Initial Access|
|Create Account|T1136|Persistence|
|Account Access Removal|T1531|Impact|
|Input Capture: Keylogging|T1056.001|Collection|
|Masquerading|T1036|Defense Evasion|
|Impair Defenses: Disable or Modify Tools|T1562.001|Defense Evasion|
|Boot or Logon Autostart Execution: Registry Run Keys|T1547.001|Persistence|


---

{% include flag.html question="sing the firewall log image on the Desktop, what MITRE ATT&CK reconnaissance technique was used?" answer="active scanning, T1595 " %}

{% include answer.html question="We can see from the firewall image in Q1 that the IP address 192.168.1.33 checked to see what ports were listening on the other system. What command can we use in CMD to check which ports are listening on the endpoint?" answer="netstat -an" %}

{% include flag.html question="here are ports listening on the endpoint that would enable remote connection, this could potentially make the system vulnerable to intrusion. It's time to check the logs! Which protocol and port have been used by the attacker to gain access to the system?" answer="ssh, 22" %}

{% include answer.html question="What user account has been accessed by the attacker?" answer="administrator" %}

{% include flag.html question="What time did the attacker first gain access to this account?" answer="11/18/2022 5:14:08 PM" %}

{% include answer.html question="What MITRE ATT&CK initial access technique did the attacker use?" answer="Valid Accounts, T1078" %}

{% include flag.html question="What MITRE ATT&CK credential access technique did the attacker use to gain access to the endpoint?" answer="Brute Force, T1110" %}

{% include answer.html question="What account did the attacker create after gaining access?" answer="sysadmin" %}

{% include flag.html question="What MITRE ATT&CK persistence technique is this?" answer="Create Account, T1136" %}

{% include answer.html question="What time did the attacker add his created account to the Administrators group?" answer="11/18/2022 5:15:33 PM" %}

{% include flag.html question="What account did the attacker delete?" answer="drb" %}

{% include answer.html question="What MITRE ATT&CK impact technique is this?" answer="Account Access Removal, T1531" %}

{% include flag.html question="What MITRE ATT&CK detection ID applies to the attacker's actions here?" answer="DS0002" %}

{% include answer.html question="What's the name of the compressed file that was extracted?" answer="keylogger.rar" %}

{% include flag.html question="What MITRE ATT&CK collection technique would this file use?" answer="Input Capture, T1056" %}

{% include answer.html question="What sub-technique of the previous answer would this file use?" answer="Keylogging, T1056.001" %}

{% include flag.html question="What two files were created from this file extraction" answer="rundell33.exe, svchost.exe" %}

{% include answer.html question="What's the file path of the folder these two files created?" answer="c:\users\administrator\appdata\roaming\WPDNSE" %}

{% include flag.html question="What's the name of the .sys file created by the malware?" answer="atapi.sys" %}

{% include answer.html question="What time was a registry value first set by the malware?" answer="11/18/2022 5:24:18 PM" %}

{% include flag.html question="What two registry values has the malware created" answer="Windows Atapi x86_64 Driver, Windows SCR Manager" %}

{% include answer.html question="What MITRE ATT&CK persistence technique has the malware used?" answer="Boot or Logon Autostart Execution, T1547.001" %}

{% include flag.html question="What sub-technique of the previous answer has the malware used?" answer="Registry Run Keys / Startup Folder, T1547.001" %}

{% include answer.html question="What's the name of the user on GitHub who created this malware?" answer="ajayrandhawa" %}
