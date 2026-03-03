---
layout: lab
title: PacketDetective
platform: CyberDefenders
difficulty: Easy
category: Network Forensics
tools: Wireshark
tactics: "[Execution, Defense Evasion, Command and Control]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/packetdetective/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/packetdetective/
permalink: /blue-team/labs/packetdetective/
summary: '"Analyze network traffic in PCAP files using Wireshark to extract IOCs and reconstruct attacker tactics like authentication and remote execution."'
art: https://cyberdefenders.org/media/terraform/PacketDetective/Packet_Detective.webp
---
# PacketDetective – Network Traffic Investigation
## Scenario
In September 2020, the SOC detected suspicious activity from a user device flagged by unusual SMB protocol usage. Initial analysis indicated a possible compromise of a privileged account and remote access tool usage. Three PCAP files were provided to trace the attacker's methods, persistence tactics, and goals. --- ## Tooling - Wireshark - Protocol Hierarchy Statistics - Conversations view

---

## Investigation Findings 
### PCAP 1 – SMB Authentication and Initial Access 
**Protocol Analysis** 
Using Wireshark's Protocol Hierarchy (`Statistics → Protocol Hierarchy`) revealed that SMB accounted for the majority of traffic with a total of **4406 bytes** transferred. 
![packet_smb.png](packet_smb.png)
**Compromised Account Identification** 
Filtering for NTLMSSP authentication: 
```bash 
ntlmssp.auth.username 
``` 
![private_smb_admin.png](private_smb_admin.png)
Revealed the `Administrator` account authenticating from `172.16.66.37` to `172.16.66.36` — confirming a privileged account was compromised. 
**Attacker IP:** `172.16.66.37` 
**Event Log Tampering** 
Searching packet details for `create` revealed an `eventlog` file access attempt. The attacker attempted to clear the Windows Event Log at: 
**2020-09-23 16:50 UTC** 
This is consistent with MITRE T1070.001 – Indicator Removal: Clear Windows Event Logs.

---

### PCAP 2 – RPC Lateral Movement via Named Pipe

**Named Pipe Identification**

Filtering with `smb && ip.addr == 172.16.66.37` and investigating RPC/DCOM traffic, expanding `OxidBindings → StringBindings` revealed a named pipe binding:

`\\01566S-WIN16-IR[\PIPE\atsvc]`

**atsvc** is the Windows Task Scheduler service — confirming the attacker used RPC over named pipes to interact with Task Scheduler for lateral movement (MITRE T1053.005).

**Communication Duration**

Using `Statistics → Conversations` and filtering `ip.addr == 172.16.66.1 && ip.addr == 172.16.66.36` the duration of communication between the two hosts was **11.7247 seconds**.
![packet_timetalk.png](packet_timetalk.png)
---
### PCAP 3 – Persistence and Remote Execution

**Secondary Username**

Filtering with 
```
ntlmssp.auth.username
```
revealed a second non-standard username: **3B\backdoor** — indicating the attacker established a backdoor account for persistence (MITRE T1136).
![packet_backdoor.png](packet_backdoor.png)
**Remote Execution via PsExec**

Filtering with 
```bash
smb2 && ip.addr == 172.16.66.1
```
 revealed the attacker writing `PSEXESVC.exe` to the target — confirming use of Sysinternals PsExec for remote process execution (MITRE T1569.002).

![packet_smb2.png](packet_smb2.png)
## IOCs 

| Type      | Value                |
| --------- | -------------------- |
| IP        | 172.16.66.1          |
| IP        | 172.16.66.37         |
| username  | administrator        |
| username  | backdoor             |
| file      | PSEXESVC.EXE         |
| timestamp | 2020-09-23 16:50 UTC |
|           |                      |
## Conclusion

> The attacker compromised the Administrator account via SMB, used RPC over named pipes to interact with the Task Scheduler service, attempted to clear event logs to cover their tracks, and established persistence through a backdoor account before executing remote processes via PsExec.

---

{% include flag.html question="The attacker’s activity showed extensive SMB protocol usage, indicating a potential pattern of significant data transfer or file access.  
What is the total number of bytes of the SMB protocol?" answer="4406" %}

{% include answer.html question="Authentication through SMB was a critical step in gaining access to the targeted system. Identifying the username used for this authentication will help determine if a privileged account was compromised.  
Which username was utilized for authentication via SMB?" answer="administrator" %}

{% include flag.html question="During the attack, the adversary accessed certain files. Identifying which files were accessed can reveal the attacker's intent.  
What is the name of the file that was opened by the attacker?" answer="eventlog" %}

{% include answer.html question="Clearing event logs is a common tactic to hide malicious actions and evade detection. Pinpointing the timestamp of this action is essential for building a timeline of the attacker’s behavior.  
What is the timestamp of the attempt to clear the event log? (24-hour UTC format)" answer="2020-09-23 16:50" %}

{% include flag.html question="The attacker used 'named pipes' for communication, suggesting they may have utilized Remote Procedure Calls (RPC) for lateral movement across the network. RPC allows one program to request services from another remotely, which could grant the attacker unauthorized access or control.  
What is the name of the service that communicated using this named pipe?" answer="atsvc" %}

{% include answer.html question="Measuring the duration of suspicious communication can reveal how long the attacker maintained unauthorized access, providing insights into the scope and persistence of the attack.  
What was the duration of communication between the identified addresses 172.16.66.1 and 172.16.66.36?" answer="11.7247 " %}

{% include flag.html question="The attacker used a non-standard username to set up requests, indicating an attempt to maintain covert access. Identifying this username is essential for understanding how persistence was established.  
Which username was used to set up these potentially suspicious requests?" answer="backdoor" %}

{% include answer.html question="The attacker leveraged a specific executable file to execute processes remotely on the compromised system. Recognizing this file name can assist in pinpointing the tools used in the attack.  
What is the name of the executable file utilized to execute processes remotely?" answer="PSEXESVC.exe" %}

I successfully completed PacketDetective Blue Team Lab at @CyberDefenders!
https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/packetdetective/
 
#CyberDefenders #CyberSecurity #BlueYard #BlueTeam #InfoSec #SOC #SOCAnalyst #DFIR #CCD #CyberDefender
