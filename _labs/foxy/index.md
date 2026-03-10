---
layout: lab
title: Foxy
platform: BTLO
difficulty: Easy
category: Threat Intelligence
skill: Threat Intelligence
tools: "[Linux CLI, Gnumeric, Text Editor, OSINT]"
tactics: "[T1204.002, T1566]"
proof: https://blueteamlabs.online/achievement/share/144656/116
challenge_url: https://blueteamlabs.online/home/investigation/foxy-45e69136ae
permalink: /blue-team/labs/foxy/
summary: '"As an Intelligence Analyst you are tasked with assisting the SOC Analysts with their investigations, providing additional context and information."'
art: https://blueteamlabs.online/storage/labs/b25ff6c8e7781cbcd53b45612feb0f29c2ba9e39.png
---
## Overview

Foxy is a threat intelligence lab centred around analysing ThreatFox CSV export files using command-line tooling. The investigation covers a range of malware families including CobaltStrike, IRATA Android RAT, AdWind/JAR RAT, Dridex, and Log4Shell exploitation. The workflow involves grep, wc, and Gnumeric to interrogate large threat feed datasets, cross-referenced against external sources including MalwareBazaar, Joe Sandbox, and Twitter/X threat researcher posts.

---

## Investigation

### CobaltStrike Beacon — dot.gif C2

The SOC flagged outbound connections from three internal hosts to `hxxp://45[.]63[.]126[.]199/dot[.]gif`. Grepping the ThreatFox exports confirmed the indicator:

bash

```zsh
cat * | grep -i 45.63.126.199/dot.gif
```

The result returned a high-confidence (100) ThreatFox entry tagging the URL as a CobaltStrike botnet C2, with aliases including BEACON, Agentemis, and cobeacon. This is a classic CobaltStrike staging pattern — a benign-looking GIF endpoint masking C2 traffic.

To determine the full scope of dot.gif usage across all export files:

bash

```zsh
cat * | grep -i dot.gif | wc
```

**Result: 568 URLs** referencing the dot.gif endpoint across all exports.

---

### IRATA Android RAT — Executive Device

A SHA256 hash detected and quarantined on an executive's Android device was submitted for analysis:

`6461851c092d0074150e4e56a146108ae82130c22580fb444c1444e7d936e0b5`
![malware_irata.png](malware_irata.png)
MalwareBazaar identified the sample as **IRATA** — an Android banking trojan/RAT. Following the reference link to a Twitter/X post from a threat researcher provided additional context on the infrastructure:
![foxy_x.png](foxy_x.png)

|Indicator|Value|
|---|---|
|Threat Name|IRATA|
|C2 Domain|`uklivemy[.]gq`|
|C2 IP|`20[.]238[.]64[.]240`|
|Registrar|Freenom|

The Joe Sandbox analysis at `hxxps://www[.]joesandbox[.]com/analysis/1319345/1/html` was reviewed for MITRE ATT&CK Collection techniques. The following five techniques were identified under the Collection tactic in alphabetical order:

- Access Contact List
- Access Stored Application Data
- Capture SMS Messages
- Location Tracking
- Network Information Discovery

This indicates IRATA has significant data harvesting capability targeting mobile devices — contacts, SMS, location, stored app data, and network enumeration. High risk to an executive device with access to sensitive communications.

---

### AdWind JAR RAT — 192.236.198.236

A junior analyst flagged outbound connections to `192[.]236[.]198[.]236` without further investigation. Grepping the ThreatFox IP:port exports:


```zsh
cat * | grep -i "192.236.198.236"
```

The IP was identified as a botnet C2 for **AdWind** (also known as AlienSpy, JSocket, Frutas, UNRECOM, JBifrost, Sockrat) — a Java-based cross-platform RAT. Two ports were in use:

- Port **1505**
- Port **1506**

The reference link pointed to a Twitter/X post from `@ddash_ct` providing the C2 domain: `ianticrish[.]tk`
![foxy_adwind.png](foxy_adwind.png)
The likely delivery method into the organisation was **Phishing (T1566)**. Further investigation of the reference material identified the weaponised Word document used for delivery:

**Filename:** `08.2022 pazartesi sipari#U015fler.docx`

This document dropped the following JAR payload:

**JAR:** `NMUWYTGOKCTUFSVCHRSLKJYOWPRFSYUECNLHFLTBLFKVTIJJMQ.jar`

---

### Discord CDN Abuse — Dridex Distribution

Discord's CDN has been observed being abused for malware hosting and distribution. The relevant CDN base URL is:

`hxxps://cdn[.]discordapp[.]com/attachments`

Counting references across all export files:

bash

```bash
cat * | grep -c "https://cdn.discordapp.com/"
```

**Result: 565 rows** referencing the Discord CDN. The malware family being widely distributed via this infrastructure is **Dridex** — a prolific banking trojan.

---

### High-Confidence Blocking — full_urls.csv

When evaluating indicators for proactive blocking on a web proxy, confidence rating is critical to avoid blocking legitimate traffic. Filtering full_urls.csv for confidence rating of 100:

bash

```zsh
cat full_urls.csv | grep -c '"100",'
```

**Result: 39,993 rows** with a confidence rating of 100 — safe candidates for web proxy blocking.

---

### Log4Shell Exploitation — CVE-2021-44228

An analyst reported suspicious activity from an IP using source port 8001. Filtering `full_ip-port.csv` in Gnumeric for `malware_printable = Unknown malware` and port 8001 identified:

**IP:** `107[.]172[.]214[.]23`
![foxy_x_cve.png](foxy_x_cve.png)
The reference link pointed to a Twitter/X post from `@bad_packets` confirming the IP was attempting to exploit **CVE-2021-44228** — better known as **Log4Shell**. A critical unauthenticated RCE vulnerability in Apache Log4j reported in November 2021, weaponised almost immediately in the wild via rogue LDAP callbacks.

---

## IOCs

|Type|Value|
|---|---|
|URL|`hxxp://45[.]63[.]126[.]199/dot[.]gif`|
|IP|`45[.]63[.]126[.]199`|
|SHA256|`6461851c092d0074150e4e56a146108ae82130c22580fb444c1444e7d936e0b5`|
|Domain|`uklivemy[.]gq`|
|IP|`20[.]238[.]64[.]240`|
|IP:Port|`192[.]236[.]198[.]236:1505`|
|IP:Port|`192[.]236[.]198[.]236:1506`|
|Domain|`ianticrish[.]tk`|
|URL|`hxxps://cdn[.]discordapp[.]com/attachments`|
|IP|`107[.]172[.]214[.]23`|
|CVE|CVE-2021-44228|

---

## MITRE ATT&CK

|Technique|ID|
|---|---|
|Phishing|T1566|
|Ingress Tool Transfer|T1105|
|Command and Scripting Interpreter|T1059|
|Collection — Mobile (Access Contact List, Capture SMS, Location Tracking)|Various|
|Exploit Public-Facing Application (Log4Shell)|T1190|

---

## Lessons Learned

ThreatFox export analysis is a practical skill for proactive threat hunting and indicator enrichment. Grep and wc are sufficient for large dataset interrogation at L1/L2 level — no complex tooling required. Cross-referencing ThreatFox entries with Twitter/X threat researcher posts and sandbox reports (Joe Sandbox, MalwareBazaar) is standard enrichment workflow. Discord CDN abuse for payload delivery is well-documented and worth implementing as a detection rule. High-confidence (100) ThreatFox indicators should be fed directly into proxy blocklists as part of a proactive threat intel pipeline.


---

{% include flag.html question="The SOC recently observed network connections from 3 internal hosts towards hxxp://45.63.126[.]199/dot.gif. What is this activity likely related to?" answer="CobaltStrike" %} 

{% include answer.html question="How many URLs are using the same endpoint 'dot.gif', across all export files?" answer="568" %} 

{% include flag.html question="The SHA256 hash of a file was detected and quarantined on one of the Executives old android phones. We are trying to work out what this file does so we can take next steps. The hash value is 6461851c092d0074150e4e56a146108ae82130c22580fb444c1444e7d936e0b5. Is this file associated with malware? If so, what is the malware name?" answer="irata" %} 

{% include answer.html question="Investigate the reference link for this SHA256 hash value. Submit the threat name (acronym only), the C2 domain, IP, and the domain registrar." answer="IRATA, uklivemy[.]gq, 20.238.64.240, freenom" %}

{% include flag.html question="Visit https://www.joesandbox.com/analysis/1319345/1/html. Investigate the MITRE ATT&CK Matrix to understand the Collection activities this file can take, and what the potential impact is to the Executives work mobile phone. Submit the 5 Technique names in alphabetical order." answer="Access Contact List, Access Stored Application Data, Capture SMS Messages, Location Tracking, Network Information Discovery" %}

{% include answer.html question="A junior analyst was handling an event that involved outbound connections to a private address and didn't perform any further analysis on the IP. What are the two ports used by the IP 192.236.198.236?" answer="1505, 1506" %} 

{% include flag.html question="Use the reference to help you further research the IP. What is the C2 domain?" answer="ianticrish.tk" %} 

{% include answer.html question="What is the likely delivery method into our organization? Provide the Technique name and Technique ID from ATT&CK." answer="Phishing, T1566" %}

{% include flag.html question="Investigate further and try to find the name of the weaponized Word document, so we can use our EDR to check if it is present anywhere else within the organization." answer="08.2022 pazartesi sipari#U015fler.docx" %} 

{% include answer.html question="What is the name of the .JAR file dropped by the Word document?" answer="NMUWYTGOKCTUFSVCHRSLKJYOWPRFSYUECNLHFLTBLFKVTIJJMQ.jar" %} 

{% include flag.html question="Executives have expressed concern about allowing employees to visit Discord on the corporate network because of online reports that it can be used for malware delivery and data exfiltration. Investigate how Discord can be abused for malicious file storage/distribution! What is the URL of the Discord CDN, ending with /attachments" answer="https://cdn.discordapp.com/attachments" %}

{% include answer.html question="Looking at all export files, how many rows reference this URL?" answer="565" %} 

{% include flag.html question="Based on this information, what is the name of the malware family that is being widely distributed via Discord?" answer="dridex" %} 

{% include answer.html question="We can proactively use indicators from threat feeds for detection, or for prevention via blocking. When it comes to blocking indicators, it is crucial that they are from a reputable source and have a high level of confidence to prevent blocking legitimate entities. How many rows in the full_urls.csv have a confidence rating of 100, and would likely be safe to block on the web proxy?" answer="39993" %} 

{% include flag.html question="An analyst has reported activity coming from an IP address using source port 8001, but they don't understand what this IP is trying to achieve. Looking at full_ip-port.csv in Gnumeric, filter on malware_printable = Unknown malware, and find an IP that is using port 8001. What is the IP address value?" answer="107.172.214.23" %} 

{% include answer.html question="Investigating the reference material, what is the CVE ID of the vulnerability that this IP has been trying to exploit? And what is the industry nickname for this vulnerability?" answer="CVE-2021-44228, Log4Shell" %}