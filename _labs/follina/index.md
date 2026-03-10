---
layout: lab
title: Follina
platform: BTLO
difficulty: Easy
category: Threat Intelligence
skill: Threat Intelligence
tools: "[VirusTotal, Any.Run, OSINT]"
tactics: OSINT
proof: https://blueteamlabs.online/achievement/share/challenge/144656/43
challenge_url: https://blueteamlabs.online/home/challenge/follina-f1a3452f34
permalink: /blue-team/labs/follina/
summary: '"On a Friday evening when you were in a mood to celebrate your weekend, your team was alerted with a new RCE vulnerability actively being exploited."'
art: https://blueteamlabs.online/achievement/share/challenge/144656/43
type: challenge
points: "10"
---
## Overview

Follina (CVE-2022-30190) is a critical remote code execution vulnerability in Microsoft Support Diagnostic Tool (MSDT) that was actively exploited in the wild in mid-2022. Unlike traditional macro-based document attacks, Follina requires no macros — instead abusing the `ms-msdt` URI scheme via an external OLE relationship embedded in a Word document. The lab tasks an analyst with extracting IOCs and building detection logic from a malicious sample.

---

## Analysis

### Sample Identification

Initial triage of the sample via SHA1 hash:

bash

```zsh
sha1sum sample.doc
```

**SHA1:** `06727ffda60359236a8029e0b3e8a0fd11c23313`

VirusTotal identifies the file as an **Office Open XML Document** — a modern Word format (.docx) masquerading with a .doc extension. `olevba` confirms no VBA or XLM macros are present, which is expected — Follina's entire premise is macro-free exploitation.

---

### Extracting the Malicious Relationship

Since the file is OpenXML (a zip container), the external relationships can be extracted directly:

bash

````zsh
unzip -p sample/sample.doc word/_rels/document.xml.rels
```

The output reveals a suspicious external relationship embedded in **document.xml.rels**:
```
rId996 | oleObject | Target="https://www.xmlformats.com/office/word/2022/wordprocessingDrawing/RDF842l.html"
````

The attacker domain `xmlformats.com` is deliberately crafted to impersonate the legitimate Microsoft namespace `openxmlformats.org` — dropping "open" and the "s" from "formats". Buried in a wall of legitimate-looking XML relationships, this is easy to miss on casual inspection.

**Extracted URL:** `hxxps://www[.]xmlformats[.]com/office/word/2022/wordprocessingDrawing/RDF842l[.]html`

---

### Vulnerability Mechanics

When Word opens the document, it fetches the external HTML file via the oleObject relationship. The HTML contains an `ms-msdt` URI that invokes the Microsoft Support Diagnostic Tool with attacker-controlled parameters, achieving code execution without any macro interaction from the user.

A key detail from the HTML processing logic — files smaller than **4096 bytes** will not invoke the payload, a threshold check built into the exploit code.

Upon execution the sample attempts to kill **msdt.exe** if it is already running, likely to ensure a clean execution environment and avoid conflicts with an existing MSDT instance.

---

### Detection

Process-based detection using Windows Event ID 4688 (Process Creation) should monitor for:

|Field|Value|
|---|---|
|ParentProcessName|`winword.exe`|
|ProcessName|`msdt.exe`|

A KQL detection rule for Microsoft Sentinel targeting this behaviour is available at the [Microsoft Sentinel Queries repository](hxxps://github%5B.%5Dcom/le0li9ht/Microsoft-Sentinel-Queries/blob/main/Detect-Follina-Exploitation%5B.%5Dkql).

Seeing `winword.exe` spawn `msdt.exe` is highly anomalous — legitimate MSDT invocations do not originate from Word.

---

## IOCs

|Type|Value|
|---|---|
|SHA1|`06727ffda60359236a8029e0b3e8a0fd11c23313`|
|URL|`hxxps://www[.]xmlformats[.]com/office/word/2022/wordprocessingDrawing/RDF842l[.]html`|
|Domain|`xmlformats[.]com`|
|CVE|CVE-2022-30190|

---

## MITRE ATT&CK

|Technique|ID|
|---|---|
|Command and Scripting Interpreter|T1059|

---

## Lessons Learned

Follina demonstrated that macro security controls alone are insufficient — attackers can achieve RCE through document external relationships without any macro execution. The typosquatted domain `xmlformats.com` versus `openxmlformats.org` is a reminder that IOC extraction requires careful character-level inspection. Detection engineering for this class of exploit requires process lineage monitoring rather than content-based signatures — `winword.exe` spawning `msdt.exe` is the key indicator regardless of the payload delivered.

---

## References

- [HTB Blog — CVE-2022-30190 Follina Explained](hxxps://www%5B.%5Dhackthebox%5B.%5Dcom/blog/cve-2022-30190-follina-explained)
- [Microsoft Sentinel KQL Detection Rule](hxxps://github%5B.%5Dcom/le0li9ht/Microsoft-Sentinel-Queries/blob/main/Detect-Follina-Exploitation%5B.%5Dkql)
