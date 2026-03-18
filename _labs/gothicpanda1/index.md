---
layout: lab
title: Gothic Panda 1
platform: BTLO
difficulty: Medium
category: Threat Intelligence
skill: Threat Intelligence
tools: "[MITRE ATT&CK Navigator, OSINT ,Google Dorks]"
tactics:
mitre:
proof: https://blueteamlabs.online/achievement/share/144656/234
challenge_url: https://blueteamlabs.online/home/investigation/gothic-panda-1-6350a04e1c
permalink: /blue-team/labs/gothicpanda1/
summary: '"CHANGE ME"'
art: https://blueteamlabs.online/storage/labs/7bd52a566c4bdadc55e8da4032e1f51fb7164a69.png
type:
points:
youtube:
locked: tate
---
## Overview

APT3 (Gothic Panda) is a Chinese state-sponsored threat group attributed to the Ministry of State Security. This BTLO Threat Intelligence lab tasks the analyst with building a comprehensive Threat Actor Report covering APT3's known TTPs, operations, CVEs, network IOCs, and MITRE ATT&CK mappings. 25 questions spanning OSINT research, MITRE Navigator, VirusTotal, and primary threat intel sources. Genuinely one of the harder intel labs on the platform — Q5 alone took three hours.

---
## Threat Actor Report
As part of this lab, a full Threat Actor Report was completed using the SBT CTI Team template, covering executive summary, timeline of activity, MITRE ATT&CK table, IOCs, and CVE analysis.

![GothicPanda](GothicPanda-APT3-ThreatActorReport-Completed.docx)
## Investigation

### Threat Actor Background

APT3 became active in **2007** and was first formally identified by the threat intelligence community in **2014** via FireEye reporting. The group primarily targeted U.S. sectors including **Aerospace, Defense, High Technology, Telecommunications, and Transportation** before shifting focus to political organisations in **Hong Kong** as part of the Buckeye campaign.

Attribution rests on Chinese-language artifacts in tooling, operational timing aligned with China Standard Time, and target selection mapping to MSS strategic priorities.

---

### Known Operations

**Operation Clandestine Fox** (April–May 2014) leveraged a zero-day in **Internet Explorer**, exploiting a use-after-free vulnerability (CVE-2014-1776) affecting IE versions **6–11** via drive-by download.

**Operation Double Tap** (November–December 2014) was a spear-phishing campaign exploiting **CVE-2014-6332** — the Windows OLE Automation array vulnerability nicknamed **"Unicorn"** by IBM researcher Robert Freeman. The bug is a **Use-After-Free** enabling **RCE**. Double Tap also leveraged **CVE-2014-4113** (Windows kernel privilege escalation).

**Operation Clandestine Wolf** (June–July 2015) exploited a **heap-based buffer overflow** in **Adobe Flash Player** (**CVE-2015-3113**), delivered via spear-phishing.

---

### Hacking Team Disclosure

Following the July 2015 Hacking Team leak, APT3 rapidly weaponised **CVE-2015-5119** (Adobe Flash zero-day). Subsequently, **CVE-2015-5122** was used to attack **Japan**, with the **Kaba** backdoor (a PlugX variant commonly used by Chinese APTs) deployed as the post-exploitation implant.

---

### MITRE ATT&CK TTPs

**Execution:** The APT3 downloader verifies SYSTEM privileges using `cmd.exe /C whoami`. Persistence is established via **Scheduled Tasks** with task name **mysc**: `schtasks /create /tn "mysc" /tr C:\Users\Public\test.exe /sc ONLOGON /ru "System"`.

**Persistence:** APT3 places **scripts** in the **Startup** folder (T1547.001). They also replace `sethc.exe` (Sticky Keys binary) for persistence — **Event Triggered Execution: Accessibility Features** (T1546.008).

**Defense Evasion:** **MSBuild.exe** is used as a LOLBin to proxy code execution — **Trusted Developer Utilities Proxy Execution** (T1127.001). UAC is bypassed via **Bypass User Account Control** (T1548.002).

**Credential Access:** A custom tool injects into `lsass.exe` and triggers with the argument **`dig`** to dump credentials (T1003.001).

**Lateral Movement:** Files are copied over **SMB/Windows Admin Shares** (T1021.002). **RDP** is also used to interact with compromised systems (T1021.001).

---

### Malware & Tools

|Tool|Type|MITRE ID|Notes|
|---|---|---|---|
|PlugX|RAT|S0013|Primary RAT — also known as Kaba|
|SHOTPUT|Backdoor|—|Custom backdoor, aka CookieCutter|
|COOKIECUTTER|Loader|—|Browser exploitation and payload delivery|
|SOGU|RAT|—|Used for sustained access and exfiltration|

**Downloader binary (Operation Double Tap):** MD5: `5c08957f05377004376e6a622406f9aa` Compiled: `2014-11-18 10:49:23Z`

---

### Network IOCs

Domain first observed **November 17, 2014** in Operation Double Tap: `www[.]securitywap[.]com` — last seen `2014-11-20` — IP `192[.]184[.]60[.]229`

---

## IOCs

| Type   | Value                            |
| ------ | -------------------------------- |
| Domain | www[.]securitywap[.]com          |
| Domain | inform[.]bedircati[.]com         |
| Domain | pn[.]lamb-site[.]com             |
| Domain | walterclean[.]com                |
| Domain | join[.]playboysplus[.]com        |
| Domain | www[.]apple-net[.]com            |
| Domain | www[.]mmfhlele[.]com             |
| Domain | www[.]olk4[.]com                 |
| Domain | update[.]olk4[.]com              |
| Domain | infosecvn[.]com                  |
| Domain | www[.]freesmadav[.]com           |
| Domain | update[.]freesmadav[.]com        |
| IP     | 192[.]184[.]60[.]229             |
| IP     | 104[.]151[.]248[.]173            |
| IP     | 154[.]223[.]150[.]105            |
| IP     | 43[.]251[.]182[.]114             |
| IP     | 185[.]239[.]226[.]61             |
| IP     | 167[.]88[.]180[.]132             |
| IP     | 45[.]251[.]240[.]55              |
| MD5    | 5c08957f05377004376e6a622406f9aa |
| CVE    | CVE-2014-6332                    |
| CVE    | CVE-2014-4113                    |
| CVE    | CVE-2014-1776                    |
| CVE    | CVE-2015-3113                    |
| CVE    | CVE-2015-5119                    |
| CVE    | CVE-2015-5122                    |
| CVE    | CVE-2017-0143                    |
| CVE    | CVE-2019-0703                    |

---

<div class="qa-item"> <div class="qa-question-text">Which country in Southeast Asia our Threat Actor is more interested in targeting?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Hong Kong</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Advanced Persistent Threats (APTs) are known to do whatever it takes to fulfill their mission. There are three known operations associated with them. Specifically, in one of these operations, which multimedia software was exploited? Additionally, in what month and year did this campaign occur?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Operation Clandestine Wolf, Adobe Flash Player, 06-2015</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Following this operation, what type of vulnerability was exploited in this multimedia software? Additionally, what CVE is associated with it?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Heap-based buffer overflow, CVE-2015-3113</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding their other operation, it is reported that they discovered an exploit in a popular native Windows software. What type of exploit did they use, and which software was targeted?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Zero-day, Internet Explorer</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding this data, what type of bug was exploited in this popular software? What is its nickname? Which CVE is associated with it? What type of attack allows the attacker to execute code to the compromised host?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Use-After-Free, Unicorn, CVE-2014-6332, RCE</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What are the U.S. sectors that they were known to target before shifting to political campaigns? Arrange your answer in the following order.</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Aerospace, Defense, High Technology, Telecommunications, Transportation</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">APT3, also known as Gothic Panda, was first identified by the threat intelligence community in which year? Additionally, in what year did this sophisticated threat group become active?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">2007, 2014</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding the vulnerabilities in the popular native Windows browser, which range of versions is affected?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">6-11</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">In Operation Double Tap, our threat actor leveraged multiple exploits. What are these exploits?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">CVE-2014-6332, CVE-2014-4113</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">At this point, we will be using MITRE ATT&CK Navigator. For APT3's execution tactics, which Windows command does their downloader use to verify it is running with the elevated privileges of “System?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">cmd.exe /C whoami</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding APT3's execution tactics, which Windows component was used to establish persistence on the compromised host? Additionally, what is the task name associated with the command that APT3 uses during this phase?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Scheduled Tasks, mysc</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding APT3's persistence tactics, which known folder does APT3 use to establish persistence, and what type of file do they place in this location?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Startup, scripts</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding APT3's persistence tactics, which known binary are they known to replace to achieve persistence? Which technique does this action belong to</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">sethc.exe, Event Triggered Execution: Accessibility Features</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">APT3 Defense Evasion Tactics, What Living-off-the-land binary do they use to evade detection? What technique is this action under? Hint: This binary is a build tool commonly associated with Visual Studio. It allows adversaries to execute arbitrary code under the guise of legitimate development processes.</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">MSBuild.exe, Trusted Developer Utilities Proxy Execution</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding APT3's defense evasion tactics, what bypass mechanism do they use to elevate privileges on the system? Under which sub-technique does this action fall?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">UAC, Bypass User Account Control</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding APT3's credential access tactics, what argument does their tool use to dump credentials by injecting itself into lsass.exe?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">dig</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">APT3 Lateral Movement Tactics, What technique and sub-technique do they use to copy files over Windows systems?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Remote Services, SMB/Windows Admin Shares</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding APT3's lateral movement tactics, which other protocol do they use to interact with compromised systems?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">rdp</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Regarding APT3's persistence tactics, what is the MD5 hash value of the binary that acts as a downloader during their operation? When was this binary compiled?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">5c08957f05377004376e6a622406f9aa, 2014-11-18 10:49:23Z</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What popular Remote Access Trojan tool is this APT3 known for using? and What MITRE Software ID does it represent?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">PlugX, S0013</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Network IOCs Threat Intelligence: APT3 is known to have used multiple domains for their campaign. One of these domains was first observed in the wild on November 17, 2014. What is this domain, when was it last seen, and what IP address was associated with it?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">www[.]securitywap[.]com, 2014-11-20, 192[.]184[.]60[.]229</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What vulnerability was exploited by APT3 and other threat actors following the disclosure of the Hacking Team's internal data?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">cVE-2015-5119</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Following APT3's espionage activities in East Asia, CVE-2015-5122 was used to attack which country? Additionally, what is the name of the malware backdoor typically used by Chinese APTs</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Japan, Kaba</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">APT3 is known to exploit a Windows SMB information disclosure vulnerability. Which CVE is associated with it?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">CVE-2019-0703</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">APT3 is known to exploit a Windows SMB remote code execution vulnerability. Which CVE is associated with it, and which version of SMB does this vulnerability affect?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">CVE-2017-0143, 1.0</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>
