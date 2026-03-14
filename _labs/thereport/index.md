---
layout: lab
title: The Report
platform: BTLO
difficulty: Easy
category: Threat Intel
skill: Threat Intelligence
tools: OSINT
tactics: Credential Access, Collection
proof: https://blueteamlabs.online/achievement/share/challenge/144656/42
challenge_url: https://blueteamlabs.online/home/challenge/the-report-a6dd340dba
permalink: /blue-team/labs/thereport/
summary: '"As part of gathering intel you were assigned a task to study a threat report released in 2022 and suggest some useful outcomes for your SOC."'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/b1ec49c9408d8e1af21b21083b9de81fcad55c29.png
type: challenge
points:
youtube:
---
## Scenario

You are working in a newly established SOC where there is still a lot of work to do to make it fully functional. As part of gathering intel you were assigned a task to study a threat report released in 2022 and suggest some useful outcomes for your SOC.

The report in question is the **Red Canary 2022 Threat Detection Report**, based on analysis of over 30,000 confirmed threats detected across customer environments throughout 2021.

---

## Answers

### Q1 — Supply chain attack related to Java logging library (end of 2021)

The report covers Log4j under the Supply Chain Compromises trend section. Log4j is a popular Java logging library that was hit with a remote code execution vulnerability in December 2021. Initial exploitation was primarily coinminers and botnets, with internet-facing VMware Horizon servers becoming a key target.


---

### Q2 — MITRE Technique ID affecting more than 50% of customers

From the Top Techniques table on page 73, T1059: Command and Scripting Interpreter topped the list at **53.4%** of customers affected, with PowerShell (T1059.001) and Windows Command Shell (T1059.003) as the dominant sub-techniques.


---

### Q3 — 2 vulnerabilities belonging to Exchange Servers

The Vulnerabilities trend section covers two major Exchange Server vulnerability chains:

- **ProxyLogon** (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065) — disclosed March 2021, allowed RCE when chained together
- **ProxyShell** (CVE-2021-31207, CVE-2021-34523, CVE-2021-34473) — disclosed July 2021, allowed unauthenticated RCE

Both resulted in web shell deployment and in some cases ransomware.


---

### Q4 — CVE of zero day vulnerability of a driver leading to RCE and SYSTEM privileges

This refers to **PrintNightmare**, which abuses the Print Spooler service. The vulnerability allows an adversary to connect to a remote host without authentication, cause it to load a malicious DLL, and gain SYSTEM-level code execution via the print spooler service (running as SYSTEM).

---

### Q5 — 2 adversary groups that leverage SEO to gain initial access

From the User-Initiated Initial Access and individual threat sections:

- **Yellow Cockatoo** — uses search engine poisoning to deliver malicious files named after the victim's search query
- **Gootkit** — operators alter search engine results to direct victims to compromised websites hosting a malicious ZIP/JS payload

---

### Q6 — Parent process for detection of malicious JS file execution (not CMD)

From the SocGholish and Gootkit detection sections, the detection analytic for JavaScript execution identifies:

```
process == wscript.exe
&&
command_line_includes (.zip && .js)
```

The Windows Script Host (`wscript.exe`) is the parent process responsible for executing the malicious JavaScript files.

---

### Q7 — Precursors used by affiliates of Conti ransomware group

From the Ransomware affiliate model table, three malware families are listed as precursors leading to Conti:

|Malware Family|Ransomware Group|
|---|---|
|Qbot|Conti|
|Bazar|Conti|
|IcedID|Conti|

---

### Q8 — 2 outdated software targeted by coinminers

From the Linux Coinminers trend section, the Take Action box specifically calls out patch management and names two outdated applications frequently exploited by coinminers:

> "Many of the coinminers we saw exploited flaws in outdated applications like JBoss and WebLogic"

---

### Q9 — Ransomware group that threatened DDoS if ransom not paid

From the Ransomware > Beyond Encryption section, an adversary known as Fancy Lazarus (no affiliation with Fancy Bear or Lazarus Group) extorted victims by threatening to conduct a DDoS attack if they didn't pay.

---

### Q10 — Security measure required for RDP connections to safeguard against ransomware

From the Ransomware Take Action section, internet-facing RDP connections without multi-factor authentication are explicitly called out as a common ransomware vector, making MFA for any accounts that can log in via RDP a high priority.

---

## Key Takeaways

- Supply chain attacks (SolarWinds, Kaseya, Log4j) represent a significant and growing risk — maintaining an accurate software/vendor inventory is critical for rapid response
- T1059 is the most prevalent technique — PowerShell and Windows Command Shell monitoring should be a baseline detection priority for any SOC
- The affiliate/RaaS model complicates attribution — defenders should focus on TTPs and precursor malware (Qbot, Bazar, IcedID) rather than trying to attribute to a single group
- Patch management and MFA remain the most effective preventative controls against ransomware
- SEO poisoning and user-initiated initial access are increasingly common — web proxy controls blocking low-reputation domains are an underrated defence
- Dual-use tools (Cobalt Strike, BloodHound, Impacket) require a baseline understanding of authorised use in your environment before you can effectively triage alerts

**Source:** [Red Canary 2022 Threat Detection Report](https://redcanary.com/threat-detection-report/)

---

<div class="qa-item"> <div class="qa-question-text">Name the supply chain attack related to Java logging library in the end of 2021 (Format: AttackNickname)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Log4j</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Mention the MITRE Technique ID which effected more than 50% of the customers (Format: TXXXX)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">T1059</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Submit the names of 2 vulnerabilities belonging to Exchange Servers (Format: VulnNickname, VulnNickname)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">ProxyLogon, ProxyShell</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Submit the CVE of the zero day vulnerability of a driver which led to RCE and gain SYSTEM privileges (Format: CVE-XXXX-XXXXX)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">CVE-2021-34527</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Mention the 2 adversary groups that leverage SEO to gain initial access (Format: Group1, Group2)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Yellow Cockatoo, Gootkit</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Question 6) In the detection rule, what should be mentioned as parent process if we are looking for execution of malicious js files [Hint: Not CMD] (Format: ParentProcessName.exe)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">wscript.exe</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Ransomware gangs started using affiliate model to gain initial access. Name the precursors used by affiliates of Conti ransomware group (Format: Affiliate1, Affiliate2, Afilliate3)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Qbot, Bazar, IcedID</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">The main target of coin miners was outdated software. Mention the 2 outdated software mentioned in the report (Format: Software1, Software2)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">JBoss, WebLogic</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Name the ransomware group which threatened to conduct DDoS if they didn't pay ransom (Format: GroupName)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Fancy Lazarus</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the security measure we need to enable for RDP connections in order to safeguard from ransomware attacks? (Format: XXX)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">MFA</span> </div> </div>
