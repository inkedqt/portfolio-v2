---
layout: lab
title: Spider
platform: BTLO
difficulty: Easy
category: Threat Intelligence
skill: Threat Intelligence
tools: OSINT
tactics: T1087
proof: https://blueteamlabs.online/achievement/share/144656/237
challenge_url: https://blueteamlabs.online/home/investigation/spider-3606f6b894
permalink: /blue-team/labs/spider/
summary: '"hreat intelligence investigation into Scattered Spider UNC3944 — a financially motivated group leveraging social engineering, SIM swapping, and RaaS affiliations to breach high-profile organisations across multiple sectors."'
art: https://blueteamlabs.online/storage/labs/485b2f8e523c798bc5cf13d4230f92dcfc6ef985.png
type:
points:
youtube:
---
![spider_flowchart.png](spider_flowchart.png)

## Overview

Scattered Spider (tracked by Mandiant as **UNC3944**) is a native English-speaking, financially motivated threat group active since 2022. They're best known for bypassing enterprise security through social engineering rather than technical exploits — targeting help desks, abusing SSO platforms, and pivoting through cloud infrastructure once inside. This lab is a deep-dive TI investigation into their TTPs, tooling, and RaaS affiliations.

---

## Investigation

### Identity & Attribution

Mandiant tracks this group as **UNC3944**. The group is also referred to as Octo Tempest and Storm-0875 depending on the vendor. Their most publicised breach was against **Caesars Entertainment** in September 2023, where they exfiltrated approximately six terabytes of data and deployed ransomware.

### Phishing Infrastructure

Scattered Spider creates convincing SSO-themed phishing pages impersonating the target organisation. A documented example targeting Walmart employees used the domain **walmartsso[.]com**, registered through **Hosting Concepts B.V. d/b/a Registrar.eu**.

Source: [Sekoia — Scattered Spider Laying New Eggs](https://blog.sekoia.io/scattered-spider-laying-new-eggs/)

### RaaS Affiliation

Prior to ALPHV/BlackCat's apparent shutdown, Scattered Spider operated as an **ALPHV** affiliate — leveraging the RaaS for their high-profile casino attacks. In 2024, the group shifted to emerging RaaS platforms **Qilin** and **RansomHub**.

Sources: [Darktrace — Untangling the Web](https://www.darktrace.com/blog/untangling-the-web-darktraces-investigation-of-scattered-spiders-evolving-tactics)

### EDR Abuse

In a Mandiant-reported incident, the group abused CrowdStrike Falcon's **Real Time Response (RTR)** module to execute commands including `whoami` and `quser` directly within the victim environment — living off the security tooling already present.

Source: [Google Cloud / Mandiant — UNC3944 Targets SaaS Applications](https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications)

### VM Persistence & Defense Evasion

The group establishes persistence by creating new virtual machines in vSphere and Azure, then deploying a batch script called **privacy-script.bat** to disable defenses on the freshly spun-up VMs.

For Azure credential and secret enumeration, they use the open-source PowerShell toolkit **MicroBurst** — capable of pulling storage keys, secrets, and connection strings from Azure environments.

Source: [Google Cloud / Mandiant — UNC3944 Targets SaaS Applications](https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications)

### Credential Access & Bypassing Domain Controls

In vSphere environments, Scattered Spider uses **PCUnlocker** to reset local administrator passwords, effectively bypassing domain controls and gaining persistent local access.

For browser-based credential theft, the group deploys **Raccoon Stealer** to harvest browser history and cookies post-foothold.

Source: [MITRE ATT&CK — Raccoon Stealer S1148](https://attack.mitre.org/software/S1148/)

### Cloud Exfiltration

The group exfiltrates data from cloud-hosted sources to attacker-controlled S3 buckets using ETL (Extract, Transform, Load) tools — specifically **Airbyte** and **Fivetran** — to blend in with legitimate data pipeline traffic.

Source: [Google Cloud / Mandiant — UNC3944 Targets SaaS Applications](https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications)

### Ransomware Binary Analysis

Analysis of the ransomware binary (SHA256: `df8d000833243acc0004595b3a8d4b66fcd7b76d8685d5c2ff61ee2a40a0e92c`) via Joe Sandbox reveals a YARA-detectable string indicating VSS deletion:

```
vssadmin.exe Delete Shadows /all /quietshadow_copy::remove_all_vss=
```

Source: [Joe Sandbox Report](https://www.joesandbox.com/analysis/1612710/0/html)

---

## MITRE ATT&CK

|Tactic|Technique|Description|
|---|---|---|
|Reconnaissance|T1598|Phishing for Information (SSO/help desk lures)|
|Initial Access|T1566|Phishing (smishing, SSO-themed pages)|
|Initial Access|T1621|MFA Request Generation (MFA fatigue)|
|Persistence|T1136|Create Account (new VMs in vSphere/Azure)|
|Defense Evasion|T1562.001|Impair Defenses (privacy-script.bat)|
|Defense Evasion|T1656|Impersonation|
|Credential Access|T1003|OS Credential Dumping (PCUnlocker)|
|Credential Access|T1539|Steal Web Session Cookie (Raccoon Stealer)|
|Discovery|T1059.001|PowerShell (MicroBurst — Azure enumeration)|
|Collection|T1530|Data from Cloud Storage Object|
|Exfiltration|T1567|Exfiltration Over Web Service (ETL tools to S3)|
|Impact|T1486|Data Encrypted for Impact (ALPHV/Qilin/RansomHub)|
|Impact|T1657|Financial Theft|

---

## IOCs

|Type|Value|
|---|---|
|Phishing Domain|walmartsso[.]com|
|Ransomware SHA256|df8d000833243acc0004595b3a8d4b66fcd7b76d8685d5c2ff61ee2a40a0e92c|



---

{% include flag.html question="What name is used by Mandiant to track the threat actor group SCATTERED SPIDER?" answer="UNC3944" %}

{% include answer.html question="The group breached the name of the American hospitality and entertainment company in September 2023. What was the name?" answer="caesars Entertainment" %}

{% include flag.html question="SCATTERED SPIDER extensively uses smishing messages to target employees for stealing credentials. The phishing pages are designed to impersonate the targeted organization and frequently use single sign-on (SSO) or service desk lures. Identify a phishing domain related to Walmart." answer="walmartsso[.]com" %}

{% include answer.html question="Name the registrar of the domain name." answer="hosting concepts b.v. d/b/a registrar.eu" %}

{% include flag.html question="Before the alleged disappearance of the adversary ALPHA SPIDER, SCATTERED SPIDER was an affiliate of which Ransomware-as-a-Service (RaaS) operations?" answer="ALPHV" %}

{% include answer.html question="In an incident reported by Mandiant, the group used an endpoint detection and response (EDR) tooling to execute commands such as “whoami” and “quser” within the victim environment. Identify the EDR module used for command execution." answer="Real Time Response" %}

{% include flag.html question="SCATTERED SPIDER establishes persistence through the creation of new virtual machines in vSphere and Azure environments. They deploy open-source utilities to disable defenses on the newly created VMs. Name the batch script used for this purpose." answer="privacy-script.bat" %}

{% include answer.html question="The threat actor leveraged an open-source PowerShell toolkit to enumerate Azure credentials and secrets. Name the tool." answer="MicroBurst" %}

{% include flag.html question="This utility is used by the threat group to bypass domain controls, including resetting local administrator passwords in vSphere environments." answer="PCUnlocker" %}

{% include answer.html question="Infostealers are malware that can steal sensitive information from compromised systems. Upon establishing a foothold in the victim environment, the threat actor retrieves browser histories and browser cookies using infostealers. Name the infostealer malware used by SCATTERED SPIDER." answer="Raccoon Stealer" %}

{% include flag.html question="SCATTERED SPIDER collects data from cloud-hosted data sources and exfiltrates to attacker-owned cloud storage resources such as S3 buckets using extract, transform, and load (ETL) tools. Name the tools—alphabetically." answer="Airbyte, Fivetran" %}

{% include answer.html question="To accomplish their objective, SCATTERED SPIDER deploys ransomware binary to encrypt the victim environment. Analyze the binary (SHA256: df8d000833243acc0004595b3a8d4b66fcd7b76d8685d5c2ff61ee2a40a0e92c) and provide the string present in the sample which indicates deletion of volume shadow copies. Utilize Joe Sandbox." answer="vssadmin.exe Delete Shadows /all /quietshadow_copy::remove_all_vss=" %}

{% include flag.html question="In the last few months, SCATTERED SPIDER members have joined forces with emerging RaaS services. Name the RaaS services—alphabetically." answer="" %}
