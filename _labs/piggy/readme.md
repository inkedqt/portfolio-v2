---
layout: lab
title: "Piggy - BTL1 PCAP Analysis Lab"
platform: BTLO
difficulty: Easy        # or whatever they are
category: [Network Security Monitoring]
tools: [Wireshark]
tactics: [Initial Access, Credential Access]
proof: https://blueteamlabs.online/achievement/share/144656/66
challenge_url: https://blueteamlabs.online/home/investigation/piggy-aij2bd8h2
permalink: /blue-team/labs/piggy/
summary: "Multi-PCAP investigation — SSH data exfiltration identification, malware infrastructure discovery, ASN attribution,"
---

<div class="lab-writeup-header">
  <img src="{{ site.baseurl }}/assets/images/labs/btl1/piggy-hero.png" alt="Piggy Lab - Network Forensics Investigation">
  
  <div class="lab-meta">
    <span class="lab-badge completed">✓ COMPLETED</span>
    <span class="lab-category">BTL1 Learning Path • Foundational</span>
    <span class="lab-tags">PCAP Analysis • Wireshark • OSINT</span>
  </div>
</div>

## 🎯 Lab Objective

**Scenario:** Investigate network activity across four PCAP files to identify data exfiltration, malware infrastructure, and attacker techniques.

**Skills Practiced:**
- PCAP analysis with Wireshark
- SSH traffic analysis
- OSINT and threat intelligence research
- ASN attribution
- MITRE ATT&CK framework mapping

**Tools Used:**
- Wireshark
- VirusTotal
- WHOIS/ASN lookups
- MITRE ATT&CK Navigator

---

## 📊 Investigation Summary

**Platform:** Security Blue Team (BTL1 Certification Preparation)  
**Category:** Network Security Monitoring - Foundational Skills  
**Lab Focus:** Multi-PCAP investigation, data exfiltration analysis, threat intelligence  
**Completion Date:** February 13, 2026  
**Score:** 27/27 points  
**Tags:** `Wireshark` `SSH` `OSINT` `ATTACK` `BTL1`

---

## 🔍 PCAP One: SSH Data Exfiltration

### Question 1: Remote SSH IP Address
**What remote IP address was used to transfer data over SSH? (Format: X.X.X.X)**

**Analysis:**

Applied SSH filter in Wireshark to identify encrypted data transfer sessions.

**Methodology:**
1. Applied filter: `tcp.port == 22`
2. Reviewed TCP conversations
3. Identified remote endpoint for SSH session

![SSH Traffic Analysis]({{ site.baseurl }}/assets/images/labs/btl1/piggy-q1.png)

**Answer:** `35.211.33.16`

---

### Question 2: Data Transfer Volume
**How much data was transferred in total? (Format: XXXX M)**

**Analysis:**

Used Wireshark's Statistics feature to calculate total SSH data transfer.

**Methodology:**
1. Statistics → Conversations → IPv4
2. Located SSH conversation (35.211.33.16)
3. Summed bidirectional traffic (Tx + Rx bytes)

![Data Transfer Statistics]({{ site.baseurl }}/assets/images/labs/btl1/piggy-q2.png)

**Calculation:**
```
Tx Bytes: 8211 k
Rx Bytes: 1123 M
Total: ~1131 M
```

**Answer:** `1131 M`

---

## 🌐 PCAP Two: Malware Infrastructure Identification

### Question 3: Malware Family Attribution
**Review the IPs the infected system has communicated with. Perform OSINT searches to identify the malware family tied to this infrastructure (Format: MalwareName)**

**Analysis:**

Identified remote IPs in PCAP Two and conducted VirusTotal research for historical attribution.

**Methodology:**
1. Extracted unique destination IPs from conversations
2. Performed VirusTotal lookups on each IP
3. Reviewed "Communicating Files" section for malware samples
4. Cross-referenced detection names across multiple samples

**Key IP Investigated:** `31.184.253.165`

**VirusTotal Findings:**
- Multiple malicious executables communicating with this IP
- Consistent detection across vendors
- Historical malware family attribution

![VirusTotal Malware Attribution]({{ site.baseurl }}/assets/images/labs/btl1/piggy-q3.png)

**Answer:** `Trickbot`

---

## 🔎 PCAP Three: Unusual Port Communications

### Question 4: ASN Attribution
**Review the two IPs that are communicating on an unusual port. What are the two ASN numbers these IPs belong to? (Format: ASN, ASN)**

**Analysis:**

Identified non-standard port communications and performed ASN lookups.

**Methodology:**
1. Reviewed port statistics to find unusual ports
2. Identified IPs communicating on port 8080
3. Performed WHOIS/VirusTotal lookups for ASN information

**IP 1:** `194.233.171.171`
- **ASN:** 63949 (Akamai Connected Cloud)

**IP 2:** `104.236.57.24`
- **ASN:** 14061 (DIGITALOCEAN-ASN)

![ASN Identification]({{ site.baseurl }}/assets/images/labs/btl1/piggy-q4.png)

**Answer:** `63949, 14061`

---

### Question 5: Malware Category Attribution
**Perform OSINT checks. What malware category have these IPs been attributed to historically? (Format: MalwareType)**

**Analysis:**

Conducted deeper VirusTotal analysis on identified IPs.

**IP: 104.236.57.24 - VirusTotal Results:**
- **Detection Tags:**
  - ⚠️ AlphaSOC: **Miner**
  - ⚠️ GCP Abuse Intelligence: **Miner**
- **Communicating Files:** Multiple cryptocurrency mining executables
- **Historical Activity:** Consistent mining pool attribution

![Malware Category Attribution]({{ site.baseurl }}/assets/images/labs/btl1/piggy-q5.png)

**Conclusion:** Infrastructure historically associated with cryptomining operations.

**Answer:** `Miner`

---

### Question 6: MITRE ATT&CK Technique
**What ATT&CK technique is most closely related to this activity? (Format: TXXXX)**

**Analysis:**

Mapped observed cryptomining behavior to MITRE ATT&CK framework.

**Observed Behavior:**
- Cryptocurrency mining activity
- Resource hijacking for profit
- Victim system resources consumed for mining operations

**MITRE ATT&CK Research:**

**Technique:** [T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)

**Description:**
> "Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability."

![MITRE ATT&CK T1496]({{ site.baseurl }}/assets/images/labs/btl1/piggy-q6.png)

**Answer:** `T1496`

---

## 📡 PCAP Four: DNS TXT Record Analysis

### Question 7: TXT Query Timing (Seconds Since Capture Start)
**Go to View > Time Display Format > Seconds Since Beginning of Capture. How long into the capture was the first TXT record query made? (Format: X.xxxxxx)**

**Analysis:**

Configured Wireshark time display and located first DNS TXT query.

**Methodology:**
1. View → Time Display Format → Seconds Since Beginning of Capture
2. Applied filter: `dns.qry.type == 16` (TXT records)
3. Identified first packet in results

**First TXT Query:**
```
Time: 2.047649 seconds
Frame: 875
Query: mlckdhokhvhtcmevvcqbggcviwxqim.sandbox.alphasoc.xyz
```

![TXT Query Timeline]({{ site.baseurl }}/assets/images/labs/btl1/piggy-q7.png)

**Answer:** `8.527712`

---

### Question 8: TXT Query Timestamp (UTC)
**Go to View > Time Display Format > UTC Date and Time of Day. What is the date and timestamp? (Format: YYYY-MM-DD HH:MM:SS)**

**Analysis:**

Changed time display format to UTC and captured absolute timestamp.

**Methodology:**
1. View → Time Display Format → UTC Date and Time of Day
2. Located same TXT query packet (Frame 875)
3. Noted UTC timestamp

![UTC Timestamp]({{ site.baseurl }}/assets/images/labs/btl1/piggy-q8.png)

**Answer:** `2024-05-24 10:08:50`

---

### Question 9: MITRE ATT&CK Subtechnique
**What is the ATT&CK subtechnique relating to this activity? (Format: TXXXX.xxx)**

**Analysis:**

Identified DNS TXT record usage as a C2 channel and mapped to specific subtechnique.

**Observed Behavior:**
- DNS TXT queries for command and control
- Encoded data in DNS requests
- Application layer protocol abuse

**MITRE ATT&CK Research:**

**Subtechnique:** [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)

**Description:**
> "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic."

![MITRE ATT&CK T1071.004]({{ site.baseurl }}/assets/images/labs/btl1/piggy-q9.png)

**Answer:** `T1071.004`

---

## ✅ Lab Completion

**Final Results:**
- ✓ All 9 questions answered correctly (27/27 points)
- ✓ Identified SSH data exfiltration (1131 M transferred)
- ✓ Attributed Pony malware family via OSINT
- ✓ Discovered cryptomining infrastructure (Miner category)
- ✓ Mapped to MITRE ATT&CK framework (T1496, T1071.004)
- ✓ Demonstrated multi-PCAP correlation skills

![Lab Completion Certificate]({{ site.baseurl }}/assets/images/labs/btl1/piggy-completion.png)

---

## 📊 MITRE ATT&CK Mapping

| Technique ID | Technique Name | Observed Evidence |
|--------------|----------------|-------------------|
| **T1071.004** | Application Layer Protocol: DNS | DNS TXT queries for C2 communication |
| **T1496** | Resource Hijacking | Cryptomining infrastructure and miner attribution |
| T1041 | Exfiltration Over C2 Channel | SSH data transfer to remote IP |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS traffic to mining pools |

---

## 🎓 Key Takeaways

### Technical Skills Demonstrated

**PCAP Analysis:**
- Multi-file PCAP investigation and correlation
- SSH traffic analysis and data volume calculation
- DNS query inspection (TXT records)
- Wireshark statistics and conversation analysis
- Time display format configuration

**Threat Intelligence:**
- VirusTotal OSINT research
- ASN attribution and WHOIS lookups
- Historical malware family identification
- IOC correlation across multiple sources

**Framework Application:**
- MITRE ATT&CK technique mapping
- Subtechnique identification
- Understanding attacker TTPs across multiple stages

### SOC Analyst Perspective

**Detection Opportunities:**
- Monitor for large SSH data transfers to external IPs
- Alert on connections to known malware/mining infrastructure
- Detect suspicious DNS TXT queries (especially to random subdomains)
- Track ASN reputation for outbound connections
- Correlate multiple indicators across timeframes

**Investigation Workflow:**
1. **Identify anomalies** - Unusual ports, large transfers, suspicious domains
2. **Extract IOCs** - IPs, domains, ports, protocols
3. **Enrich with OSINT** - VirusTotal, ASN lookups, malware databases
4. **Map to framework** - ATT&CK techniques for context
5. **Document findings** - Timeline, evidence, conclusions

**Lessons Learned:**
- Multi-PCAP investigations require correlation across files
- OSINT is critical for attribution and historical context
- Time display format matters for incident reporting
- Understanding both techniques and subtechniques provides deeper analysis
- Statistical analysis (data volume) can reveal exfiltration

---

## 🔗 Investigation Artifacts

**IOCs Identified:**

| Indicator Type | Value | Context |
|----------------|-------|---------|
| IPv4 | 35.211.33.16 | SSH data exfiltration destination |
| IPv4 | 31.184.253.165 | Pony malware C2 infrastructure |
| IPv4 | 194.233.171.171 | Mining infrastructure (AS 63949) |
| IPv4 | 104.236.57.24 | Mining infrastructure (AS 14061 - Miner tagged) |
| Domain | mlckdhokhvhtcmevvcqbggcviwxqim.sandbox.alphasoc.xyz | DNS TXT C2 query |
| Port | 22 (SSH) | Data exfiltration channel |
| Port | 8080 | Unusual port communication |
| Data Volume | 1131 M | Total SSH transfer volume |
| Malware Family | Trickbot | Stealer/information theft malware |

**Timeline:**
- `2024-05-24 10:08:50 UTC` - First DNS TXT query (8.527712s into capture)

---

<div class="lab-nav">
  <a href="{{ site.baseurl }}/blue-team/" class="btn-back">← Back to Blue Team Portfolio</a>
  <a href="{{ site.baseurl }}/blue-team/" class="btn-next">More Labs Coming Soon</a>
</div>
```

---
