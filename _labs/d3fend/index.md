---
layout: lab
title: D3FEND
platform: CyberDefenders
difficulty: Easy
category: Threat Intelligence
skill: Threat Intelligence
tools: D3FEND Framework
tactics:
proof: https://blueteamlabs.online/achievement/share/challenge/144656/27
challenge_url: https://blueteamlabs.online/home/challenge/d3fend-6c9dcd4b79
permalink: /blue-team/labs/d3fend/
summary: '"Navigating the MITRE D3FEND framework to identify defensive techniques, tactics, artifacts and open-source tooling mapped to ATT&CK."'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/4483c9698a1377a56b1ab536b91bf825de5a227f.png
type: challenge
points:
youtube:
---
## Overview

A companion challenge to ATT&CK, this lab focuses on **MITRE D3FEND** — the defensive counterpart to ATT&CK that provides a structured knowledge base of cybersecurity countermeasures. Where ATT&CK maps adversary techniques, D3FEND maps defensive techniques, artifacts, and digital mappings that defenders can operationalize. This challenge tests navigation of the D3FEND matrix at d3fend.mitre.org.

---

## D3FEND Framework Navigation

### Technique Lookup — D3-SDM

Each D3FEND technique has a unique ID prefixed with `D3-`. Looking up **D3-SDM** in the framework resolves to **System Daemon Monitoring** — a detection technique that involves monitoring system daemons for anomalous behaviour indicative of compromise or tampering.

### The Five D3FEND Tactics

D3FEND organises all defensive techniques under five top-level tactics, representing the general categories of defensive action available to defenders. In the order they appear in the framework:

1. **Harden** — reducing attack surface before exploitation occurs
2. **Detect** — identifying adversary activity in progress
3. **Isolate** — containing or limiting the spread of an attack
4. **Deceive** — misleading adversaries to waste resources or reveal intent
5. **Evict** — removing adversary presence from the environment

This structure complements ATT&CK's offensive tactic chain and gives blue teams a direct defensive mapping for each adversary technique.

### Open-Source ATT&CK to D3FEND Bridge

The open-source project **Sentinel2D3FEND** bridges the gap between detection and defence — it retrieves Azure Sentinel detection rules that are already mapped to MITRE ATT&CK techniques, then automatically generates the corresponding MITRE D3FEND defensive countermeasures. This allows SOC teams using Sentinel to immediately understand what defensive techniques are relevant to the threats their detection rules cover.

### Technique Definition — File Access Pattern Analysis

**File Access Pattern Analysis** is defined by the framework as:

> Analyzing the files accessed by a process to identify unauthorized activity.

This technique falls under the Detect tactic and is useful for identifying malware, data staging, or credential access behaviour by correlating process-to-file access patterns against known-good baselines.

### Artifact Definition — Local Resource Access

A **Local Resource Access** artifact is defined as:

> Ephemeral digital artifact comprising a request of a local resource and any response from that resource.

D3FEND artifacts represent the digital evidence or signals that defensive techniques operate on. Ephemeral artifacts are transient — they exist only in the moment of the request/response and may not persist to disk, making real-time monitoring essential for capturing them.


---

<div class="qa-item"> <div class="qa-question-text">What is the corresponding name for the ID ‘D3-SDM’?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">System Daemon Monitoring</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What are the five general tactics used to classify each defensive method? (In the order they appear)</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Harden, Detect, Isolate, Deceive, Evict
</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What open-source project retrieves Azure Sentinel rules that are mapped to MITRE ATT&CK Framework and generates the related MITRE D3FEND defenses?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Sentinel2D3FEND</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What does ‘File Access Pattern Analysis’ mean?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Analyzing the files accessed by a process to identify unauthorized activity.</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What does ‘Local Resource Access’ artifact mean?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Ephemeral digital artifact comprising a request of a local resource and any response from that resource.</span> </div> </div>
