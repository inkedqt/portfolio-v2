---
layout: lab
title: ATT&CK
platform: BTLO
difficulty: Easy
category: Threat Intelligence
skill: Threat Intelligence
tools: Mitre attack framework
tactics: "[Execution, Command and Control]"
proof: https://blueteamlabs.online/achievement/share/challenge/144656/15
challenge_url: https://blueteamlabs.online/home/challenge/attck-0e4914db5d
permalink: /blue-team/labs/attack_btlo/
summary: '"See how you can operationalize the MITRE ATT&CK framework to solve these scenario-based problems. "'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/a5af13bcbfd3f4487f33493646eabc4a07d617c6.png
type: challenge
points:
youtube:
---
## Overview

A threat intelligence challenge focused on operationalizing the MITRE ATT&CK framework. Rather than log analysis or malware triage, this lab tests your ability to navigate the ATT&CK matrix and extract actionable intelligence — mapping techniques, identifying threat actors, and understanding detection strategies.

---

## ATT&CK Framework Navigation

### Cloud Discovery — Azure AD & Office 365

When an attacker obtains valid credentials to a cloud environment like Azure AD or Office 365, they can perform Discovery without touching any API. The relevant technique is **T1538 — Cloud Service Dashboard**, which covers adversaries using the cloud service's web GUI directly to enumerate the environment. Since the hint specifies no API interaction, this rules out techniques like T1526 (Cloud Service Discovery via API calls) and points squarely at the browser-based dashboard approach.

Mitigation: enforce MFA, restrict access to administrative portals, and implement Conditional Access policies to detect anomalous login locations or devices.

### Uncommon Data Flow — Port 4050

Observing unusual C2 traffic on port 4050 is a fingerprint for **G0099 — APT-C-36** (also known as Blind Eagle), a suspected South American espionage group primarily targeting Colombian government institutions and financial sector corporations. This group is documented under **T1571 — Non-Standard Port**, using port 4050 for C2 communications to blend into legitimate traffic and evade port-based filtering.

### Initial Access — 9 Techniques

The tactic covering methods an attacker uses to get into your network is **TA0001 — Initial Access**. The framework documents exactly 9 techniques under this tactic:

- T1189 — Drive-by Compromise
- T1190 — Exploit Public-Facing Application
- T1091 — Replication Through Removable Media
- T1200 — Hardware Additions
- T1566 — Phishing
- T1195 — Supply Chain Compromise
- T1199 — Trusted Relationship
- T1078 — Valid Accounts
- T1133 — External Remote Services

### Account Access Removal Software

The software documented by the framework that prohibits users from accessing their accounts via deletion, lockout, or password changes is **S0372 — LockerGoga**. This ransomware strain is documented under T1531 (Account Access Removal) for its behavior of changing account passwords and forcibly logging off users prior to encryption — preventing incident responders from accessing systems during the attack.

### Detecting Pass the Hash

Pass the Hash (T1550.002) allows attackers to authenticate using captured NTLM hashes without knowing the plaintext password, enabling lateral movement across a network. Per the MITRE ATT&CK framework's detection guidance, the recommended approach is to **monitor newly created logons and credentials used in events and review for discrepancies** — specifically looking for NTLM Type 3 network logons that don't align with expected user behaviour or authentication patterns.

Key Windows Event IDs to monitor:

- **4624** — Successful logon (focus on LogonType 3)
- **4648** — Logon using explicit credentials
- **4672** — Special privileges assigned to new logon

---

<div class="qa-item"> <div class="qa-question-text">Your company heavily relies on cloud services like Azure AD, and Office 365 publicly. What technique should you focus on mitigating, to prevent an attacker performing Discovery activities if they have obtained valid credentials? (Hint: Not using an API to interact with the cloud environment!)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">T1538</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">You were analyzing a log and found uncommon data flow on port 4050. What APT group might this be?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">G0099</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">The framework has a list of 9 techniques that falls under the tactic to try to get into your network. What is the tactic ID?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">TA0001</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">A software prohibits users from accessing their account by deleting, locking the user account, changing password etc. What such software has been documented by the framework?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">S0372</span> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Using ‘Pass the Hash’ technique to enter and control remote systems on a network is common. How would you detect it in your company?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Monitor newly created logons and credentials used in events and review for discrepancies</span> </div> </div>
