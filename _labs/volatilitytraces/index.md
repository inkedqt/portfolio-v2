---
layout: lab
title: Volatility Traces
platform: CyberDefenders
difficulty: Easy
category: Endpoint Forensics
tools: ["Volatility 3"]
tactics: ["Execution", "Persistence", "Defense Evasion"]
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/volatility-traces/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/volatility-traces/
permalink: /blue-team/labs/volatilitytraces/
summary: "Analyze a memory dump using Volatility to identify malicious processes, persistence mechanisms, defense evasion techniques, and map them to MITRE ATT&CK."
art: https://cyberdefenders.org/media/terraform/Volatility%20Traces/Volatility_Traces_A7cz9FH.webp
---

## Overview

This investigation focused on analyzing a Windows memory dump using Volatility to identify suspicious processes, persistence mechanisms, defense evasion activity, and the user account associated with malicious behavior.

Only three plugins were required: `windows.psscan`, `windows.cmdline`, and `windows.getsids`. The analysis revealed malicious PowerShell execution, antivirus exclusions being added, and suspicious executables linked to a specific user account.

---

## Evidence Source

| Artifact | Detail |
|----------|--------|
| Memory Image | memory.dmp |
| Tool | Volatility 3 |

---

## Step 1 — Identify Suspicious Parent Process

Running `windows.psscan` against the memory dump revealed the process hierarchy. One executable stood out — it had spawned two child PowerShell processes, which is uncommon for legitimate software.

```
python3 vol.py -f memory.dmp windows.psscan
```

![psscan showing process hierarchy](vol_psscan1.png)

![pslist detail view](vol_pslist.png)

The parent process was suspicious by name alone — a document-themed executable with no legitimate reason to be spawning PowerShell children.

---

## Step 2 — Analyze Process Command Lines

With the suspicious parent identified, `windows.cmdline` was used to extract the full command line arguments of all running processes. This is where attacker intent becomes clear.

```
python3 vol.py -f memory.dmp windows.cmdline
```

![cmdline output](col_spscan2.png)

![psscan detail](vol_psscan3.png)

Both PowerShell processes were launched with parameters targeting Windows Defender's exclusion list using `Add-MpPreference` with `-ExclusionPath`. This is a well-known defense evasion pattern — the malware is carving out a safe zone for itself before executing its payload.

A secondary executable was also identified as active under the same parent — a persistence mechanism designed to survive reboots.

---

## Step 3 — Map to MITRE ATT&CK

The PowerShell activity maps directly to a specific sub-technique. Modifying antivirus exclusion settings falls under **Impair Defenses** — the adversary is not disabling AV entirely (which would alert), but surgically excluding their own tools from scanning.

![MITRE ATT&CK T1562.001](vol_mitre.png)

---

## Step 4 — Identify Associated User Account

The final step linked the malicious processes to a local user account using `windows.getsids`, filtering for PowerShell processes. The SID mapping revealed which account the attacker was operating under.

```
python3 vol.py -f memory.dmp windows.getsids | grep -i powershell
```

![getsids output showing associated user](vol_lee.png)

---

## IOCs

| Type | Value |
|------|-------|
| Suspicious Parent (PID 4596) | InvoiceCheckList.exe |
| Persistence Executable | HcdmIYYf.exe |
| Child Processes | powershell.exe ×2 |
| Additional Process (PID 4596) | RegSvcs.exe |
| Associated User | Lee |
| MITRE Technique | T1562.001 |

---

## Lessons Learned

`psscan` scans physical memory directly — it catches processes unlinked from the standard process list to evade detection. `cmdline` reveals attacker intent more clearly than any other artifact; the PowerShell parameters here told the whole story. Pairing `getsids` with process filtering is an efficient way to pivot from process to user context.

The use of `Add-MpPreference` as a defense evasion technique is worth adding to your detection playbook — it is legitimate PowerShell, which means it rarely triggers alerts on its own. Behavioral detection (PowerShell spawned from a document-themed executable) is the more reliable signal.

> The investigation successfully identified the malicious process chain, persistence mechanism, defense evasion technique, and associated user account using three focused Volatility plugins. A narrow, methodical approach was more effective than running every available plugin.

---

## Lab Questions

{% include flag.html question="What is the name of the suspicious process that spawned two malicious PowerShell processes?" answer="InvoiceCheckList.exe" %}

{% include flag.html question="Which executable is responsible for the malware's persistence?" answer="HcdmIYYf.exe" %}

{% include flag.html question="Aside from the PowerShell processes, what other active suspicious process originating from the same parent is identified?" answer="RegSvcs.exe" %}

{% include answer.html question="What PowerShell cmdlet is used by the malware for defense evasion?" answer="Add-MpPreference" %}

{% include answer.html question="Which two applications were excluded by the malware from antivirus scanning?" answer="InvoiceCheckList.exe, HcdmIYYf.exe" %}

{% include answer.html question="What is the specific MITRE sub-technique ID associated with disabling or modifying antivirus settings?" answer="T1562.001" %}

{% include answer.html question="Which user account is linked to the malicious processes?" answer="Lee" %}
