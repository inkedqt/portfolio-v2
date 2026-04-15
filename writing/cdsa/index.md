---
layout: writing
title: HTB CDSA — Is It Worth It for Breaking Into SOC?
date: 2026-01-10
type: review
summary: A honest breakdown of the HTB CDSA exam — what it covers, how hard it actually is, and whether it moves the needle for landing an L1 SOC role.
---
## HTB CDSA — Is It Worth It for Breaking Into SOC?

The HTB Certified Defensive Security Analyst (CDSA) is one of the more serious blue team certs available right now. Not serious in a "memorise this RFC" way — serious in the sense that you're handed a live environment, multiple compromised hosts, real tooling, and told to figure out what happened. No multiple choice. No hand-holding. You write a commercial-grade incident report and submit it alongside your flags.

Having just come out the other side of it, here's an honest breakdown.

---

### What the Exam Actually Is

The exam gives you two independent incidents across two separate networks. You access everything via RDP into a Windows lab host loaded with a full DFIR toolkit — a SIEM for each incident, memory analysis tooling, log analysis utilities, offline registry tools, and KAPE-collected artefacts. Your job is to work both incidents end-to-end and produce a report that covers executive summary, technical analysis, IOCs, root cause analysis, kill chain coverage, and a technical timeline — per incident.

The passing bar is 16 of 20 flags on Incident 1, plus a report that meets a commercial standard across both. The flags aren't just "run this tool and read the output." You're pivoting across data sources, chasing the same attacker across multiple hosts in a multi-stage intrusion, and documenting every step in a way that would hold up in a professional context.

The two incidents cover meaningfully different attack types and different primary SIEMs, so you can't lean on one tool for the whole exam. Each requires building a story from raw evidence — not following a guided walkthrough.

---

### The Tooling Reality

The CDSA course covers a broad DFIR toolkit and the exam reflects it. On the day you're likely to touch all of the following:

- **Kibana (Elastic/Winlogbeat)** — SIEM work for one incident. You're writing raw KQL, pivoting across process relationships, command line arguments, and file events. Sysmon data does a lot of the heavy lifting.
- **Splunk** — primary SIEM for the second incident. SPL syntax is different to KQL but the investigative methodology is the same. Knowing both matters.
- **Volatility 3** — memory analysis on specific processes. Used to surface tooling that an attacker tried to hide inside a legitimate process — strings extraction and handle analysis are the main workflows.
- **Chainsaw** — rapid Windows event log searching across a directory. Good for hunting a specific indicator when you know roughly what you're looking for and need to cover a lot of logs fast.
- **Registry Explorer** — offline hive analysis for persistence. One of the more satisfying finds of the exam came out of a registry hunt for a subtly named DLL in a Run key.

Knowing _why_ you're using each tool at a given point matters more than knowing every flag. The exam rewards investigative thinking, not tool memorisation.

---

### How It Compares to BTL1

I have both. They're targeting different things and it's worth being honest about that.

BTL1 is broader and more accessible. It covers phishing, SIEM, digital forensics, network analysis, and threat intel as separate domains. The exam is open-book, six hours, scenario-based but guided. It's an excellent foundational cert — the breadth is its strength.

CDSA goes deeper on investigation and pushes harder on actual workflow. The exam environment is more realistic. You're not answering questions about what a tool can do — you're working a live case with multiple threads, competing hypotheses, and incomplete information. The report requirement forces you to document your methodology in a way that BTL1 doesn't, which builds a skill that actually matters professionally.

Ranked purely on investigation depth and exam realism: CDSA is the harder cert and the more impressive one to hold. Ranked on foundational coverage: BTL1 is more well-rounded and covers terrain the CDSA course doesn't touch.

Ideally you want both. They complement each other well.

---

### Will It Help Land an L1 SOC Role?

Honestly — yes, but with caveats worth knowing upfront.

The CDSA is primarily a DFIR cert. An L1 SOC role day-to-day is less "run memory analysis on a process dump" and more "triage this alert, check it against context, escalate or close." The investigation depth the CDSA builds is more relevant to L2/L3 or IR work than it is to L1 ticket velocity.

That said, it demonstrates something that matters: you can actually investigate. Not just follow a playbook, not just run a tool — but track an attacker across multiple data sources, correlate evidence, and produce documentation that a SOC manager could hand to a client. That's a genuine differentiator when you're competing against candidates with a Security+ and a Udemy course.

The SIEM work is the most directly transferable piece. Writing KQL and SPL under exam pressure, pivoting across event sources, building a timeline from raw logs — that's the core skill an L1 analyst uses daily. The cert proves you can do it in an environment you've never seen before, which is more meaningful than proving you memorised a syllabus.

Where it falls short as an L1 hiring signal: most managed SOC shops in Australia run Sentinel and Defender, not Elastic and Splunk. The investigative methodology transfers completely; the syntax doesn't. SC-200 on top of CDSA would round that gap out well.

---

### Bottom Line

The CDSA is worth it if you're serious about blue team work and want a cert that tests investigation skill rather than knowledge recall. The exam experience — two real incidents, full toolchain, commercial report requirement — is closer to what DFIR work actually looks like than most certs manage.

For the SOC job hunt specifically: it's a strong signal in a field with a lot of noise. Combine it with BTL1, a SIEM-specific cert, and demonstrated lab work across ranked platforms and you've built a story that's hard to dismiss.

The cert alone won't get you hired. The skills it builds might.
