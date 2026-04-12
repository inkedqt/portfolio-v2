# inksec.io — Portfolio Review & Suggestions
_SOC L1 hiring perspective · April 2026_

---

## Overall Verdict

Not peaked — very strong, but a few friction points could cost you interviews. The site is genuinely impressive for a SOC L1 applicant and well above average. What follows is what's actually worth fixing.

---

## What's Working Well (Don't Touch)

- **Day X YouTube series** — biggest differentiator. Most applicants just list certs; you've documented 80+ real investigations out loud. That's rare.
- **Dual offensive/defensive profile** — HTB Top 1%, CPTS alongside CDSA and BTL1 tells a story: you understand attacker thinking. That's exactly what SOC L1 hiring managers want.
- **Design** — distinctive, memorable, fits the field. Not generic.
- **TAFE medal nomination** — adds real credibility, keep it prominent on the resume.
- **Cert stack** — CDSA + BTL1 are the two most directly relevant certs for the target role. Priority ordering is correct.
- **Showcase section on /blue-team/** — the IR / SOC / CLOUD domain rows with 3 featured writeups each is well structured. Organized by domain before the full 87-lab grid is the right call.

---

## Issues That Could Hurt You

### 1. Stats inconsistency — fix this first

| Location     | Investigations | YouTube |
|--------------|---------------|---------|
| Homepage     | 80+           | 40+     |
| Resume       | 43            | 72      |

A hiring manager who looks at both will flag this. It reads as careless. Pick the accurate current numbers and sync them everywhere.

### 2. No tool-specific buzzwords on the homepage

The blue-team card says "Splunk & Elastic" but SOC L1 job postings are ctrl+f'd for:
- `KQL` / `SPL` (Splunk query language)
- `Wireshark` / `NetworkMiner`
- `Volatility` (memory forensics)
- `VirusTotal`, `AbuseIPDB`, `Shodan` (threat intel)
- `Microsoft Sentinel` / `Defender for Endpoint` / `CrowdStrike`

Even adding 3-4 tool names to the homepage bullets would help pass resume screening.

### 3. TryHackMe SAL1 missing from homepage cert strip

It's on the resume but not in the cert pills. `SAL1` literally stands for *SOC Analyst Level 1* — the single most name-matched cert to the target role title. It should be visible without needing to open the resume.

### 4. Homepage has no investigation quality signal

The showcase rows on `/blue-team/` are good, but they require a click. A hiring manager landing on the homepage sees "80+ investigations" (quantity) but no taste of what an actual investigation looks like. Even a single 3-4 line excerpt with a "read full writeup →" link on the homepage would bridge this. Optional — the nav link and CTA button are prominent — but worth considering.

### 5. Red team card — intentionally subdued (keep as-is)

The secondary, muted treatment of the red team card is deliberate and correct. Leading with offensive experience can cause HR screeners to flag the profile, or make hiring managers assume you'll get bored in a defensive role. The card is there for technical managers who will appreciate it, without pushing it at people who won't.

The better lever is the resume summary, which already frames it well: "attacker-behaviour context that directly enhances detection accuracy." Keep that framing — let the blue team work lead, and let the offensive background explain itself in one sentence.

### 6. Resume dark theme print risk

The resume has `@media print` CSS but many ATS systems and recruiters print PDFs or convert to grayscale. The dark background may print as a solid black page depending on browser/printer settings. Test `Ctrl+P` in Chrome. A secondary light-mode PDF export would be a useful safety net.

---

## Nice-to-Have Additions

- **Python/scripting mention** — even basic automation scripts for IOC enrichment signals analytical maturity. Many SOC L1 JDs list "basic Python" as preferred.
- **Ticketing system mention** — ServiceNow or Jira appear in nearly every SOC L1 job description. Even "familiar with ITSM workflows" on the resume covers it.

---

## Priority Order

1. Fix the numbers inconsistency (resume vs homepage)
2. Add SAL1 to the cert strip
3. Add specific tool names to homepage bullets (KQL, SPL, Wireshark, Volatility, Sentinel)
4. Test and fix the resume print output
5. (Optional) Surface one investigation excerpt on the homepage
