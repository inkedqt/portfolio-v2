# BEC-KY BTLO Investigation Summary  

## Investigation Overview  

| Step | Objective | Key Findings | Evidence |
|------|----------|--------------|----------|
| **1 – Identify the initial phishing source** | Locate the malicious email that started the compromise. | Suspicious sender: **sabastian@flanaganspensions.co.uk** – look-alike phishing domain. | Email headers & message details |
| **2 – Determine the type of compromise** | Classify the attack vector. | **Business Email Compromise (BEC)** – attacker used valid credentials to send fraudulent transfers. | No malware observed; activity originated from CFO mailbox |
| **3 – Trace attacker IPs** | Identify unauthorized sign-in sources. | **159.203.17.81** and **95.181.232.30** – anomalous geo-locations aligned with transaction timing. | Azure AD sign-in logs filtered for victim (Becky) |
| **4 – Identify the destination bank** | Determine where funds were transferred. | **First Bank of Nigeria Ltd.** (SWIFT: **FBNINGLA**) | SWIFT code found in compromised email threads |
| **5 – Detect inbox folder creation** | Check for persistence or activity hiding mechanisms. | Folder named **"History"** created via inbox rule. | Azure audit log showing `"MoveToFolder"` event |
| **6 – Analyse malicious rule keyword** | Understand filtering behavior. | Rule deleted emails containing **"Withdrawal"** | Rule log: `SubjectOrBodyContainsWords="Withdrawal"`; `DeleteMessage=True` |

---

## 🔍 Attack Narrative  

1. A **phishing email** from a spoofed domain tricks Becky into interacting.  
2. The attacker **compromises the CFO mailbox** and initiates legitimate-looking bank transfers (classic BEC behavior).  
3. **Azure sign-in logs** reveal two suspicious IP addresses:  
   - `159.203.17.81`  
   - `95.181.232.30`  
4. Transaction emails include SWIFT code **FBNINGLA**, linked to **First Bank of Nigeria Ltd.**  
5. The attacker creates a hidden folder called **"History"** using an inbox rule.  
6. A malicious rule automatically deletes emails containing **"Withdrawal"**, removing evidence of fraudulent activity.

---

## 🛡 Key Defensive Takeaways  

- Validate sender domains carefully (watch for subtle misspellings).  
- Monitor Azure AD sign-in anomalies (geo-location & time deviations).  
- Audit mailbox rules regularly — unexpected folder creation or delete actions are red flags.  
- Verify SWIFT codes in financial email communications.  
- Enforce **Multi-Factor Authentication (MFA)** for executive accounts.  
- Apply **least privilege access** to high-value mailboxes (e.g., CFO).

---

## 🎯 MITRE ATT&CK Mapping  

- **T1566.002** – Phishing: Spearphishing Link  
- **T1078** – Valid Accounts  
- **T1114** – Email Collection  
- **T1564.008** – Hide Artifacts: Email Hiding Rules  
- **T1647** – Financial Theft  

