---
layout: lab
title: Spilled Bucket
platform: BTLO
difficulty: Easy
category: Cloud Forensics
skill: Cloud Forensics
tools: "[Splunk]"
tactics:
mitre: "[T1651, T1580, T1098.003]"
proof: https://blueteamlabs.online/achievement/share/144656/232
challenge_url: https://blueteamlabs.online/home/investigation/spilled-bucket-21784640e3
permalink: /blue-team/labs/spilledbucket/
summary: '"The attackers were successful in attacking and gaining access to their cloud infrastructure. Can you help them out?"'
art: https://blueteamlabs.online/storage/labs/bf54d9e7f7017a8b512a95b62a9627c91e3a3bf1.png
type:
points:
youtube:
locked: tate
---
## Scenario

An Australian-based company recently migrated from on-premise to AWS Cloud infrastructure. During the migration, several misconfigurations were introduced that a threat actor group leveraged to gain full access to their environment. The company has no IR team and manages their cloud exclusively via browser — no CLI was configured. We're provided with AWS CloudTrail and VPC Flow Logs ingested into Splunk to reconstruct the full attack chain.

> **Note:** The `_time` field in Splunk reflects when logs were ingested into Splunk, not when events occurred. All timestamps referenced here use `eventTime` (CloudTrail) and `start`/`end` (VPC Flow Logs).

---

## Investigation

### Initial Access — S3 Bucket Exposure

The investigation begins with CloudTrail, querying for S3 `GetObject` events to identify what was accessed and by whom:

```bash
index=* eventSource="s3.amazonaws.com" eventName="GetObject"
| table eventTime, sourceIPAddress, requestParameters.bucketName, requestParameters.key, userAgent
```

Two source IPs appear in the results — `103[.]108[.]229[.]19` and `18[.]216[.]138[.]52`. Filtering on `18[.]216[.]138[.]52` reveals the attacker accessed the `developers-configuration` bucket and downloaded `VPN-Profiles/DevelopersProfile_wg0.conf`. A WireGuard VPN configuration file contains private keys and peer endpoints — effectively handing the attacker direct network-level access into the VPC. This is the root cause of the entire compromise: a sensitive credential file sitting in a misconfigured, publicly accessible S3 bucket.

---

### OPSEC Failure — Attacker Real IP Leaked

With a valid WireGuard config in hand, the attacker connected directly into the VPC. WireGuard operates on UDP port 51820, so the VPC Flow Logs capture the handshake:

```bash
index=* dstport=51820
| table start, srcaddr, dstaddr, dstport, protocol
| sort start
```

The connection originates from `122[.]161[.]49[.]105` — notably different from the S3 attacker IP. One of the threat actors made an OPSEC error, connecting via their personal machine rather than routing through their usual anonymising infrastructure. This leaks their real IP address. The WireGuard endpoint they connected to maps to EC2 instance with private IP `10[.]0[.]1[.]125`.

---

### Privilege Escalation — EC2 Instance Role Abuse

From inside the EC2 instance, the attacker enumerated the AWS environment using the instance's attached IAM role via the Instance Metadata Service (IMDS). CloudTrail logs `AssumeRole` calls, but filtering these is noisy due to AWS internal services constantly assuming roles. Excluding the service noise:

```bash
index=* eventName="AssumeRole" sourceIPAddress!="resource-explorer-2.amazonaws.com"
| table eventTime, sourceIPAddress, requestParameters.roleArn
| sort eventTime
```

![](spilled_assumerole.png)

The results show `ec2.amazonaws.com` as the source — the EC2 instance itself assuming its attached role, which is exactly how IMDS credential abuse appears in CloudTrail. Expanding the raw event confirms the full role ARN:
![](spilled_arn.png)

The role `arn:aws:iam::764581110688:role/ec2-role` is assumed, with the session name set to the instance ID `i-00eda415438b3d90c` and temporary credentials issued with access key `ASIA3EBEV4OQLCERBWSP`. The attacker now has IAM permissions to operate across the AWS environment.

---

### Persistence — Rogue IAM User Creation

Armed with the `ec2-role` credentials, the attacker pivots to IAM to establish persistence. Searching CloudTrail for IAM write events tied to the compromised instance:

```bash
index=* eventSource="iam.amazonaws.com" "i-00eda415438b3d90c"
| table eventTime, eventName, requestParameters
| sort eventTime
```

The first page of results is pure enumeration — `ListUsers`, `GetUser`, `ListAttachedUserPolicies`, `ListRoles`, and so on. The attacker is thoroughly mapping out the IAM landscape before acting. Scrolling to page two, the write actions appear:
![](spilled_persistance.png)

The persistence chain executes in three steps — `CreateUser` at `11:10:59Z`, `CreateAccessKey` at `11:11:10Z`, and `AttachUserPolicy` at `11:11:22Z`. Expanding the `CreateUser` event reveals the new identity:
![](spilled_usercreated.png)

The rogue user `web_engg_2` is created, blending in with what appears to be an existing naming convention for engineering accounts. The `AttachUserPolicy` event confirms what was granted:
![](spilled_admin.png)

The policy `arn:aws:iam::aws:policy/AdministratorAccess` is attached — full, unrestricted access to the entire AWS account. The attacker now has a persistent backdoor IAM user with programmatic access keys that survives even if the EC2 instance is terminated.

---

### Lateral Movement — SSH to Second EC2

With `AdministratorAccess` and knowledge of the internal network layout from the enumeration phase, the attacker moves laterally. Checking VPC Flow Logs for SSH connections:

```bash
index=* dstport=22
| table start, srcaddr, dstaddr, dstport
| sort start
```

![](spilled_ssh_ip.png)

The source IP `3[.]26[.]170[.]141` — the public IP of EC2-1 (`10[.]0[.]1[.]125`) — is used as a jump host to SSH into a second instance at private IP `10[.]0[.]2[.]32`. The attacker is pivoting deeper into the network using the initially compromised instance as a launchpad.

---

### Impact — Reverse Shell Established

From the second EC2 instance, the attacker establishes a reverse shell for interactive C2 access. Filtering VPC Flow Logs for outbound TCP connections from `10[.]0[.]2[.]32`:

```bash
index=* srcaddr="10.0.2.32" protocol=6
| stats count by dstaddr, dstport
| sort -count
```

The vast majority of traffic is port 443 HTTPS — legitimate AWS service communication. Port 123 UDP (NTP) is also noise. The standout entry is two connections to `3[.]15[.]209[.]50` on port `13337` — a deliberate leet-speak port choice that immediately flags as attacker infrastructure. The low connection count is consistent with a reverse shell initiation rather than sustained polling. Notably, `3[.]15[.]209[.]50` also appeared in the SSH lateral movement traffic, confirming this is the attacker's C2 server.
![](spilled_revshell.png)

---

## Attack Chain Summary
```
S3 Misconfiguration (developers-configuration bucket public)
  → WireGuard config downloaded (DevelopersProfile_wg0.conf)
    → Attacker VPN into VPC (OPSEC fail: real IP 122[.]161[.]49[.]105 leaked)
      → EC2-1 (10[.]0[.]1[.]125) accessed via WireGuard
        → IMDS abuse → ec2-role assumed (arn:aws:iam::764581110688:role/ec2-role)
          → IAM enumeration → rogue user web_engg_2 created with AdministratorAccess
            → SSH pivot from EC2-1 to EC2-2 (10[.]0[.]2[.]32)
              → Reverse shell → 3[.]15[.]209[.]50:13337
````

---

## IOCs

|Type|Value|
|---|---|
|IP — Initial S3 Attacker|`18[.]216[.]138[.]52`|
|IP — Attacker Real IP (OPSEC fail)|`122[.]161[.]49[.]105`|
|IP — C2 / Reverse Shell|`3[.]15[.]209[.]50`|
|S3 Bucket|`developers-configuration`|
|File|`VPN-Profiles/DevelopersProfile_wg0.conf`|
|IAM Role ARN|`arn:aws:iam::764581110688:role/ec2-role`|
|IAM User|`web_engg_2`|
|Policy ARN|`arn:aws:iam::aws:policy/AdministratorAccess`|
|EC2 Private IP — Initial|`10[.]0[.]1[.]125`|
|EC2 Private IP — Lateral|`10[.]0[.]2[.]32`|
|Port — Reverse Shell|`13337`|



---

<div class="qa-item"> <div class="qa-question-text">Which S3 bucket's object was accessed by the attacker?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">18[.]216[.]138[.]52</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What was the attacker IP associated in S3 access? [Provide the defanged IP]</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">developers-configuration</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What object/file did the attacker then access/download that would allow access to their environment?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">DevelopersProfile_wg0.conf</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Based on the previous question, what is the software associated with the file? Provide the name of the software used for such type of files.</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">wireguard</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Using the previously mentioned file, one of the attackers accidentally connected via main system leading to his IP address getting leaked. What is the IP address of the Attacker?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">122[.]161[.]49[.]105</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What was the Private IP of the EC2 instance to which the attacker connected?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">10.0.1.125</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">The attacker performed further enumeration while being inside the EC2 instance and found a role that could be used further by assuming it. What was the ARN of the role?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">arn:aws:iam::764581110688:role/ec2-role</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Using the role Attacker targeted IAM to achieve persistence in the environment. Provide the APIs used for it in order of its usage.</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">CreateUser, CreateAccessKey, AttachUserPolicy</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Provide the name of the IAM Identity created during Persistence.</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">web_engg_2</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What policy was attached to the Identity later? Provide the policy ARN.</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">arn:aws:iam::aws:policy/AdministratorAccess</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Another EC2 instance was found to be accessed by the Attacker using SSH. Find its Private IP Address</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">10.0.2.32</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">From the above EC2 instance, attacker then created a reverse shell. Find the Reverse Shell IP & port.</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">3[.]15[.]209[.]50, 13337</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>


