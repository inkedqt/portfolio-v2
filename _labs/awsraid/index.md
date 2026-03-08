---
layout: lab
title: AWSRaid
platform: CyberDefenders
difficulty: Easy
category: Cloud Forensics
skill: Cloud Forensics
tools: "[Splunk]"
tactics: "[Persistence, Privilege Escalation, Credential Access]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/awsraid/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/awsraid/
permalink: /blue-team/labs/awsraid/
summary: '"Investigate AWS CloudTrail logs using Splunk to identify unauthorized access, analyze configuration changes, and detect persistence mechanisms."'
art: https://cyberdefenders.org/media/terraform/AWSRaid/AWSRaid.webp
---
## CCD — AWSRaid

**Platform:** CCD | **Difficulty:** Easy | **Category:** Cloud Forensics / AWS / Threat Hunting

---

## Overview

A security incident was reported within an AWS-hosted environment involving unauthorized access and potential data exfiltration. The investigation uses AWS CloudTrail logs ingested into Splunk to trace the attacker's activity from initial access through persistence establishment.

---

## Environment

|Field|Value|
|---|---|
|Log Source|AWS CloudTrail|
|SIEM|Splunk|
|Compromised Account|`helpdesk.luke`|

## Analysis

### Initial Access — Compromised Account

Querying CloudTrail for `CreateLoginProfile` events revealed the attacker's entry point — a login profile was created for an existing IAM user, granting console access to a previously programmatic-only account:

```
index=* eventName=CreateLoginProfile
```

The compromised account identified was `helpdesk.luke`.
![[aws_luke.png]]
### S3 Data Access — First Exfiltration Attempt

With the compromised account established, the attacker began accessing S3 objects. Querying for `GetObject` events under `helpdesk.luke` and converting the earliest epoch timestamp:

```bash
index=* "userIdentity.userName"="helpdesk.luke" eventName=GetObject 
 | stats min(_time) as first_access_timestamp
```
Epoch `1698918953` converts to **2023-11-02 09:55 UTC** — the first confirmed S3 access.

Expanding the query to show full bucket and key details revealed the specific objects accessed:

```bash
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject" | table _time, eventName, requestParameters.bucketName, requestParameters.key
```

![[aws_bucket.png]]
Among the buckets accessed, `product-designs-repository31183937` contained a DWG file — engineering/design intellectual property, a high-value exfiltration target.

### Bucket Misconfiguration — Public Access Enabled

The attacker also modified bucket access controls to enable public access, effectively staging data for exfiltration without needing authenticated requests:
```bash
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventName=PutBucketPublicAccessBlock | stats count by requestParameters.bucketName
```

![[aws_change_bucket.png]]
The bucket `backup-and-restore98825501` had its public access block removed — a significant security misconfiguration introduced deliberately by the attacker.

### Persistence — New IAM User Created

To maintain access beyond the compromised `helpdesk.luke` account, the attacker created a new IAM user and login profile:

```bash
`index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventCategory="Management" | search eventName="CreateUser" OR eventName="CreateLoginProfile"| table _time, eventName, requestParameters.userName`
```
![[aws_marketingmark.png]]
The newly created account was `marketing.mark` — a low-suspicion username designed to blend in with legitimate users.

### Privilege Escalation — Admin Group Membership

The backdoor account was immediately added to a privileged group to ensure full administrative access:

```bash
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventName=AddUserToGroup | stats count by requestParameters.groupName
```

![[aws_admin_group.png]]
`marketing.mark` was added to the `Admins` group — granting full AWS environment control through the persistence account.

## Attack Chain  
CreateLoginProfile on helpdesk.luke 
	↓ 
S3 GetObject — product-designs-repository31183937 (DWG file exfiltrated)
	↓ 
PutBucketPublicAccessBlock removed — backup-and-restore98825501 staged for public access 
	↓ 
CreateUser + CreateLoginProfile — marketing.mark created 
	↓ 
AddUserToGroup — marketing.mark added to Admins

## IOCs 

| Type                  | Value                                |
| --------------------- | ------------------------------------ |
| Compromised IAM user  | `helpdesk.luke`                      |
| Backdoor IAM user     | `marketing.mark`                     |
| Targeted bucket (DWG) | `product-designs-repository31183937` |
| Misconfigured bucket  | `backup-and-restore98825501`         |
| Privilege group       | `Admins                              |
| First S3 access       | `2023-11-02 09:55 UTC`               |

## MITRE ATT&CK

|Technique|ID|
|---|---|
|Valid Accounts: Cloud Accounts|T1078.004|
|Data from Cloud Storage|T1530|
|Exfiltration to Cloud Storage|T1567.002|
|Create Account: Cloud Account|T1136.003|
|Account Manipulation|T1098|
|Modify Cloud Compute Configurations|T1578|

---

## Key Takeaway

This investigation demonstrates a textbook cloud account compromise chain — initial access via IAM credential abuse, rapid data access and staging, followed by persistence through a backdoor account with elevated privileges. The `CreateLoginProfile` event is a high-fidelity detection opportunity as it grants console access to accounts that previously had none, and is rarely a legitimate administrative action on existing user accounts.

---

{% include flag.html question="Knowing which user account was compromised is essential for understanding the attacker's initial entry point into the environment. What is the username of the compromised user?" answer="helpdesk.luke" %}

{% include answer.html question="We must investigate the events following the initial compromise to understand the attacker's motives. What is the timestamp for the first access to an S3 object by the attacker?" answer="2023-11-02 09:55" %}

{% include flag.html question="Among the S3 buckets accessed by the attacker, one contains a DWG file. What is the name of this bucket?" answer="product-designs-repository31183937" %}

{% include answer.html question="We've identified changes to a bucket's configuration that allowed public access, a significant security concern. What is the name of this particular S3 bucket?" answer="backup-and-restore98825501" %}

{% include flag.html question="Creating a new user account is a common tactic attackers use to establish persistence in a compromised environment. What is the username of the account created by the attacker?" answer="marketing.mark" %}

{% include answer.html question="Following account creation, the attacker added the account to a specific group. What is the name of the group to which the account was added?" answer="Admins" %}

