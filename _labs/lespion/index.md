---
layout: lab
title: Lespion Lab
platform: CyberDefenders
difficulty: Easy
category: Threat Intel
tools: Wireshark
tactics: "[Google Maps, Google Image search, Sherlock]"
proof: https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/lespion/
challenge_url: https://cyberdefenders.org/blueteam-ctf-challenges/lespion/
permalink: /blue-team/labs/lespion/
summary: '"Investigated an insider breach using GitHub analysis and OSINT pivoting to uncover exposed credentials, crypto-mining activity, and geolocation evidence."'
art: https://cyberdefenders.org/media/terraform/Lespion/Lespion.webp
---
# Lespion – Insider Investigation

## Scenario

A client’s internal network was compromised and taken offline. Initial forensic findings suggest the breach originated from a single internal user account, likely an insider.

Your task is to identify the insider and reconstruct their actions using available digital artifacts and open-source intelligence.

---

## Initial Lead – GitHub Artifact

The investigation begins with the file `Github.txt`, which points to a public GitHub profile:

[https://github.com/EMarseille99](https://github.com/EMarseille99)

Reviewing the account shows one non-forked repository:

Project-Build---Custom-Login-Page

Inside the repository, sensitive data was exposed.

### Exposed API Key

The insider committed a plaintext API key:

aJFRaLHjMXvYZgLPwiJkroYLGRkNBW

This immediately confirms operational security failure and possible credential misuse.

---

## Credential Exposure

Within the same repository, a Base64 encoded password was discovered:

UGljYXNzb0JhZ3VldHRlOTk=

Decoding it:

echo "UGljYXNzb0JhZ3VldHRlOTk=" | base64 -d

Result:

PicassoBaguette99

This confirms the insider directly exposed usable credentials.

---

## Cryptocurrency Mining Activity

Further review of the GitHub profile revealed a forked repository for:

xmrig

XMRig is a known Monero cryptocurrency miner. This suggests possible resource abuse or crypto-mining experimentation.

This strengthens the insider threat hypothesis.

---

## Social Media Pivot

Using username enumeration and search engine dorking led to an Instagram account:

[https://www.instagram.com/emarseille99/?hl=en](https://www.instagram.com/emarseille99/?hl=en)

The Instagram profile contained additional intelligence:

- A QR code linking to a Steam account
    
- Travel photos
    
- Personal information revealing lifestyle details
    

---

## Travel Intelligence

Social media analysis revealed:

- The insider traveled to Singapore
    
- Their family resides in Dubai
    

This information becomes relevant when correlating potential motive and geographic movement.

---

## Geolocation – Office Image

The provided file office.jpg contained a visible street sign.

A quick Google Maps comparison identified the location as:

Birmingham, United Kingdom

This confirms the company’s office location.

---

## Surveillance Camera Pivot

The file Webcam.png was investigated by reverse searching the image title and matching it with EarthCam streams.

The camera location was identified as:

Notre Dame, Indiana

This confirms the state associated with the final movement of the person of interest.

## IOCs 


| Type | Value |
| ---- | ----- |
| office.jpg  | 9b65d6c4e1e10209b4c874e79549e00c |
| WebCam.png  | 21375b5626ba750d5ff393d9f6e719ec |
| Github      | https://github.com/EMarseille99  |
| API Key     | aJFRaLHjMXvYZgLPwiJkroYLGRkNBW   |
| Password    | PicassoBaguette99                |
| Mining Tool | xmrig                            |


## Conclusion

The investigation confirms:

- The insider exposed sensitive credentials publicly on GitHub
    
- They showed interest in cryptocurrency mining tools
    
- Their social media activity revealed identifiable personal and travel details
    
- Geolocation artifacts confirmed both corporate and surveillance locations
    

> This case highlights the risks of credential leakage, insider threat behavior, and the power of OSINT correlation in digital investigations.





---

I successfully completed Lespion Blue Team Lab at @CyberDefenders!
https://cyberdefenders.org/blueteam-ctf-challenges/achievements/inksec/lespion/
 
#CyberDefenders #CyberSecurity #BlueYard #BlueTeam #InfoSec #SOC #SOCAnalyst #DFIR #CCD #CyberDefender
