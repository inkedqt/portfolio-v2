---
layout: lab
title: Squid Game
platform: BTLO
difficulty: Medium
category: Threat Intelligence
skill: Threat Intelligence
tools: "[Google, Steghide, Stegsolve.jar, Python]"
tactics: Credential Access, Collection
proof: https://blueteamlabs.online/achievement/share/challenge/144656/33
challenge_url: https://blueteamlabs.online/home/challenge/squid-game-12b0862d18
permalink: /blue-team/labs/squidgame/
summary: '"Will you survive the Squid Games?"'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/6c1aab7ad9ef3f74d5b632d02bc43ad5c35e46ba.png
type: challenge
points: "20"
---
## Overview

A steganography challenge themed around the Squid Game universe. The investigation chain involves Google dorking to retrieve an invite code, using that code to extract a hidden file via steghide, then analysing the extracted image through stegsolve to locate a hidden pixel — ultimately decoding the final flag from extracted RGB values.

---

## Investigation

### Reconnaissance — Google Dorking

The challenge hints that steghide and stegsolve are required tools. Before touching either, a Google dork against the invitation card reveals the embedded phone number:

**Phone number:** `8650 4006`

This doubles as the steghide passphrase for the next stage.
![[squid_dork.png]]

---

### Steghide Extraction

Install steghide if not already available: `sudo apt install steghide`

![[squid_steghide.png]]
Using the phone number as the passphrase against the invitation card image extracts a hidden file: **Extracted file:** `Dalgona.png`

---
### Stegsolve 
Analysis Opening `Dalgona.png` in stegsolve.jar (available at [github.com/Giotino/stegsolve](https://github.com/Giotino/stegsolve/releases)) and cycling through colour plane filters reveals the hint embedded in the image: 
![[squid_stegsolve.png]]
**Hint:** `red pixel`
![[squid_pixel.png]]

---
### Pixel Analysis— pixspy.com 
Following the red pixel hint, the image is uploaded to pixspy.com to extract the red channel RGB values.
![[squid_pixspy.png]]
Pulling just the R values produces the following decimal sequence:
![[squid_r_codes.png]]
```zsh
123, 102, 124, 173, 123, 64, 166, 63, 137, 115, 171, 64, 156, 155, 64, 162, 137, 107, 165, 171, 65, 175
```

### Decoding — dcode.fr

The decimal sequence is submitted to dcode.fr using ASCII decode, which converts the red channel values to the final flag:

**Flag:** `SBT{S4v3_My4nm4r_Guy5}`
![[squid_dcode_fr.png]]
![[squid_ascii.png]]

## MITRE ATT&CK

Not applicable — CTF steganography challenge.

---

## Lessons Learned

Steganography challenges follow a predictable chain — recon for credentials, extract hidden data, analyse the output, decode. Google dorking as the first step is an underutilised OSINT technique for surface-level recon. The red channel pixel extraction via pixspy is a useful tool to have in the toolkit for future stego work. dcode.fr remains the go-to for rapid cipher and encoding identification when the encoding type is unknown.

---

{% include flag.html question="What is the phone number on the invitation card in Squid Game? " answer="86504006" %}

{% include answer.html question="Can you extract something from the invitation card file? What is the name of the file? " answer="Dalgona.png" %}

{% include flag.html question="What hint text can be discovered in the final file? " answer="red pixel" %}

{% include answer.html question="What is the final flag?" answer="SBT{S4v3_My4nm4r_Guy5}" %}
