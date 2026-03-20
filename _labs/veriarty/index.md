---
layout: lab
title: Veriarty
platform: BTLO
difficulty: Medium
category: Threat Intelligence
skill: Threat Intelligence
tools: "[hashcat, veracrypt, gpp]"
tactics:
mitre: "[T1027, T1027.003, T1140, T1553, T1560, T1564.001, T1573]"
proof: https://blueteamlabs.online/achievement/share/challenge/144656/36
challenge_url: https://blueteamlabs.online/home/challenge/veriarty-81c20f947f
permalink: /blue-team/labs/veriarty/
summary: '"DI Lestrade has intercepted a transmission from a criminal known as Moriarty"'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/b17fa3b4085a6dc90f61c050a7f0326df12c3a21.png
type: challenge
points:
youtube:
locked: tate
---
## Overview

DI Lestrade has intercepted a transmission from a criminal known as Moriarty and needs help decoding it. This is one of the most layered and creative challenges on BTLO — it chains together VeraCrypt, PGP, email analysis, ROT47, Base64, ASCII85, a VeraCrypt hidden volume with a keyfile, steganography, and Braille. Every answer is locked behind the next puzzle.

---

## Investigation

### Cracking the VeraCrypt Container

The evidence includes a `container.vc` file. VeraCrypt containers are encrypted volumes that look like random data from the outside — no headers, no signature. The first job is cracking the password using hashcat with mode `13751` (VeraCrypt SHA-512 + AES):

```bash
hashcat -m 13751 -a 0 container.vc wordlist
```

The password cracks quickly: **`jamie`**. Mounting the container in VeraCrypt reveals two files inside the outer volume — `secret.key` and `email.eml.gpg`.![](veriarty_hashcat.png)


---

### PGP Key and Encrypted Email

The evidence folder also contains `secret.key` (a PGP private key belonging to James Moriarty) and `email.eml.gpg`. Importing the key and decrypting the email:


<details class="code-block">
  <summary>pgp key</summary>
  <pre><code>-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=fmof
-----END PGP PRIVATE KEY BLOCK-----</code></pre>
</details>


```bash
gpg --import secret.key
gpg --decrypt email.eml.gpg > email.eml
```

The decrypted email comes from `pokdyk+5r9ofvxtmjh4w@guerrillamail[.]com` to `ytrairom@gmail[.]com` with the subject **"47-64"** and an originating IP of `90[.]255[.]27[.]89`. The body is a mess of quoted-printable encoded ciphertext.


<details class="code-block">
  <summary>decoded email</summary>
  <pre><code>Delivered-To: ytrairom@gmail.com
Received: by 2002:ab0:670c:0:0:0:0:0 with SMTP id q12csp882698uam;
        Tue, 19 Oct 2021 10:44:13 -0700 (PDT)
X-Google-Smtp-Source: ABdhPJzuw93pmfmSXcLonr5ino7tRJQquxRNs0Gf5qHaK2Lekv7+XemWjXe6wZXS4jfs60OOQQf5
X-Received: by 2002:a1c:2043:: with SMTP id g64mr2419232wmg.123.1634665452923;
        Tue, 19 Oct 2021 10:44:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634665452; cv=none;
        d=google.com; s=arc-20160816;
        b=EfRZ4BouLCvWhGxIpVuv/NuewAyPVPcd98HiLVZ9YC6IBKgpJTI3VZ54mRwh26SPJx
         nV60ea72igPc/EZ2x6Rnpf/romJ0Cw/033wZ/VTiIjAfw3IOzqqoBNHKpTvOkAewRBrY
         SJptM0JIftgw4D95MMa5OiJREi0VDXL9A7qj59ZO9FgRO+zTirc2kDZFXjf3uSTOU2GM
         v5fLQ1hTubkhqPFm0woFby7gRI/p1qr8RuVVre2Ie8Q0B1BGzOQZRgL+iN55IgJuB1al
         H66rQfxWQ0H2a+dtxZ69tztFLs9Uw7wQKf30TXcMj/HgSzt346CjLgwOqlBkhSRCJvbP
         pGkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=dkim-signature:content-transfer-encoding:subject:from:to:date
         :message-id:mime-version;
        bh=ddP9H+42B8wBu/Ujjpr6pzh87J5Km0kvPF6iDXcTdqI=;
        b=tEYT4C2jDWNLIIZDqSR29Twn9IPDeLREdBpNaHM40v0mPE51qfN5vue5VdtqiYtBau
         DRy6SN+fimx9BrbLjYAyfn8hpK/LQ+dsWHI/ilMdIsrinD5ChCKLolfcpkYwDp2/YNY6
         pLUgtTKuNo+rcpppwjxzY4HPwdUQ+g/5HMqGGR8Le1Qw4kDFe/QuUtZp5lYXFIYm3FgQ
         5zUp2rJcv+g3SPUmF08Fcfy1s58wJlIIBfZDFQLaHmLSwLD7iLwSNSDNM0XpgzR4+tOO
         d/JGr+7OdHALnQ5449kjreF8iCkkvCtW/Bxyxe/6i5l4k6JOU5uB4HS7DcbVmdw24Z8b
         c4PQ==
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@guerrillamail.com header.s=highgrade header.b=Bb5Wr2h+;
       spf=pass (google.com: domain of pokdyk+5r9ofvxtmjh4w@guerrillamail.com designates 2a01:4f8:251:657::2 as permitted sender) smtp.mailfrom=pokdyk+5r9ofvxtmjh4w@guerrillamail.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=guerrillamail.com
Return-Path: &lt;pokdyk+5r9ofvxtmjh4w@guerrillamail.com&gt;
Received: from mail.guerrillamail.com (mail.guerrillamail.com. [2a01:4f8:251:657::2])
        by mx.google.com with ESMTPS id y13si1388170wry.75.2021.10.19.10.44.12
        for &lt;ytrairom@gmail.com&gt;
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Oct 2021 10:44:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of pokdyk+5r9ofvxtmjh4w@guerrillamail.com designates 2a01:4f8:251:657::2 as permitted sender) client-ip=2a01:4f8:251:657::2;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@guerrillamail.com header.s=highgrade header.b=Bb5Wr2h+;
       spf=pass (google.com: domain of pokdyk+5r9ofvxtmjh4w@guerrillamail.com designates 2a01:4f8:251:657::2 as permitted sender) smtp.mailfrom=pokdyk+5r9ofvxtmjh4w@guerrillamail.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=guerrillamail.com
Received: by 168.119.142.36 with HTTP; Tue, 19 Oct 2021 17:44:11 +0000
MIME-Version: 1.0
Message-ID: &lt;93624b0c4b500d3602bd59e31a6e508c121@guerrillamail.com&gt;
Date: Tue, 19 Oct 2021 17:44:11 +0000
To: "ytrairom@gmail.com" &lt;ytrairom@gmail.com&gt;
From: &lt;pokdyk+5r9ofvxtmjh4w@guerrillamail.com&gt;
Subject: 47-64
X-Originating-IP: [90.255.27.89]
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable
X-Domain-Signer: PHP mailDomainSigner 0.2-20110415 &lt;http://code.google.com/p/php-mail-domain-signer/&gt;
DKIM-Signature: v=1; a=rsa-sha256; s=highgrade; d=guerrillamail.com; l=356;
	t=1634665452; c=relaxed/relaxed; h=to:from:subject;
	bh=ddP9H+42B8wBu/Ujjpr6pzh87J5Km0kvPF6iDXcTdqI=;
	b=Bb5Wr2h+KYNo61hshUn/kC4d6j2oNkntO6isE6b5OpGkyBRAFGCnJlwevS4dgA2ovv/06OT2+p+y
	wWwKBuc+6d/MTXkSyeuaCeGg1Rr1c0e7mfL4vEmqc9FqVTz2BNwhg3bUJfRPlFn492ok8Unckjl5
	2nbUqTMRv3ce5NV7vK0dfaoO4ml0fzrGUcuetrb3k3Es+hOhmZl8ledg1BNn1TyRd2yn8+bJumwN
	uo6rAweTgpDO/mHHfb2xmX+8Gey5ytr+S8YxSDhn5Q6V/Buce6bGk7nPtgHLzKawjvTPUMquS3/h
	2EUqqPLiTa+U3bLdW67TCtruo9Vdr7nLDMtQYw==

")9=3D3rq(2)+a2(uF{pA)+$qF+('&lt;xw#Gxv`=3D+)"85vg8+v=3DK*b'K4Jq_2v&84vI93?|Fx=
t`=3D+)"83(&8*)"8$a'D5&gt;'&lt;3ac8$vu_*a88&a';4&gt;'_xtd`*aI=3D*)x8"?'F2a'J{rqs%%t_=
xs'&%rq95rpI|;@H|rczr&lt;`G4&gt;=3D94?#d=0A=0A=0A=0A=0A=0A----=0ASent using Guerr=
illamail.com=0ABlock or report abuse: https://www.guerrillamail.com//abuse/=
?a=3DVkh6ARRTE%2BREqAm58XcTPBfIQA%3D%3D=0A</code></pre>
</details>


---

### Decoding the Email Body — ROT47

The subject line `47-64` is the hint. The email body is quoted-printable encoded first, then ROT47 encoded. In CyberChef:
```
From Quoted Printable → ROT47
```

This produces a base64 string. Decoding that reveals the decoy message:
```
Axel Vivvian,
We need to meet to discuss the plans. Meet me at Kelvedon Hatch Secret 
Nuclear Bunker, CM14 5TL at 12:00.

Moriarty
```

This looks like the answer — but nothing here gets accepted. This is the **plausible deniability** layer. The Axel message is a decoy designed to fool investigators. The real intelligence is hidden deeper.![](ver_cyberchef.png)

---

### VeraCrypt Hidden Volume — Keyfile

VeraCrypt supports a two-password model called **plausible deniability**. One password mounts an outer volume with innocent-looking content. A second password (and optionally a keyfile) mounts a completely separate hidden volume inside the same container — undetectable without the correct credentials.

The key insight: use `secret.key` as a **keyfile** when mounting. In VeraCrypt:
```
Mount → Select container.vc → Use keyfiles → Add secret.key → Password: jamie
```

A hidden volume mounts successfully, revealing a folder with new files including `Decode Me.jpg` and a hidden directory.
![](ver_hidden_mount.png)

---

### POA.txt — ASCII85

The `POA.txt` from the hidden volume is addressed to **Vera**:
```
Vera,
If you're reading this message, then you know how to find the 
information about our next meeting.

1bg+2AKWlf+>PVn2E;m<...

Moriarty
```

The body is ASCII85 encoded — identifiable by the `+>` character pairs. Decoding in CyberChef:
```
From ASCII85
```

The decoded message reads:
```
And if you're reading this my dear Holmes, then good luck to you. I look 
forward to seeing you and your little sidekick gatecrashing our meeting. 
But know this, I am well prepared for your arrival.
````
![](ver_base85_hex.png)
Moriarty knew someone might get this far. Classic.

---

### Hidden volume
![](ver_hidden_folder.png)
Inside the hidden volume's folder is the meeting location image — **Central Perk, Piccadilly Circus**.![](ver_central_perk.png)
![](cer_meeting_spot2.png)

---

### Braille — Time of Meeting - Decode Me.jpg

The final file is an image titled "Time Of Meeting" showing a grid of red and grey circles arranged in Braille cell patterns. Red = filled dot, grey = empty dot. Reading the Braille from the image gives the meeting time: **5th November, 16:05**.
![](ver_meeting_time.png)

---

## The Full Chain
```
container.vc (hashcat -m 13751)
    └── Outer volume password: jamie
        ├── POA.txt        → decoy / ASCII85 troll message to Holmes
        └── Decode Me.jpg  → steg → meeting location (outer layer)

    └── Hidden volume (password: keyfile: secret.key)
        ├── Hidden folder
        │   ├── Central Perk image  → Q4 meeting location
        │   └── Braille time image  → Q5 meeting time

email.eml.gpg (gpg --import secret.key → decrypt)
    └── From: pokdyk (Vera's alias)
    └── Body: Quoted Printable → ROT47 → Base64 → Axel decoy message
````

---

## IOCs

|Type|Value|
|---|---|
|Email|`pokdyk+5r9ofvxtmjh4w@guerrillamail[.]com`|
|Email|`ytrairom@gmail[.]com`|
|IP|`90[.]255[.]27[.]89`|
|PGP UID|`James Moriarty <jim@moriarty-inc[.]com>`|
|Key ID|`B5B72AEC14C55EE5`|

---

<div class="qa-item"> <div class="qa-question-text">#1) What is the hash type (-m flag) used by hashcat to crack the password? (Format: Hash Type Number)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">13751</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">#2) What is the password to unlock the container?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">jamie</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">#3) What is the name of Moriaty's general sending the email</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">vera</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">#4) Where is the meeting supposed to be taking place?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">central perk, piccadilly circus</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">#5) When is the meeting supposed to be taking place?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">5th November, 16:05</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>
