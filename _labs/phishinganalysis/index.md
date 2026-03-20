---
layout: lab
title: Phishing Analysis
platform: BTLO
difficulty: Easy
category: Security Operations
skill: "[Security Operations]"
tools: "[Text Editor, Thunderbird]"
tactics:
mitre: "[T1566.001, T1598.003, T1071.003]"
proof: https://blueteamlabs.online/achievement/share/challenge/144656/16
challenge_url: https://blueteamlabs.online/home/challenge/phishing-analysis-f92ef500ce
permalink: /blue-team/labs/phishinganalysis/
summary: '"Can you investigate the email and attachment to collect useful artifacts? "'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/dbcda50ac795a74ab7fa188aba2d18f724383d7b.png
type: challenge
points:
youtube:
locked: tate
---
## Overview

A user received a suspicious email and forwarded it to the SOC for investigation. The task is to analyse the email and its attachment to extract useful artefacts, trace the origin of the message, and identify the malicious URL embedded inside.

---


<details class="code-block">
  <summary>email source</summary>
  <pre><code>Website\ contact\ form\ submission.eml 
Delivered-To: johnsmith123@gmail.com
Received: by 2002:a0c:aa16:0:0:0:0:0 with SMTP id d22csp2828343qvb;
        Fri, 19 Mar 2021 09:49:20 -0700 (PDT)
X-Google-Smtp-Source: ABdhPJw6aSxYvWThdbRKONzsnCvhxRDdEr3hG0x1Okb6JQCf12+SFcsTRCmOGgXzJxsaz1W/04Ve
X-Received: by 2002:aa7:cd54:: with SMTP id v20mr10780856edw.80.1616172560336;
        Fri, 19 Mar 2021 09:49:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616172560; cv=pass;
        d=google.com; s=arc-20160816;
        b=kCZr16KOmbcxQ5hzDiTI2ksyThj1usdAC+9D+v2UuV8pOSEsONn8q6I9+0i1AO0krl
         zkezk4UXN1dDdWqGz84wV/FfOCoUxfUyYj+J2GlJVR0pdfibTkp3HXlZZRWxKuqL25uj
         WZrWJ1rIYz6y7YswX/TvFip2m6mTLRwHO0LfyrYyoEqHfaD8z7kgr0zZdg1UKpebXDBA
         k7JBCgmiajzjuq6Te8hCMMEe0gZ5HbMiuq5CHTjLjEzBzgQCR25UK3t81KFHK+qBOgS4
         53D6bgDKWtnn/qASJY8DgMf797MiCwTpt0U0oaxMPQcPfyTddLs2IOM3at073tGZl8nL
         UQBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:to
         :from;
        bh=4z4cDZlJjLvM3Bl1T3yMmEcXkORdJWZJkT0oHvxaEaU=;
        b=I2XYzTP8Rgx50buCZmkTig8x5PFs2Y+kLw5yXLtzkEgxd1iQgZkT2NHSe1+XbtMH8R
         LrsTJ/mjruUSefTRrJBv1TJdV0XuMla5icP0yLCviZmAQmWbCIflI4lvRmLnL/sOPFJ/
         EI9l0TxwbFr4hv2QgVU2O8WTvhkUYc0L+nQjR1KqZ5fMdRJeuPyQv/gLmMhZeJICB4gN
         ejVzNcyO299DSh+yQkH25ELGuYNSv3dkai9l2DpfdO0/+SZjpFnolXANsT/29PlxxIEm
         qhfWEsbjC01L2CfD4NJ5zA+Nas9W/gZ9hFshmxWOTFGhCNFDGbcnlOLsDRPR4fjpgBH4
         c3Wg==
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=VvT4wsAhm1GvyO/RiF8rca1DY0Hroh8G5JdZQOCUNXwxGdGnH7xacufVV1uLYmZ2lqZble+9gepolupL0bFOP9lajUtHeUjMX+FwK7JdlA8jqbpZE3qS4FHna+aKPa2GXnV3OZhkh5zP9pgFU4uYokZuCs8qVhNJXrTafr6ISfbrCS90PyX+Oh1yI0g4whWgmhGvTKfTgjit+ZhMEceOWSMcxHd1nUlSpWcS3/r0CY5VL8QwPwpyJGQdvSCWkP80+FnhVVsosuAu/OBXhJJICywov3oaBTXByi2tbndaS9xYPviGnVlcRffYykBwlzTMppT82O22zVpRs/nDOa59bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=4z4cDZlJjLvM3Bl1T3yMmEcXkORdJWZJkT0oHvxaEaU=;
 b=jkXRplE3fIqP0bQwXpfvDjkc0QlGrOLJa+vwtOv6JtGdi0+VFntyrBxgQn1DTQqyx4bLHm71Vl7CZTEV3o3zTHtfZSSKxx0GZ0xURonCmt5UdS/r9+aAhAQDkuDmMp11m72T3RZJNXUUnDT/zjLm7APzNLjU8BjzjmWnVHLw0SrtgcXDeW9BQKyB3bhUwRmdvSYWbCDukvCPIyDKRSoBCCm7/i+8bGeMiYf3ApKgytfUvY4rOjaX3U1sbobW+52PJDYPBmI4cKDKaGjTvXDhSjUUm84efY+c7AZJmvQq/ydVYP53fvQNSV9Zq6uwur84UxuvfcOMZtkrftpRrXEeMA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from DB5EUR03FT029.eop-EUR03.prod.protection.outlook.com
 (2a01:111:e400:7e0a::50) by
 DB5EUR03HT003.eop-EUR03.prod.protection.outlook.com (2a01:111:e400:7e0a::111)
 with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3955.18; Fri, 19 Mar
 2021 16:49:19 +0000
Received: from VI1PR0102MB3167.eurprd01.prod.exchangelabs.com
 (2a01:111:e400:7e0a::4e) by DB5EUR03FT029.mail.protection.outlook.com
 (2a01:111:e400:7e0a::131) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3955.18 via Frontend
 Transport; Fri, 19 Mar 2021 16:49:19 +0000
Received: from VI1PR0102MB3167.eurprd01.prod.exchangelabs.com
 ([fe80::d6d:5a3d:86f4:b199]) by
 VI1PR0102MB3167.eurprd01.prod.exchangelabs.com ([fe80::d6d:5a3d:86f4:b199%6])
 with mapi id 15.20.3955.018; Fri, 19 Mar 2021 16:49:19 +0000
To: john smith &lt;johnsmith123@gmail.com&gt;
Subject: Website contact form submission
Thread-Topic: Website contact form submission
Thread-Index: AQHXG60pM2b+ojN0CkOPbNfmJ2aSpqqLiC32
Date: Fri, 19 Mar 2021 16:49:19 +0000
Message-ID:
 &lt;VI1PR0102MB31679BEF784B62C41CDAEDB282689@VI1PR0102MB3167.eurprd01.prod.exchangelabs.com&gt;
References: &lt;E1lMk2z-00086Y-Jw@se7-syd.hostedmail.net.au&gt;
In-Reply-To: &lt;E1lMk2z-00086Y-Jw@se7-syd.hostedmail.net.au&gt;
Accept-Language: en-GB, en-US
Content-Language: en-GB
X-MS-Has-Attach: yes
X-MS-TNEF-Correlator:
x-incomingtopheadermarker:
 OriginalChecksum:758588460280CD3154F452A169E5B30299F6FA4400B34A08781C232163844E2A;UpperCasedChecksum:C08DAFF147292AFCD0C0E842D84728FDE93C04DA85452688274080A4C1208FD5;SizeAsReceived:6828;Count:44
x-ms-exchange-messagesentrepresentingtype: 1
x-tmn: [2GSIXQgTh+J+KVj3hU0l6FWIaLKAjldM]
x-ms-publictraffictype: Email
x-incomingheadercount: 44
x-eopattributedmessage: 0
x-ms-office365-filtering-correlation-id: 35f7d58b-52ef-46af-b3b5-08d8eaf6f0cd
x-ms-traffictypediagnostic: DB5EUR03HT003:
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info:
 dI7Se/jvrKe/c4F8Uq/X3EN1B075MSvHRj+42WR8WvNFHfV2P+loY42iQ46DgGfbtdZiMTFekFhgle0QrgtfM4T/j2P0Q+MI4Bdid10Qm1erNio1E6JG2qmFsTwicLpBziaKVqHmaHMCCqEL2acC9Lq5Tah9oIS5Y1qpBlf1eOO4bvXidcrToeFFZu8p8DQWD5/AuI57K26xTtl74+rmXuxkNCDxuji0DyiuCOm7q5YznA99haFiNFenl0kVQKGMQYTHCOoZYJ50s8DQ02mNHI8t/XhxFgjZ0MU2BmrtX7SWWwyYh7fezlU5MncBW9KNGk5QMAxTBpDbNewrv1z/Gy7ul5hBBHjtd0nGEeDEyuF7Wk/eTtTAXN6OFUZL0taqPLzLyA6Km7gXuSTPK8Euw3cnpBIv3vj12o8M31UrGwQ=
x-ms-exchange-antispam-messagedata:
 coLxiKb697ihiuVjy57RMtiScT++qwxVnmsRNlPsyCYuSh+qKTaQAD4B885tj5j9SZYGhabYnRTI9heOjdoSo8mCRF+u97WPFVaVFfys9h7JgmAqu7Qug1AaFybaIGK8P00ya9GcbBheKzhyShAvfg==
x-ms-exchange-transport-forked: True
Content-Type: multipart/mixed;
	boundary="_004_VI1PR0102MB31679BEF784B62C41CDAEDB282689VI1PR0102MB3167_"
MIME-Version: 1.0
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-AuthSource: DB5EUR03FT029.eop-EUR03.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: 35f7d58b-52ef-46af-b3b5-08d8eaf6f0cd
X-MS-Exchange-CrossTenant-originalarrivaltime: 19 Mar 2021 16:49:19.4742
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Internet
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB5EUR03HT003

--_004_VI1PR0102MB31679BEF784B62C41CDAEDB282689VI1PR0102MB3167_
Content-Type: multipart/alternative;
	boundary="_000_VI1PR0102MB31679BEF784B62C41CDAEDB282689VI1PR0102MB3167_"

--_000_VI1PR0102MB31679BEF784B62C41CDAEDB282689VI1PR0102MB3167_
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable


________________________________
From: Mail Delivery System &lt;Mailer-Daemon@se7-syd.hostedmail.net.au&gt;
Sent: 18 March 2021 04:14
To: kinnar1975@yahoo.co.uk &lt;kinnar1975@yahoo.co.uk&gt;
Subject: Undeliverable: Website contact form submission

This message was created automatically by mail delivery software.

A message that you sent could not be delivered to one or more of its
recipients. This is a permanent error. The following address(es) failed:

  kinnar1975@yahoo.co.uk
    host mx-eu.mail.am0.yahoodns.net [188.125.72.73]
    SMTP error from remote mail server after end of data:
    554 30 Sorry, your message to kinnar1975@yahoo.co.uk cannot be delivere=
d. This mailbox is disabled (554.30).

--_000_VI1PR0102MB31679BEF784B62C41CDAEDB282689VI1PR0102MB3167_
Content-Type: text/html; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

&lt;html&gt;
&lt;head&gt;
&lt;meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-=
1"&gt;
&lt;style type=3D"text/css" style=3D"display:none;"&gt; P {margin-top:0;margin-bo=
ttom:0;} &lt;/style&gt;
&lt;/head&gt;
&lt;body dir=3D"ltr"&gt;
&lt;div style=3D"font-family: Calibri, Helvetica, sans-serif; font-size: 12pt;=
 color: rgb(0, 0, 0);"&gt;
&lt;br&gt;
&lt;/div&gt;
&lt;div&gt;
&lt;div id=3D"appendonsend"&gt;&lt;/div&gt;
&lt;hr tabindex=3D"-1" style=3D"display:inline-block; width:98%"&gt;
&lt;div id=3D"divRplyFwdMsg" dir=3D"ltr"&gt;&lt;font face=3D"Calibri, sans-serif" co=
lor=3D"#000000" style=3D"font-size:11pt"&gt;&lt;b&gt;From:&lt;/b&gt; Mail Delivery System =
&lt;Mailer-Daemon@se7-syd.hostedmail.net.au&gt;&lt;br&gt;
&lt;b&gt;Sent:&lt;/b&gt; 18 March 2021 04:14&lt;br&gt;
&lt;b&gt;To:&lt;/b&gt; kinnar1975@yahoo.co.uk &lt;kinnar1975@yahoo.co.uk&gt;&lt;br&gt;
&lt;b&gt;Subject:&lt;/b&gt; Undeliverable: Website contact form submission&lt;/font&gt;
&lt;div&gt;&nbsp;&lt;/div&gt;
&lt;/div&gt;
&lt;div class=3D"BodyFragment"&gt;&lt;font size=3D"2"&gt;&lt;span style=3D"font-size:11pt"=
&gt;
&lt;div class=3D"PlainText"&gt;This message was created automatically by mail del=
ivery software.&lt;br&gt;
&lt;br&gt;
A message that you sent could not be delivered to one or more of its&lt;br&gt;
recipients. This is a permanent error. The following address(es) failed:&lt;br=
&gt;
&lt;br&gt;
&nbsp; kinnar1975@yahoo.co.uk&lt;br&gt;
&nbsp;&nbsp;&nbsp; host mx-eu.mail.am0.yahoodns.net [188.125.72.73]&lt;br&gt;
&nbsp;&nbsp;&nbsp; SMTP error from remote mail server after end of data:&lt;br=
&gt;
&nbsp;&nbsp;&nbsp; 554 30 Sorry, your message to kinnar1975@yahoo.co.uk can=
not be delivered. This mailbox is disabled (554.30).&lt;br&gt;
&lt;/div&gt;
&lt;/span&gt;&lt;/font&gt;&lt;/div&gt;
&lt;/div&gt;
&lt;/body&gt;
&lt;/html&gt;

--_000_VI1PR0102MB31679BEF784B62C41CDAEDB282689VI1PR0102MB3167_--

--_004_VI1PR0102MB31679BEF784B62C41CDAEDB282689VI1PR0102MB3167_
Content-Type: message/rfc822
Content-Disposition: attachment;
	creation-date="Thu, 18 Mar 2021 04:14:19 GMT";
	modification-date="Thu, 18 Mar 2021 04:14:19 GMT"
Content-ID: &lt;5A9638EA6676A449B32643CFC62AAB5F@eurprd01.prod.exchangelabs.com&gt;

Received: from c5s2-1e-syd.hosting-services.net.au ([103.9.171.10])
	by se7-syd.hostedmail.net.au with esmtps (TLSv1.2:AES128-GCM-SHA256:128)
	(Exim 4.92)
	id 1lMk2r-0007vB-6O
	for kinnar1975@yahoo.co.uk; Thu, 18 Mar 2021 15:14:06 +1100
Received: from markgard by c5s2-1e-syd.hosting-services.net.au with local (Exim 4.94)
	id 1lMk2m-002w3b-NT
	for kinnar1975@yahoo.co.uk; Thu, 18 Mar 2021 15:13:56 +1100
To: kinnar1975@yahoo.co.uk
Subject: Website contact form submission
X-PHP-Script: www.markgardner.com.au/index.php for 91.90.123.43
X-PHP-Filename: /home/markgard/public_html/index.php REMOTE_ADDR: 91.90.123.43
Message-ID: &lt;9af4091a6356d03e08c653d61c3317c5@www.markgardner.com.au&gt;
Date: Thu, 18 Mar 2021 15:13:56 +1100
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable
X-AntiAbuse: This header was added to track abuse, please include it with any abuse report
X-AntiAbuse: Primary Hostname - c5s2-1e-syd.hosting-services.net.au
X-AntiAbuse: Original Domain - yahoo.co.uk
X-AntiAbuse: Originator/Caller UID/GID - [645 501] / [47 12]
X-AntiAbuse: Sender Address Domain - hotmail.co.uk
X-Get-Message-Sender-Via: c5s2-1e-syd.hosting-services.net.au: authenticated_id: markgard/only user confirmed/virtual account not confirmed
X-Authenticated-Sender: c5s2-1e-syd.hosting-services.net.au: markgard
X-Source:
X-Source-Args:
X-Source-Dir: markgardner.com.au:/public_html
X-Originating-IP: 103.9.171.10
X-SpamExperts-Domain: out-2.hosting-services.net.au
X-SpamExperts-Username: 103.9.171.10
Authentication-Results: hostedmail.net.au; auth=pass smtp.auth=103.9.171.10@out-2.hosting-services.net.au
X-SpamExperts-Outgoing-Class: unsure
X-SpamExperts-Outgoing-Evidence: Combined (0.52)
X-Recommended-Action: accept
X-Filter-ID: Pt3MvcO5N4iKaDQ5O6lkdGlMVN6RH8bjRMzItlySaT89hY7QKxoN2bH3hJaGW2IpPUtbdvnXkggZ
 3YnVId/Y5jcf0yeVQAvfjHznO7+bT5zqUA8hT1A9YKB9i1C8tm0FSY5pAhCsHHyuxCwGLoOzBIJL
 M0i5ZAms0EHrvcCaVIMMGG9jpucc0SNLsDvCI1wozIXV52OyeiH3YVVX92r9xygFBqP9R4pweyxd
 HXGiL7j6BpeseSBELv+0jcKNeZXKhVuvOR3Ln3jZRs77DOT24JCTMkaicdLs0JYHIM966+y5TpWT
 FsQKCOuiS4S8pbsCwiF5chQ0eGHndnjZbM6wL3TaeQtlKubP6iUTjj6yPASOmrbMWhZFkvyjvYIF
 be8tdb9BwqvSI91oKEKHszPrHGllke3azHdKmySKNUVQl4ntlVxnbS8qIO7oudHyb2T1emsmnnq8
 H5RnRriVft+dRaZGawtRufZzJOZwa6OUbLspcvZoI7P90p8oLprk3TF7EVBannnL7tRRK/uB8nvA
 5dTkQHZZAFXxrDiK8BajMqIBbapBffof8ZbjRi48kxwwd/8g8ph5pmY3BWxh+gw0+bNud3PgzKGZ
 88iododq/YfVWMlHoWh7YJ70YBk8N5yx6J1fhOzjF0b4LXcjJZ5lophHcCCSZA0wo+GCaDbv8BVl
 BrgfA+nWs+ztZpIm+YUajlb62b+LvSOnVgYfMfV4/FZVYBSmXLV0H9UwfJB5VkyXuNsMOTPAVIrj
 2CQcJI3nLOjrOwwGI3kKu05JnDlv7nu+R5njOOVDeTnBQh+vgakM+3bjD6YI0Pi00Yp9Jo2PalvC
 Jx/RaFcuVNt8/inhvATugv1leQFvfCG5Mo+bZdrT9kO/rNfjYvuiOaQMP7hsYO4RKhzUPwqM4mnL
 vWdl6qmCT+WDVl7mMFEDbEvOkCuSUAX+wQaSOBQUHJ9fl0pktssFkv3lRh6UA/3FEjNcCz7Qn5mE
 3ifZ1Wx+Bxers9vSFjcXvojt6rPDFXmX7JFPjVZ28Fo80MP7MdFAR4SkjoOu+oaeH1BvSVyLTJZ2
 qqIBbapBffof8ZbjRi48kxwwEp0StAIU5onMW52eptt78P9RT6iLoaztK96skCBBmEn58PNKHent
 BN+4pS7z1zv6So+O6aenwaZ6/X2ea4ZBUw==
X-Report-Abuse-To: spam@se1-syd.hostedmail.net.au
MIME-Version: 1.0

&lt;!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.=
w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"&gt;&lt;html xmlns=3D"http://www.w3.=
org/1999/xhtml"&gt;&lt;head&gt;
&lt;meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dutf-8"&gt;
&lt;title&gt;Website contact form submission&lt;/title&gt;
&lt;/head&gt;
&lt;body&gt;

&lt;style type=3D"text/css"&gt;
  p { margin-bottom: 1em; }
&lt;/style&gt;

&lt;p&gt;&lt;strong&gt;First Name:&lt;/strong&gt; Robertbiolo&lt;br&gt;&lt;strong&gt;Last Name:&lt;/strong&gt; =
Robertbiolo&lt;br&gt;&lt;strong&gt;Email Address:&lt;/strong&gt; kinnar1975@yahoo.co.uk&lt;br&gt;&lt;s=
trong&gt;Mobile:&lt;/strong&gt; 85471397431&lt;br&gt;&lt;strong&gt;Booking Date:&lt;/strong&gt; 1977-1=
1-10&lt;br&gt;&lt;strong&gt;Booking Time:&lt;/strong&gt; RobertbioloXE&lt;br&gt;&lt;strong&gt;Services Re=
quired:&lt;/strong&gt;&lt;/p&gt;
&lt;p&gt;Good earnings from $6500 per day &gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt=
;     https://35000usdperwwekpodf.blogspot.sg?p=3D9swghttps://35000usdperww=
ekpodf.blogspot.co.il?o=3D0hnd   &lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&l=
t;&lt;/p&gt;&lt;/body&gt;
&lt;/html&gt;

--_004_VI1PR0102MB31679BEF784B62C41CDAEDB282689VI1PR0102MB3167_--</code></pre>
</details>

## Investigation

### Understanding the Email Structure

The first thing to understand is that this is not a simple one-layer email. What was forwarded to the SOC is actually a **bounce notification** — an automated delivery failure message. Inside that bounce is the original phishing email attached as `Website contact form submission.eml`. This means all the useful forensic data lives in the **attachment**, not the outer email.

The outer email is from `Mailer-Daemon@se7-syd.hostedmail.net.au` informing `kinnar1975@yahoo[.]co[.]uk` that their message could not be delivered because the Yahoo mailbox is disabled. This is a common spam technique — attackers abuse legitimate website contact forms to send spam, and when delivery fails the bounce lands in someone else's inbox.

---

### Attachment Analysis — The Original Phishing Email

Opening the attached `.eml` reveals the original contact form submission. The relevant headers and content are:

The email was sent on **18 March 2021 04:14** from a PHP contact form at `www.markgardner.com.au`, as shown in the `X-PHP-Script` header:

```
X-PHP-Script: www.markgardner.com.au/index.php for 91.90.123.43
```

The originating IP is visible in the `X-Originating-IP` header:

```
X-Originating-IP: 103.9.171.10
```

This is the server IP of the Australian hosting provider that relayed the message, resolving via reverse DNS to `c5s2-1e-syd.hosting-services.net.au`.

---

### Malicious URL

The body of the contact form reveals  URL:

```
[hxxps[://]35000usdperwwekpodf[.]blogspot[.]sg?p=9swg](<https://35000usdperwwekpodf.blogspot.sg?p=3D9swghttps://35000usdperww= ekpodf.blogspot.co.il?o=3D0hnd>)
```

The domain makes it clear this is hosted on **Blogspot** — Google's free blogging platform, which is frequently abused for spam and phishing pages due to its trusted domain reputation. Checking the URL via URL2PNG confirms the blog has since been taken down, showing the heading **"Blog has been removed"**.

---

## IOCs

|Type|Value|
|---|---|
|Email|`kinnar1975@yahoo[.]co[.]uk`|
|IP|`103[.]9[.]171[.]10`|
|Host|`c5s2-1e-syd.hosting-services.net.au`|
|Domain|`35000usdperwwekpodf[.]blogspot[.]sg`|
|URL|`hxxps[://]35000usdperwwekpodf[.]blogspot[.]sg?p=9swg`|
|File|`Website contact form submission.eml`|

---

<div class="qa-item"> <div class="qa-question-text">Who is the primary recipient of this email?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">kinnar1975@yahoo.co.uk</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the subject of this email?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Undeliverable: Website contact form submission</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the date and time the email was sent?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">18 March 2021 04:14</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the Originating IP?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">103.9.171.10</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Perform reverse DNS on this IP address, what is the resolved host?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">c5s2-1e-syd.hosting-services.net.au</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the name of the attached file?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">Website contact form submission.eml</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the URL found inside the attachment?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">https://35000usdperwwekpodf.blogspot.sg?p=3D9swghttps://35000usdperww=
ekpodf.blogspot.co.il?o=3D0hnd</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What service is this webpage hosted on?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">blogspot</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Using URL2PNG, what is the heading text on this page?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">blog has been removed</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

