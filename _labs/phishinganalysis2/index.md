---
layout: lab
title: Phising analysis 2
platform: BTLO
difficulty: Easy
category: Threat Intelligence
skill: Threat Intelligence
tools: "[Text Editor, Thunderbird]"
tactics:
mitre: "[T1566.002]"
proof: https://blueteamlabs.online/achievement/share/challenge/144656/24
challenge_url: https://blueteamlabs.online/home/challenge/phishing-analysis-2-a1091574b8
permalink: /blue-team/labs/phishinganalysis2/
summary: '"Analysis of a phishing email impersonating Amazon, delivered to saintington73@outlook.com. The email body is base64 encoded HTML, the CTA button points to a typosquatted domain, and the attacker left a personal Facebook profile URL embedded in the footer."'
art: https://d2ghw05x0obr70.cloudfront.net/thumbnails/6156a19eafa9b683f8616ae21d677fac47e20834.png
type: challenge
points:
youtube:
locked: tate
---
## Overview

A phishing email impersonating Amazon is provided for triage. The goal is to extract key artifacts from the email headers, body, and embedded URLs to build an IOC profile of the campaign.

---

## Investigation

### Email Headers

Opening the `.eml` file in a text editor exposes the key headers immediately:

- **From:** `amazon@zyevantoby[.]cn` — a Chinese TLD domain with no affiliation to Amazon
- **To:** `saintington73@outlook[.]com`
- **Subject:** `Your Account has been locked`
- **Date:** `Wed, 14 Jul 2021 01:40:32 +0900`

The sending domain `zyevantoby[.]cn` is the first major red flag — legitimate Amazon correspondence originates from `amazon.com` domains only.

### Body Encoding

The email body MIME part declares:

```
Content-Transfer-Encoding: base64
```

The entire HTML body is base64 encoded. Decoding it in CyberChef (**From Base64**) reveals a full HTML email template impersonating Amazon's branding, complete with inline CSS styling and a call-to-action button.

The decoded HTML confirms a fully crafted Amazon account limitation lure with inline CSS styling built from a Mailchimp template (`mcnTextBlock`, `mcnButtonBlock` class names). The body warns the recipient their account access has been restricted and lists impacted capabilities including the ability to pay, change payment method, redeem gift cards, and close their account — all designed to maximise urgency.

<details class="code-block">
  <summary>decoded base64 message</summary>
  <pre><code>&lt;!DOCTYPE HTML&gt;&lt;html&gt;&lt;head&gt;
&lt;meta http-equiv="Content-Type" content="text/html; charset=utf-8"&gt;&lt;meta name="GENERATOR" content="MSHTML 11.00.10570.1001"&gt;&lt;/head&gt;
&lt;body&gt;&lt;xml&gt;             &lt;o:officedocumentsettings&gt;&lt;o:allowpng&gt;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
&lt;/o:allowpng&gt;         &lt;/o:officedocumentsettings&gt;         &lt;!--[endif]----&gt;       
   
&lt;META http-equiv="X-UA-Compatible" content="IE=edge"&gt;     
&lt;META name="viewport" content="width=device-width, initial-scale=1"&gt;   
&lt;TITLE&gt;&lt;/TITLE&gt;       
&lt;STYLE type="text/css"&gt;
		p{
			margin:10px 0;
			padding:0;
		}
		table{
			border-collapse:collapse;
		}
		h1,h2,h3,h4,h5,h6{
			display:block;
			margin:0;
			padding:0;
		}
		img,a img{
			border:0;
			height:auto;
			outline:none;
			text-decoration:none;
		}
		body,#bodyTable,#bodyCell{
			height:100%;
			margin:0;
			padding:0;
			width:100%;
		}
		.mcnPreviewText{
			display:none !important;
		}
		#outlook a{
			padding:0;
		}
		img{
			-ms-interpolation-mode:bicubic;
		}
		table{
			mso-table-lspace:0pt;
			mso-table-rspace:0pt;
		}
		.ReadMsgBody{
			width:100%;
		}
		.ExternalClass{
			width:100%;
		}
		p,a,li,td,blockquote{
			mso-line-height-rule:exactly;
		}
		a[href^=tel],a[href^=sms]{
			color:inherit;
			cursor:default;
			text-decoration:none;
		}
		p,a,li,td,body,table,blockquote{
			-ms-text-size-adjust:100%;
			-webkit-text-size-adjust:100%;
		}
		.ExternalClass,.ExternalClass p,.ExternalClass td,.ExternalClass div,.ExternalClass span,.ExternalClass font{
			line-height:100%;
		}
		a[x-apple-data-detectors]{
			color:inherit !important;
			text-decoration:none !important;
			font-size:inherit !important;
			font-family:inherit !important;
			font-weight:inherit !important;
			line-height:inherit !important;
		}
		#bodyCell{
			padding:10px;
		}
		.templateContainer{
			max-width:600px !important;
		}
		a.mcnButton{
			display:block;
		}
		.mcnImage,.mcnRetinaImage{
			vertical-align:bottom;
		}
		.mcnTextContent{
			word-break:break-word;
		}
		.mcnTextContent img{
			height:auto !important;
		}
		.mcnDividerBlock{
			table-layout:fixed !important;
		}
	/*
	@tab Page
	@section Background Style
	@tip Set the background color and top border for your email. You may want to choose colors that match your company's branding.
	*/
		body,#bodyTable{
			/*@editable*/background-color:#FFFFFF;
			/*@editable*/background-image:none;
			/*@editable*/background-repeat:no-repeat;
			/*@editable*/background-position:center;
			/*@editable*/background-size:cover;
		}
	/*
	@tab Page
	@section Background Style
	@tip Set the background color and top border for your email. You may want to choose colors that match your company's branding.
	*/
		#bodyCell{
			/*@editable*/border-top:0;
		}
	/*
	@tab Page
	@section Email Border
	@tip Set the border for your email.
	*/
		.templateContainer{
			/*@editable*/border:0;
		}
	/*
	@tab Page
	@section Heading 1
	@tip Set the styling for all first-level headings in your emails. These should be the largest of your headings.
	@style heading 1
	*/
		h1{
			/*@editable*/color:#202020;
			/*@editable*/font-family:Helvetica;
			/*@editable*/font-size:26px;
			/*@editable*/font-style:normal;
			/*@editable*/font-weight:bold;
			/*@editable*/line-height:125%;
			/*@editable*/letter-spacing:normal;
			/*@editable*/text-align:left;
		}
	/*
	@tab Page
	@section Heading 2
	@tip Set the styling for all second-level headings in your emails.
	@style heading 2
	*/
		h2{
			/*@editable*/color:#202020;
			/*@editable*/font-family:Helvetica;
			/*@editable*/font-size:22px;
			/*@editable*/font-style:normal;
			/*@editable*/font-weight:bold;
			/*@editable*/line-height:125%;
			/*@editable*/letter-spacing:normal;
			/*@editable*/text-align:left;
		}
	/*
	@tab Page
	@section Heading 3
	@tip Set the styling for all third-level headings in your emails.
	@style heading 3
	*/
		h3{
			/*@editable*/color:#202020;
			/*@editable*/font-family:Helvetica;
			/*@editable*/font-size:20px;
			/*@editable*/font-style:normal;
			/*@editable*/font-weight:bold;
			/*@editable*/line-height:125%;
			/*@editable*/letter-spacing:normal;
			/*@editable*/text-align:left;
		}
	/*
	@tab Page
	@section Heading 4
	@tip Set the styling for all fourth-level headings in your emails. These should be the smallest of your headings.
	@style heading 4
	*/
		h4{
			/*@editable*/color:#202020;
			/*@editable*/font-family:Helvetica;
			/*@editable*/font-size:18px;
			/*@editable*/font-style:normal;
			/*@editable*/font-weight:bold;
			/*@editable*/line-height:125%;
			/*@editable*/letter-spacing:normal;
			/*@editable*/text-align:left;
		}
	/*
	@tab Header
	@section Header Style
	@tip Set the borders for your email's header area.
	*/
		#templateHeader{
			/*@editable*/border-top:0;
			/*@editable*/border-bottom:0;
		}
	/*
	@tab Header
	@section Header Text
	@tip Set the styling for your email's header text. Choose a size and color that is easy to read.
	*/
		#templateHeader .mcnTextContent,#templateHeader .mcnTextContent p{
			/*@editable*/color:#202020;
			/*@editable*/font-family:Helvetica;
			/*@editable*/font-size:16px;
			/*@editable*/line-height:150%;
			/*@editable*/text-align:left;
		}
	/*
	@tab Header
	@section Header Link
	@tip Set the styling for your email's header links. Choose a color that helps them stand out from your text.
	*/
		#templateHeader .mcnTextContent a,#templateHeader .mcnTextContent p a{
			/*@editable*/color:#007C89;
			/*@editable*/font-weight:normal;
			/*@editable*/text-decoration:underline;
		}
	/*
	@tab Body
	@section Body Style
	@tip Set the borders for your email's body area.
	*/
		#templateBody{
			/*@editable*/border-top:0;
			/*@editable*/border-bottom:0;
		}
	/*
	@tab Body
	@section Body Text
	@tip Set the styling for your email's body text. Choose a size and color that is easy to read.
	*/
		#templateBody .mcnTextContent,#templateBody .mcnTextContent p{
			/*@editable*/color:#202020;
			/*@editable*/font-family:Helvetica;
			/*@editable*/font-size:16px;
			/*@editable*/line-height:150%;
			/*@editable*/text-align:left;
		}
	/*
	@tab Body
	@section Body Link
	@tip Set the styling for your email's body links. Choose a color that helps them stand out from your text.
	*/
		#templateBody .mcnTextContent a,#templateBody .mcnTextContent p a{
			/*@editable*/color:#007C89;
			/*@editable*/font-weight:normal;
			/*@editable*/text-decoration:underline;
		}
	/*
	@tab Footer
	@section Footer Style
	@tip Set the borders for your email's footer area.
	*/
		#templateFooter{
			/*@editable*/border-top:0;
			/*@editable*/border-bottom:0;
		}
	/*
	@tab Footer
	@section Footer Text
	@tip Set the styling for your email's footer text. Choose a size and color that is easy to read.
	*/
		#templateFooter .mcnTextContent,#templateFooter .mcnTextContent p{
			/*@editable*/color:#202020;
			/*@editable*/font-family:Helvetica;
			/*@editable*/font-size:12px;
			/*@editable*/line-height:150%;
			/*@editable*/text-align:left;
		}
	/*
	@tab Footer
	@section Footer Link
	@tip Set the styling for your email's footer links. Choose a color that helps them stand out from your text.
	*/
		#templateFooter .mcnTextContent a,#templateFooter .mcnTextContent p a{
			/*@editable*/color:#202020;
			/*@editable*/font-weight:normal;
			/*@editable*/text-decoration:underline;
		}
	@media only screen and (min-width:768px){
		.templateContainer{
			width:600px !important;
		}

}	@media only screen and (max-width: 480px){
		body,table,td,p,a,li,blockquote{
			-webkit-text-size-adjust:none !important;
		}

}	@media only screen and (max-width: 480px){
		body{
			width:100% !important;
			min-width:100% !important;
		}

}	@media only screen and (max-width: 480px){
		#bodyCell{
			padding-top:10px !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnRetinaImage{
			max-width:100% !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnImage{
			width:100% !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnCartContainer,.mcnCaptionTopContent,.mcnRecContentContainer,.mcnCaptionBottomContent,.mcnTextContentContainer,.mcnBoxedTextContentContainer,.mcnImageGroupContentContainer,.mcnCaptionLeftTextContentContainer,.mcnCaptionRightTextContentContainer,.mcnCaptionLeftImageContentContainer,.mcnCaptionRightImageContentContainer,.mcnImageCardLeftTextContentContainer,.mcnImageCardRightTextContentContainer,.mcnImageCardLeftImageContentContainer,.mcnImageCardRightImageContentContainer{
			max-width:100% !important;
			width:100% !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnBoxedTextContentContainer{
			min-width:100% !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnImageGroupContent{
			padding:9px !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnCaptionLeftContentOuter .mcnTextContent,.mcnCaptionRightContentOuter .mcnTextContent{
			padding-top:9px !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnImageCardTopImageContent,.mcnCaptionBottomContent:last-child .mcnCaptionBottomImageContent,.mcnCaptionBlockInner .mcnCaptionTopContent:last-child .mcnTextContent{
			padding-top:18px !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnImageCardBottomImageContent{
			padding-bottom:9px !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnImageGroupBlockInner{
			padding-top:0 !important;
			padding-bottom:0 !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnImageGroupBlockOuter{
			padding-top:9px !important;
			padding-bottom:9px !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnTextContent,.mcnBoxedTextContentColumn{
			padding-right:18px !important;
			padding-left:18px !important;
		}

}	@media only screen and (max-width: 480px){
		.mcnImageCardLeftImageContent,.mcnImageCardRightImageContent{
			padding-right:18px !important;
			padding-bottom:0 !important;
			padding-left:18px !important;
		}

}	@media only screen and (max-width: 480px){
		.mcpreview-image-uploader{
			display:none !important;
			width:100% !important;
		}

}	@media only screen and (max-width: 480px){
	/*
	@tab Mobile Styles
	@section Heading 1
	@tip Make the first-level headings larger in size for better readability on small screens.
	*/
		h1{
			/*@editable*/font-size:22px !important;
			/*@editable*/line-height:125% !important;
		}

}	@media only screen and (max-width: 480px){
	/*
	@tab Mobile Styles
	@section Heading 2
	@tip Make the second-level headings larger in size for better readability on small screens.
	*/
		h2{
			/*@editable*/font-size:20px !important;
			/*@editable*/line-height:125% !important;
		}

}	@media only screen and (max-width: 480px){
	/*
	@tab Mobile Styles
	@section Heading 3
	@tip Make the third-level headings larger in size for better readability on small screens.
	*/
		h3{
			/*@editable*/font-size:18px !important;
			/*@editable*/line-height:125% !important;
		}

}	@media only screen and (max-width: 480px){
	/*
	@tab Mobile Styles
	@section Heading 4
	@tip Make the fourth-level headings larger in size for better readability on small screens.
	*/
		h4{
			/*@editable*/font-size:16px !important;
			/*@editable*/line-height:150% !important;
		}

}	@media only screen and (max-width: 480px){
	/*
	@tab Mobile Styles
	@section Boxed Text
	@tip Make the boxed text larger in size for better readability on small screens. We recommend a font size of at least 16px.
	*/
		table.mcnBoxedTextContentContainer td.mcnTextContent,td.mcnBoxedTextContentContainer td.mcnTextContent p{
			/*@editable*/font-size:14px !important;
			/*@editable*/line-height:150% !important;
		}

}	@media only screen and (max-width: 480px){
	/*
	@tab Mobile Styles
	@section Header Text
	@tip Make the header text larger in size for better readability on small screens.
	*/
		td#templateHeader td.mcnTextContent,td#templateHeader td.mcnTextContent p{
			/*@editable*/font-size:16px !important;
			/*@editable*/line-height:150% !important;
		}

}	@media only screen and (max-width: 480px){
	/*
	@tab Mobile Styles
	@section Body Text
	@tip Make the body text larger in size for better readability on small screens. We recommend a font size of at least 16px.
	*/
		td#templateBody td.mcnTextContent,td#templateBody td.mcnTextContent p{
			/*@editable*/font-size:16px !important;
			/*@editable*/line-height:150% !important;
		}

}	@media only screen and (max-width: 480px){
	/*
	@tab Mobile Styles
	@section Footer Text
	@tip Make the footer content text larger in size for better readability on small screens.
	*/
		td#templateFooter td.mcnTextContent,td#templateFooter td.mcnTextContent p{
			/*@editable*/font-size:14px !important;
			/*@editable*/line-height:150% !important;
		}

}&lt;/STYLE&gt;
    &lt;BR&gt;&nbsp; 
&lt;TABLE width="600" align="center" style="width: 600px;" border="0" cellspacing="0" 
cellpadding="0"&gt;
  &lt;TBODY&gt;
  &lt;TR&gt;
    &lt;TD width="600" align="center" valign="top" 
      style="width: 600px;"&gt;&nbsp;&lt;IMG width="749" height="67" style="width: 100px;" 
      alt="" src="https://images.squarespace-cdn.com/content/52e2b6d3e4b06446e8bf13ed/1500584238342-OX2L298XVSKF8AO6I3SV/amazon-logo?format=750w&amp;content-type=image%2Fpng" 
      border="0" hspace="0"&gt;                   
      &lt;TABLE width="100%" class="templateContainer" border="0" cellspacing="0" 
      cellpadding="0"&gt;
        &lt;TBODY&gt;
        &lt;TR&gt;
          &lt;TD id="templateBody" valign="top"&gt;
            &lt;TABLE width="100%" class="mcnTextBlock" style="min-width: 100%;" 
            border="0" cellspacing="0" cellpadding="0"&gt;
              &lt;TBODY class="mcnTextBlockOuter"&gt;
              &lt;TR&gt;
                &lt;TD class="mcnTextBlockInner" valign="top" style="padding-top: 9px;"&gt;&lt;!--[if mso]&gt;
				&lt;table align="left" border="0" cellspacing="0" cellpadding="0" width="100%" style="width:100%;"&gt;
				&lt;tr&gt;
				&lt;![endif]--&gt;&lt;!--[if mso]&gt;
				&lt;td valign="top" width="600" style="width:600px;"&gt;
				&lt;![endif]--&gt; 
                                                                        
                  &lt;TABLE width="100%" align="left" class="mcnTextContentContainer" 
                  style="min-width: 100%; max-width: 100%;" border="0" 
                  cellspacing="0" cellpadding="0"&gt;
                    &lt;TBODY&gt;
                    &lt;TR&gt;
                      &lt;TD class="mcnTextContent" valign="top" style="padding: 0pt 18px 9px;"&gt;
                        &lt;TABLE width="100%"&gt;
                          &lt;TBODY&gt;
                          &lt;TR&gt;
                            &lt;TD&gt;
                              &lt;P&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;&lt;STRONG&gt;Hello 
                                                            Dear 
                              Customer,&lt;/STRONG&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/P&gt;
                              &lt;P&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;Your 
                                                            aϲϲount access has 
                              been limited. We've noticed                        
                                     significant changes in your aϲϲount 
                              activity. As                               your 
                              payment process,&nbsp;We need to understand        
                                                     these changes 
                              better&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/P&gt;
                              &lt;UL&gt;&lt;/UL&gt;
                              &lt;P&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;&lt;STRONG&gt;This 
                                                            Limitation will 
                              affect your ability                               
                              to:&lt;/STRONG&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/P&gt;
                              &lt;UL&gt;
                                &lt;LI&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;&lt;STRONG&gt;Ρay.&lt;/STRONG&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/LI&gt;
                                &lt;LI&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;&lt;STRONG&gt;Change 
                                                                your payment 
                                 method.&lt;/STRONG&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/LI&gt;
                                &lt;LI&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;&lt;STRONG&gt;Buy 
                                                                or redeem gift   
                                                              
                                cards.&lt;/STRONG&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/LI&gt;
                                &lt;LI&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;&lt;STRONG&gt;Close 
                                                                your 
                                aϲϲount.&lt;/STRONG&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/LI&gt;&lt;/UL&gt;
                              &lt;P&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;&lt;STRONG&gt;What 
                                                            to do 
                              next:&lt;/STRONG&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/P&gt;
                              &lt;OL&gt;&lt;/OL&gt;
                              &lt;P&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;Please 
                                                            click the link above 
                              and follow the steps in                            
                                 order to &lt;STRONG&gt;Review The Account&lt;/STRONG&gt;, 
                              If                               we don't receive 
                              the information within 72 hours,                   
                                          Your aϲϲount aϲϲess may be             
                                              
                          lost.&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/P&gt;&lt;/TD&gt;&lt;/TR&gt;&lt;/TBODY&gt;&lt;/TABLE&gt;&lt;/TD&gt;&lt;/TR&gt;&lt;/TBODY&gt;&lt;/TABLE&gt;&lt;!--[if mso]&gt;
				&lt;/td&gt;
				&lt;![endif]--&gt; 
                                    
              &lt;BR&gt;&lt;BR&gt;&lt;BR&gt;&lt;BR&gt;&lt;BR&gt;&lt;BR&gt;&lt;BR&gt;&lt;BR&gt;&lt;BR&gt;&lt;BR&gt;&lt;/TD&gt;&lt;/TR&gt;&lt;/TBODY&gt;&lt;/TABLE&gt;&lt;/TD&gt;&lt;/TR&gt;
        &lt;TR&gt;
          &lt;TD id="templateFooter" valign="top"&gt;
            &lt;TABLE width="100%" class="mcnButtonBlock" style="min-width: 100%;" 
            border="0" cellspacing="0" cellpadding="0"&gt;
              &lt;TBODY class="mcnButtonBlockOuter"&gt;
              &lt;TR&gt;
                &lt;TD align="center" class="mcnButtonBlockInner" valign="top" 
                style="padding: 0pt 18px 18px;"&gt;
                  &lt;TABLE width="100%" class="mcnButtonContentContainer" style="border-collapse: separate !important; background-color: rgb(255, 153, 0);" 
                  border="0" cellspacing="0" cellpadding="0"&gt;
                    &lt;TBODY&gt;
                    &lt;TR&gt;
                      &lt;TD align="center" class="mcnButtonContent" valign="middle" 
                      style="padding: 20px; font-family: Arial; font-size: 16px;"&gt;&lt;A 
                        title="Review Account" class="mcnButton" style="text-align: center; color: rgb(255, 255, 255); line-height: 100%; letter-spacing: normal; font-weight: bold; text-decoration: none;" 
                        href="https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Famaozn.zzyuchengzhika.cn%2F%3Fmailtoken%3Dsaintington73%40outlook.com&amp;data=04%7C01%7C%7C70072381ba6e49d1d12d08d94632811e%7C84df9e7fe9f640afb435aaaaaaaaaaaa%7C1%7C0%7C637618004988892053%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C1000&amp;sdata=oPvTW08ASiViZTLfMECsvwDvguT6ODYKPQZNK3203m0%3D&amp;reserved=0" originalSrc="https://amaozn.zzyuchengzhika.cn/?mailtoken=saintington73@outlook.com" shash="Fs6cig8SRUo6Yy/pwwp7bmc4QzHa7mipEFApeNMEIJLHvXJD9hfKyBwuC15cZyvTqeMhxfySpUVyqi3LJVJRYmYealKld7FRPW8cYeBFLrZb+qOcKx3Po2WpFWyOukDUKStz+9k7dXejUhmw3WGJuyIz8OCD12wPagtFXHYyHJk=" target="_blank"&gt;Review                
                                 
            Account&lt;/A&gt;&lt;/TD&gt;&lt;/TR&gt;&lt;/TBODY&gt;&lt;/TABLE&gt;&lt;/TD&gt;&lt;/TR&gt;&lt;/TBODY&gt;&lt;/TABLE&gt;
            &lt;TABLE width="100%" class="mcnTextBlock" style="min-width: 100%;" 
            border="0" cellspacing="0" cellpadding="0"&gt;
              &lt;TBODY class="mcnTextBlockOuter"&gt;
              &lt;TR&gt;
                &lt;TD class="mcnTextBlockInner" valign="top" style="padding-top: 9px;"&gt;
                  &lt;DIV style="text-align: center;"&gt;&lt;/DIV&gt;
                  &lt;TABLE width="100%" align="left" class="mcnTextContentContainer" 
                  style="min-width: 100%; max-width: 100%;" border="0" 
                  cellspacing="0" cellpadding="0"&gt;
                    &lt;TBODY&gt;
                    &lt;TR&gt;
                      &lt;TD class="mcnTextContent" valign="top" style="padding: 0pt 18px 9px;"&gt;
                        &lt;DIV style="text-align: center;"&gt;&lt;/DIV&gt;
                        &lt;P style="text-align: center;"&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN 
                        style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;&lt;EM&gt;Yours 
                                                
                        Sincerely,&nbsp;&lt;/EM&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;BR&gt;&lt;/P&gt;
                        &lt;DIV style="text-align: center;"&gt;&lt;A href="https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.facebook.com%2Famir.boyka.7&amp;data=04%7C01%7C%7C70072381ba6e49d1d12d08d94632811e%7C84df9e7fe9f640afb435aaaaaaaaaaaa%7C1%7C0%7C637618004988892053%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C1000&amp;sdata=KVi%2BG1%2BFO3v3ALNVowA1PrenHiT3aT%2FIvb5y1KxkAkc%3D&amp;reserved=0" originalSrc="https://www.facebook.com/amir.boyka.7" shash="GensOMRql5Vqvbx8WtI2HuCQojKiOwg7AD9+j3lsp1MJ8kbk6EbXKYUYje6INStWQ4xNG6Tfa9JLrYG51E0Azr3pMKAdzbJV1i+mX09meMM6wMYdF1GPgi0vTMLrYM5G4WlnQk+KI7F1gVlC5jEXJj6gDuMfnhlYhET3olHtypI=" 
                        target="_blank"&gt;&lt;SPAN style="font-size: 13px;"&gt;&lt;SPAN 
                        style="font-family: helvetica neue,helvetica,arial,verdana,sans-serif;"&gt;&lt;SPAN 
                        style="color: rgb(255, 153, 0);"&gt;Amazon Support          
                                       Team&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/A&gt;&lt;SPAN style="font-size: 12px;"&gt;&lt;SPAN 
                        style="font-family: helvetica neue,helvetica,arial,verdana,sans-serif;"&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;BR&gt;&lt;SPAN 
                        style="font-size: 12px;"&gt;&lt;SPAN style="font-family: helvetica neue,helvetica,arial,verdana,sans-serif;"&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;/DIV&gt;
                        &lt;DIV style="text-align: center;"&gt;&lt;SPAN style="font-size: 12px;"&gt;&lt;SPAN 
                        style="font-family: helvetica neue,helvetica,arial,verdana,sans-serif;"&gt;Copyright 
                                                 © 1999-2021 Amazon. All rights  
                                               reserved.&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;BR&gt;&lt;/DIV&gt;
                        &lt;P&gt;&lt;SPAN style="font-size: 14px;"&gt;&lt;SPAN style="font-family: arial,helvetica neue,helvetica,sans-serif;"&gt;&lt;STRONG&gt;&lt;/STRONG&gt;&lt;/SPAN&gt;&lt;/SPAN&gt;&lt;BR&gt; 
                                               &nbsp;  
                  &lt;/P&gt;&lt;/TD&gt;&lt;/TR&gt;&lt;/TBODY&gt;&lt;/TABLE&gt;&lt;BR&gt;&lt;/TD&gt;&lt;/TR&gt;&lt;/TBODY&gt;&lt;/TABLE&gt;&lt;/TD&gt;&lt;/TR&gt;&lt;/TBODY&gt;&lt;/TABLE&gt;&lt;!--[if (gte mso 9)|(IE)]&gt;
                        &lt;/td&gt;
                        &lt;/tr&gt;
                        &lt;/table&gt;
                        &lt;![endif]--&gt; 
&lt;!-- // END TEMPLATE --&gt;     &lt;/TD&gt;&lt;/TR&gt;&lt;/TBODY&gt;&lt;/TABLE&gt;&lt;/xml&gt;&lt;/body&gt;&lt;/html&gt;
</code></pre>
</details>


### Impersonation Technique

The decoded HTML presents a convincing Amazon account limitation notice urging the recipient to click a "Review Account" button within 72 hours or risk losing account access — a classic urgency-based social engineering technique. The email uses the Amazon logo pulled from a third-party Squarespace CDN URL:

`hxxps://images.squarespace-cdn[.]com/content/52e2b6d3e4b06446e8bf13ed/1500584238342-OX2L298XVSKF8AO6I3SV/amazon-logo?format=750w&content-type=image%2Fpng`

A subtle indicator of fraud is the use of visually identical Unicode characters substituted for standard ASCII — `ϲ` (Cyrillic small letter es) replacing `c` in the word "account" throughout the body, a technique used to evade keyword-based spam filters.

### Call-to-Action URL

The "Review Account" button resolves through a Microsoft SafeLinks wrapper to the actual phishing destination:

`hxxps://amaozn[.]zzyuchengzhika[.]cn/?mailtoken=saintington73@outlook[.]com`

Key observations:

- **Typosquatted domain:** `amaozn` — transposing the `o` and `z` in Amazon
- **Victim email pre-populated** as a mailtoken parameter — personalised phishing, tracking who clicked
- The domain `zzyuchengzhika[.]cn` is another Chinese TLD with no Amazon affiliation
- Checking the URL via URL2PNG shows the site is no longer live: _"This web page could not be loaded."_

### Embedded Facebook Profile

Buried in the footer, the "Amazon Support Team" text is hyperlinked not to Amazon but to a personal Facebook profile:

`hxxps://www.facebook[.]com/amir.boyka.7`

This is a significant OPSEC failure by the attacker — leaving a personal social media account linked directly inside the phishing template. The Facebook username is **amir.boyka.7**.

---

## IOCs

|Type|Value|
|---|---|
|Sender|`amazon@zyevantoby[.]cn`|
|Recipient|`saintington73@outlook[.]com`|
|Subject|`Your Account has been locked`|
|Phishing domain|`amaozn[.]zzyuchengzhika[.]cn`|
|Full phishing URL|`hxxps://amaozn[.]zzyuchengzhika[.]cn/?mailtoken=saintington73@outlook[.]com`|
|Logo CDN URL|`hxxps://images.squarespace-cdn[.]com/content/52e2b6d3e4b06446e8bf13ed/1500584238342-OX2L298XVSKF8AO6I3SV/amazon-logo`|
|Attacker Facebook|`hxxps://www.facebook[.]com/amir.boyka.7`|

---



<div class="qa-item"> <div class="qa-question-text">What is the sending email address?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">amazon@zyevantoby.cn</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the recipient email address?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">saintington73@outlook.com</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the subject line of the email?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Your Account has been locked</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What company is the attacker trying to imitate?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">amazon</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the date and time the email was sent?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">Wed, 14 Jul 2021 01:40:32 +0900</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the URL of the main call-to-action button?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">[ANSWER](https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Famaozn.zzyuchengzhika.cn%2F%3Fmailtoken%3Dsaintington73%40outlook.com&data=04%7C01%7C%7C70072381ba6e49d1d12d08d94632811e%7C84df9e7fe9f640afb435aaaaaaaaaaaa%7C1%7C0%7C637618004988892053%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C1000&sdata=oPvTW08ASiViZTLfMECsvwDvguT6ODYKPQZNK3203m0%3D&reserved=0)</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">Look at the URL using URL2PNG. What is the first sentence (heading) displayed on this site? (regardless of whether you think the site is malicious or not)</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">This web page could not be loaded.</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">When looking at the main body content in a text editor, what encoding scheme is being used?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">base64</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">What is the URL used to retrieve the company's logo in the email?</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">https://images.squarespace-cdn.com/content/52e2b6d3e4b06446e8bf13ed/1500584238342-OX2L298XVSKF8AO6I3SV/amazon-logo?format=750w&amp;content-type=image%2Fpng</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

<div class="qa-item"> <div class="qa-question-text">For some unknown reason one of the URLs contains a Facebook profile URL. What is the username (not necessarily the display name) of this account, based on the URL?</div> <div class="answer-reveal"> <input type="checkbox"> <span class="r-placeholder">Click to reveal answer</span> <span class="r-answer">amir.boyka.7</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>

