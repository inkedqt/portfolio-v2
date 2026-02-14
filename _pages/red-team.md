---
layout: splash
title: " "
permalink: /red-team/
classes: wide
---

<!-- Red Team Hero -->
<div class="red-team-hero">
  <div class="hero-icon">⚔️</div>
  <h1>Red Team Operations</h1>
  <p class="hero-subtitle">Penetration Testing & Offensive Security Research</p>
  <p class="hero-description">
    HTB Season 9 Top 1% (Holo) ranking through systematic exploitation of Active Directory environments, 
    web applications, container escapes, and privilege escalation chains. Demonstrating attacker TTPs 
    to strengthen defensive capabilities.
  </p>
<p class="hero-description">
  HTB Season 9 ranked, Active Directory specialist, and offensive security researcher 
  focused on realistic attack simulations and security assessments.
</p>

<p style="text-align: center; color: #b8b8b8; font-size: 0.95rem; margin-top: 1.5rem; margin-bottom: 0.5rem;">
  Active hands-on training across industry-leading cybersecurity platforms
</p>

<!-- Platform Badges -->
<div style="margin-top: 1rem; display: flex; flex-direction: column; align-items: center; gap: 1.5rem;">
  <!-- HTB Badge -->
  <a href="https://app.hackthebox.com/users/2216056" target="_blank">
    <img src="https://www.hackthebox.eu/badge/image/2216056" 
         alt="HackTheBox Profile" 
         style="border-radius: 8px; width: 400px; height: auto;">
  </a>
  
  <!-- THM Badge -->
  <iframe src="https://tryhackme.com/api/v2/badges/public-profile?userPublicId=4106179" 
          style="border:none; width: 400px; height: 120px; border-radius: 8px;" 
          title="TryHackMe Stats">
  </iframe>
</div>
</div>

<!-- Quick Stats -->
<div class="red-team-stats">
  <div class="stat-box">
    <div class="stat-number">🏆 Holo</div>
    <div class="stat-label">Season 9 (Top 1%)</div>
  </div>
  <div class="stat-box">
    <div class="stat-number">30+</div>
    <div class="stat-label">Seasonal Boxes</div>
  </div>
  <div class="stat-box">
    <div class="stat-number">50+</div>
    <div class="stat-label">Retired Boxes</div>
  </div>
</div>

<!-- Certifications -->
<h2 class="section-heading">🎓 Offensive Security Certifications</h2>

<div class="cert-grid-mini">
  <div class="cert-card">
    <img src="{{ site.baseurl }}/assets/images/certs/cpts.png" alt="CPTS">
    <h3>CPTS</h3>
    <p>HTB Certified Penetration Testing Specialist</p>
    <a href="https://www.credly.com/badges/3dff4822-f70f-40c8-a4b4-ee19a43b1d26/public_url" target="_blank" class="cert-link">Verify →</a>
  </div>
  
  <div class="cert-card">
    <img src="{{ site.baseurl }}/assets/images/certs/bscp.png" alt="BSCP">
    <h3>BSCP</h3>
    <p>Burp Suite Certified Practitioner</p>
    <a href="https://portswigger.net/web-security/e/c/3dcdb1592a81aeed" target="_blank" class="cert-link">Verify →</a>
  </div>
  
  <div class="cert-card">
    <img src="{{ site.baseurl }}/assets/images/certs/cwes.png" alt="CWES">
    <h3>CWES</h3>
    <p>Certified Web Exploitation Specialist</p>
    <a href="https://www.credly.com/badges/2bbefbd8-a51a-4459-a3eb-8f42e4953f17" target="_blank" class="cert-link">Verify →</a>
  </div>
  
  <div class="cert-card">
    <img src="{{ site.baseurl }}/assets/images/certs/ejpt.png" alt="eJPT">
    <h3>eJPT</h3>
    <p>Junior Penetration Tester</p>
    <a href="https://certs.ine.com/418db589-3ab5-4b4e-9a3c-236681afa28a" target="_blank" class="cert-link">Verify →</a>
  </div>
</div>

<!-- Featured Achievement -->
<h2 class="section-heading">⭐ Featured Achievement</h2>

<div class="featured-achievement">
  <div class="achievement-badge">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/HTB/proofs/htb_season9.png" alt="HTB Season 9 Holo Badge">
  </div>
  <div class="achievement-details">
    <h3>🏆 HTB Season 9 – Season of the Gacha</h3>
    <p><strong>Rank:</strong> 95 / 9,850 Players (Top ~1%) | <strong>Badge:</strong> Holo</p>
    <p><strong>Achievement:</strong> 13/13 Roots • 13/13 Users • Perfect completion</p>
    
    <p class="achievement-summary">
      Achieved top 1% ranking through consistent exploitation across diverse attack vectors: 
      Active Directory abuse (Kerberos delegation, shadow credentials, ESC1), web application vulnerabilities 
      (logic flaws, SSRF, RCE), container escapes, and advanced privilege escalation techniques.
    </p>
    
    <ul class="achievement-highlights">
      <li><strong>AD Exploitation:</strong> Certificate abuse, shadow credentials, Kerberos attacks, ACL manipulation</li>
      <li><strong>Web Security:</strong> IDOR, SQL injection, SSRF, file upload bypasses, CMS exploitation</li>
      <li><strong>Container Tech:</strong> Docker escapes, registry abuse, Kubernetes misconfigurations</li>
      <li><strong>Privilege Escalation:</strong> Sudo abuse, SUID binaries, service misconfigurations, kernel exploits</li>
    </ul>
    
    <p class="achievement-meta">
      <strong>Blue Team Value:</strong> Understanding these attack chains enables detection engineering, 
      SIEM rule development, and incident response playbook creation from a defender's perspective.
    </p>
  </div>
</div>

<!-- Seasonal Results -->
<h2 class="section-heading">🏆 Seasonal Performance</h2>
{% include seasonal-results.html %}

<!-- Seasonal Boxes Table -->
<h2 class="section-heading">🗓️ HTB Seasonal Boxes</h2>
<p class="table-intro">
  Current and recent seasonal boxes demonstrating Active Directory exploitation, web application security, 
  container escapes, and multi-stage attack chains.
</p>
{% include seasonal-table.html %}

<!-- Retired Boxes -->
<h2 class="section-heading">📦 HTB Retired Boxes</h2>
<p class="table-intro">
  Full write-ups available for all retired boxes covering diverse attack techniques and methodologies.
</p>
{% include retired-table.html %}

<!-- Active Boxes -->
<h2 class="section-heading">🔒 HTB Active Boxes</h2>
<p class="private-note">
  ⚠️ Write-ups withheld per HTB rules until box retirement. Proof screenshots demonstrate completion 
  without revealing solutions.
</p>
{% include active-table.html %}

<!-- Pro Labs -->
<h2 class="section-heading">🏢 HTB Pro Labs</h2>
<p class="table-intro">
  Multi-machine enterprise environments simulating real-world corporate networks, AD forests, 
  and complex attack chains.
</p>
{% include pro-labs.html %}

<!-- Other Platforms -->
<!-- Other Platforms -->
<h2 class="section-heading">🌐 Other Platforms</h2>
<p class="table-intro">
  Penetration testing practice across TryHackMe, ProvingGrounds, and other offensive security platforms.
</p>

{% include other-platforms.html title="🧪 Proving Grounds (PG) Boxes" items=site.data.pg %}
{% include other-platforms.html title="🧪 TryHackMe (THM) Boxes" items=site.data.thm %}

{% if site.data.hacksmarter %}
  {% include other-platforms.html title="🧪 HackSmarter Labs" items=site.data.hacksmarter %}
{% endif %}

<!-- Featured Case Study -->
<h2 class="section-heading">📋 Featured Case Study</h2>

<div class="case-study-highlight">
  <h3>VPN Compromise & Privilege Escalation</h3>
  
  <p>
    Structured penetration test case study demonstrating attack methodology from external reconnaissance 
    through full host compromise, written from a <strong>defensive perspective</strong>.
  </p>
  
  <div class="case-study-content">
    <div class="attack-chain">
      <h4>Attack Chain:</h4>
      <ol>
        <li><strong>Enumeration:</strong> IKE Aggressive Mode discovery on VPN endpoint</li>
        <li><strong>Credential Recovery:</strong> PSK extraction and offline cracking</li>
        <li><strong>Initial Access:</strong> VPN authentication with recovered credentials</li>
        <li><strong>Privilege Escalation:</strong> Sudo misconfiguration leading to root</li>
      </ol>
    </div>
    
    <div class="defensive-value">
      <h4>Defensive Insights:</h4>
      <ul>
        <li>MITRE ATT&CK mapping for detection engineering</li>
        <li>Risk ratings and business impact assessment</li>
        <li>Remediation guidance and compensating controls</li>
        <li>Detection opportunities at each attack stage</li>
      </ul>
    </div>
  </div>
  
  <p class="case-study-cta">
    <a href="https://inksec.io/Case-Studies/VPN-PrivEsc/" target="_blank" class="btn-case-study">
      📖 Read Full Case Study →
    </a>
  </p>
</div>

<!-- Philosophy Section -->
<div class="red-team-philosophy">
  <h3>🎯 Why Red Team Skills Matter for Blue Team Roles</h3>
  
  <p>
    My offensive security background directly strengthens defensive capabilities:
  </p>
  
  <div class="philosophy-grid">
    <div class="philosophy-point">
      <div class="point-icon">🔍</div>
      <h4>Attack Detection</h4>
      <p>Understanding how attacks work enables creation of accurate detection rules and SIEM queries</p>
    </div>
    
    <div class="philosophy-point">
      <div class="point-icon">📊</div>
      <h4>Threat Hunting</h4>
      <p>Knowledge of attacker TTPs informs proactive hunting hypotheses and investigation priorities</p>
    </div>
    
    <div class="philosophy-point">
      <div class="point-icon">🛡️</div>
      <h4>Incident Response</h4>
      <p>Experience with exploitation chains accelerates incident analysis and containment decisions</p>
    </div>
    
    <div class="philosophy-point">
      <div class="point-icon">🎓</div>
      <h4>Security Training</h4>
      <p>Practical attack knowledge enables realistic tabletop exercises and security awareness training</p>
    </div>
  </div>
  
  <p class="philosophy-summary">
    <strong>Current Focus:</strong> Applying offensive security knowledge to SOC analyst workflows through 
    LetsDefend investigations, TryHackMe blue team paths, and hands-on SIEM lab work. Seeking SOC L1/Security 
    Operations roles in Melbourne where this perspective strengthens defensive capabilities.
  </p>
</div>

<!-- HTB Rules Note -->
<div class="red-team-note">
  <p>
    💡 <strong>Note on Active Boxes:</strong> Per HTB community guidelines, write-ups are only published 
    after box retirement. Proof screenshots demonstrate completion without revealing solutions. 
    Full methodologies and detailed write-ups are available for all retired boxes in my 
    <a href="https://github.com/inkedqt/ctf-writeups" target="_blank">GitHub repository</a>.
  </p>
</div>

<!-- CTA -->
<div class="red-team-cta">
  <h3>📬 Discuss Offensive Security Techniques</h3>
  <p>
    Interested in discussing attack methodologies, defensive applications, or collaboration opportunities?
  </p>
  <a href="{{ site.baseurl }}/#contact" class="btn-cta">Get In Touch →</a>
</div>
