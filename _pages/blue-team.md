---
layout: splash
title: " "  # Blank title
permalink: /blue-team/
classes: wide
header:
  overlay_color: "#000000"
  overlay_filter: "0.5"
---
<!-- Hero Section -->
<div class="blue-team-hero">
  <div class="hero-icon">🛡️</div>
  <h1>Blue Team Operations</h1>
  <p class="hero-subtitle">SOC Analysis & Defensive Security</p>
  <p class="hero-description">
    80+ documented investigations across multiple platforms demonstrating SIEM analysis, 
    alert triage, incident response workflows, and threat detection capabilities.
  </p>
</div>
<!-- INLINE STYLE FIX - ADD THIS HERE -->
<style>
.btl1-labs-grid {
  display: grid !important;
  grid-template-columns: repeat(3, 1fr) !important;
  gap: 2rem !important;
  max-width: 1400px !important;
  margin: 2rem auto !important;
  padding: 0 1rem !important;
}

.btl1-thumbnail {
  width: 100% !important;
  height: auto !important;
  max-height: 200px !important;
  border-radius: 8px !important;
  overflow: hidden !important;
  margin-bottom: 1rem !important;
  border: 2px solid #ff66c4 !important;
  background: #000 !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
}

.btl1-thumbnail img {
  width: 100% !important;
  height: auto !important;
  max-height: 200px !important;
  object-fit: contain !important;
}

@media (max-width: 900px) {
  .btl1-labs-grid {
    grid-template-columns: 1fr !important;
  }
}
</style>

<!-- Featured Achievements -->
<h2 class="section-heading">🏆 Featured Achievements</h2>

<div class="achievement-cards">
  <!-- TryHackMe Night Shift -->
  <div class="achievement-card">
    <div class="achievement-badge">
      <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/HTB/proofs/THM_first_shift.png" alt="TryHackMe Night Shift Completion">
    </div>
    <h3>TryHackMe Night Shift CTF</h3>
    <p class="achievement-meta">Completed: February 2026 | Difficulty: Medium | 2,214 Points</p>
    <ul class="achievement-highlights">
      <li>Week-long SOC analyst simulation</li>
      <li>Alert triage & severity assessment</li>
      <li>Multi-source log correlation</li>
      <li>Incident response playbooks</li>
      <li>9 realistic enterprise scenarios</li>
    </ul>
    <a href="https://tryhackme.com/inkedqt" target="_blank" class="btn-achievement">View Profile →</a>
  </div>

  <!-- LetsDefend SOC Analyst -->
  <div class="achievement-card">
    <div class="achievement-badge">
      <img src="{{ site.baseurl }}/assets/images/certs/letsdefend.png" alt="LetsDefend">
    </div>
    <h3>LetsDefend SOC Analyst Path</h3>
    <p class="achievement-meta">Completed: February 2026 | 34 Investigations | 97% Success Rate</p>
    <ul class="achievement-highlights">
      <li>Real-world SIEM alert triage</li>
      <li>Log analysis & correlation</li>
      <li>Malware investigation & IOC identification</li>
      <li>Incident documentation & reporting</li>
      <li>Threat intelligence integration</li>
    </ul>
    <a href="https://app.letsdefend.io/user/inkedqt" target="_blank" class="btn-achievement">View Profile →</a>
  </div>
<!-- TryHackMe Advent of Cyber 2025 -->
  <div class="achievement-card">
    <div class="achievement-badge">
      <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/HTB/proofs/thm_advent2025.png" alt="THM SOCmas">
    </div>
    <h3>🎄 TryHackMe – Advent of Cyber 2025 (SOC-mas)</h3>
    <p class="achievement-meta">Completed: December 2025 | 24 Daily Labs</p>
    <ul class="achievement-highlights">
      <li><strong>Phishing:</strong> Email analysis, IOC extraction, investigation workflow</li>
      <li><strong>Splunk:</strong> Basic searches, detections, triage context, alert review</li>
      <li><strong>SOC alert triage:</strong> Signal vs noise, next steps, evidence collection</li>
      <li><strong>Host-based forensics:</strong> Registry/system artefacts, timeline-style thinking</li>
      <li><strong>Network discovery/traffic:</strong> Scanning concepts + reading results</li>
      <li><strong>Malware analysis:</strong> Basic static/dynamic concepts (entry-level but practical)</li>
      <li><strong>ICS/Modbus awareness:</strong> Intro industrial protocol scenarios</li>
      <li><strong>Detection concepts:</strong> C2 indicators, command & control patterns</li>
    </ul>
    <p class="achievement-meta"><em>Complements CDSA and strengthens "detect + respond" skills alongside offensive work.</em></p>
    <a href="https://tryhackme-certificates.s3-eu-west-1.amazonaws.com/THM-2H6JFCWHKX.pdf" target="_blank" class="btn-achievement">View Certificate →</a>
  </div>
  <!-- HTB CDSA -->
  <div class="achievement-card">
    <div class="achievement-badge">
      <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/certs/cdsa.png" alt="HTB Certified Defensive Security Analyst">
    </div>
    <h3>HTB Certified Defensive Security Analyst (CDSA)</h3>
    <p class="achievement-meta">Completed: [Month Year] | Certification Exam</p>
    <ul class="achievement-highlights">
      <li>SOC fundamentals & alert triage workflows</li>
      <li>SIEM analysis with Splunk & Elastic</li>
      <li>Threat intelligence & IOC correlation</li>
      <li>Digital forensics & incident response</li>
      <li>Phishing analysis & malware detection</li>
      <li>Network traffic analysis & PCAP investigation</li>
    </ul>
    <a href="https://www.credly.com/badges/80ca0800-f89e-4be7-86c1-4e104d776233/public_url" target="_blank" class="btn-achievement">View Certificate →</a>
  </div>
</div>
</div>
<!-- YouTube Investigation Walkthroughs -->
<h2 class="section-heading">📺 Investigation Walkthroughs</h2>

<div class="youtube-cards">
  <!-- LetsDefend Playlist -->
  <div class="youtube-card">
    <a href="https://www.youtube.com/playlist?list=PL4gQknB3vSQ4gVy09mt2oMwl0hjL5aCor" target="_blank" class="youtube-link">
      <div class="youtube-thumbnail">
        <img src="https://img.youtube.com/vi/TCJv1ndeOiU/hqdefault.jpg" alt="LetsDefend SOC Investigations">
        <div class="play-overlay">▶</div>
      </div>
      <h3>LetsDefend SOC Investigations</h3>
      <p>Real-world SIEM alert investigations with full analysis, log correlation, and incident response workflows.</p>
      <div class="playlist-stats">
        <span>📹 15+ Videos</span>
        <span>⏱️ ~4 hours</span>
      </div>
    </a>
  </div>

  <!-- TryHackMe Playlist -->
  <div class="youtube-card">
    <a href="https://www.youtube.com/playlist?list=PL4gQknB3vSQ5G7likpYieGzLbhVcCO4hN" target="_blank" class="youtube-link">
      <div class="youtube-thumbnail">
        <img src="https://img.youtube.com/vi/q6VErK_2PLA/hqdefault.jpg" alt="TryHackMe Blue Team">
        <div class="play-overlay">▶</div>
      </div>
      <h3>TryHackMe Blue Team Operations</h3>
      <p>SOC Level 1 learning path walkthroughs covering network security, PCAP analysis, and defensive operations.</p>
      <div class="playlist-stats">
        <span>📹 12+ Videos</span>
        <span>⏱️ ~3 hours</span>
      </div>
    </a>
  </div>
</div>
<!-- BTL1 Certification Labs -->
<h2 class="section-heading">🎓 BTL1 Certification Labs</h2>

<p class="section-intro">Hands-on labs from Security Blue Team's Blue Team Level 1 certification path. Each lab covers real-world defensive security scenarios with practical analysis and reporting.</p>

<style>
.btl1-labs-grid {
  display: grid !important;
  grid-template-columns: repeat(3, 1fr) !important;
  gap: 2rem !important;
  max-width: 1400px !important;
  margin: 2rem auto !important;
  padding: 0 1rem !important;
}

.btl1-lab-card {
  background: #1a1a1a !important;
  border: 2px solid #444 !important;
  border-radius: 12px !important;
  padding: 1.5rem !important;
  transition: all 0.3s ease !important;
}

.btl1-lab-card.completed {
  border-color: #00ff88 !important;
  box-shadow: 0 0 20px rgba(0, 255, 136, 0.3) !important;
}

.btl1-lab-card.locked {
  opacity: 0.6 !important;
}

.btl1-thumbnail {
  width: 100% !important;
  height: auto !important;
  max-height: 200px !important;
  border-radius: 8px !important;
  overflow: hidden !important;
  margin-bottom: 1rem !important;
  border: 2px solid #ff66c4 !important;
  background: #000 !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
}

.btl1-thumbnail img {
  width: 100% !important;
  height: auto !important;
  max-height: 200px !important;
  object-fit: contain !important;
}

@media (max-width: 900px) {
  .btl1-labs-grid {
    grid-template-columns: 1fr !important;
  }
}
</style>

<div class="btl1-labs-grid">
  <!-- Lab 1: Piggy -->
  <div class="btl1-lab-card completed">
    <a href="{{ site.baseurl }}/blue-team/piggy/" class="lab-card-link">
      <div class="btl1-thumbnail">
        <img src="{{ site.baseurl }}/assets/images/labs/btl1/piggy-hero.png" alt="Piggy - PCAP Analysis Lab">
      </div>
      <div class="btl1-badge">✓ COMPLETED</div>
      <h3>Piggy</h3>
      <p class="lab-category">PCAP Analysis • Wireshark • Network Forensics</p>
      <p class="lab-description">Multi-PCAP investigation covering SSH data exfiltration, malware infrastructure identification, and MITRE ATT&CK mapping.</p>
      <div class="lab-tags">
        <span class="tag">Wireshark</span>
        <span class="tag">OSINT</span>
        <span class="tag">BTL1</span>
      </div>
      <div class="lab-cta">View Investigation →</div>
    </a>
  </div>

  <!-- Lab 2: Locked -->
  <div class="btl1-lab-card locked">
    <div class="btl1-badge">🔒 UPCOMING</div>
    <div class="btl1-thumbnail">
      <div class="placeholder-thumb">Lab 2</div>
    </div>
    <h3>Upcoming Lab</h3>
    <p class="lab-category">TBD</p>
    <p class="lab-description">Additional BTL1 labs will be documented here as they are completed.</p>
  </div>

  <!-- Lab 3: Locked -->
  <div class="btl1-lab-card locked">
    <div class="btl1-badge">🔒 UPCOMING</div>
    <div class="btl1-thumbnail">
      <div class="placeholder-thumb">Lab 3</div>
    </div>
    <h3>Upcoming Lab</h3>
    <p class="lab-category">TBD</p>
    <p class="lab-description">Additional BTL1 labs will be documented here as they are completed.</p>
  </div>
</div>

<div class="btl1-progress">
  <div class="progress-bar">
    <div class="progress-fill" style="width: 11%;"></div>
  </div>
  <p class="progress-text">1 of 9 BTL1 labs completed (11%)</p>
</div>
<!-- Investigation Documentation -->
<h2 class="section-heading">📊 Investigation Documentation</h2>

<div class="documentation-cards">
  <!-- Obsidian Dashboard -->
  <div class="doc-card">
    <div class="doc-icon">📓</div>
    <h3>Obsidian Investigation Vault</h3>
    <p>Comprehensive case documentation with MITRE ATT&CK mapping, IOC tracking, and investigation timelines.</p>
    <ul>
      <li>80+ documented investigations</li>
      <li>MITRE ATT&CK technique mapping</li>
      <li>Reusable investigation templates</li>
      <li>IOC database & metrics dashboard</li>
    </ul>
    <p class="doc-note"><em>Private repository - screenshot available on request</em></p>
  </div>

  <!-- Platform Profiles -->
  <div class="doc-card">
    <div class="doc-icon">🔗</div>
    <h3>Public Platform Profiles</h3>
    <p>Verified investigation work across multiple SOC training platforms.</p>
    <ul>
      <li><a href="https://app.letsdefend.io/user/inkedqt" target="_blank">LetsDefend</a> - 34 cases, 97% success</li>
      <li><a href="https://tryhackme.com/p/inkedqt" target="_blank">TryHackMe</a> - 46 cases, 100% detection</li>
      <li>All investigations publicly verifiable</li>
      <li>Real-time metrics & rankings</li>
    </ul>
  </div>
</div>

<!-- Hands-On Labs -->
<h2 class="section-heading">🔬 Hands-On Lab Environments</h2>

<div class="lab-cards">
  <!-- Splunk SIEM Lab -->
  <div class="lab-card">
    <div class="lab-icon">📡</div>
    <h3>Splunk Enterprise SIEM Lab</h3>
    <p>Production-style SIEM environment for alert detection, log analysis, and threat hunting practice.</p>
    <div class="lab-specs">
      <div class="lab-spec">
        <strong>Host:</strong> Ubuntu 24.04 running Splunk Enterprise
      </div>
      <div class="lab-spec">
        <strong>Agent:</strong> Windows 11 with Universal Forwarder
      </div>
      <div class="lab-spec">
        <strong>Telemetry:</strong> Sysmon event collection & parsing
      </div>
      <div class="lab-spec">
        <strong>Use Cases:</strong> Custom detection rules, SPL queries, dashboards
      </div>
    </div>
  </div>

  <!-- Malware Analysis Sandbox -->
  <div class="lab-card">
    <div class="lab-icon">🦠</div>
    <h3>Malware Analysis Sandbox</h3>
    <p>Isolated environment for safe malware detonation, static analysis, and reverse engineering practice.</p>
    <div class="lab-specs">
      <div class="lab-spec">
        <strong>Platform:</strong> FlareVM on isolated virtual network
      </div>
      <div class="lab-spec">
        <strong>Tools:</strong> IDA, Ghidra, PE analysis, debuggers
      </div>
      <div class="lab-spec">
        <strong>Analysis:</strong> Static & dynamic malware examination
      </div>
      <div class="lab-spec">
        <strong>Use Cases:</strong> IOC extraction, behavior analysis, reporting
      </div>
    </div>
  </div>
</div>

<!-- Call to Action -->
<div class="blue-team-cta">
  <h2>Ready to Discuss SOC Operations?</h2>
  <p>View my investigation work, watch walkthroughs, or reach out to discuss defensive security capabilities.</p>
  <a href="/#contact" class="btn-cta">Get In Touch →</a>
</div>
