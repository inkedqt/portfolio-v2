---
layout: splash
title: "Tate Pannam - SOC Analyst"
header:
  overlay_color: "#000000"
  overlay_filter: "0.5"
classes: wide
---

<style>
/* Terminal Hero */
.terminal-hero {
  background: #000000;
  border: 2px solid #ff66c4;
  border-radius: 12px;
  padding: 2.5rem;
  margin: 2rem auto;
  max-width: 1000px; /* Wider */
  font-family: 'Courier New', 'Fira Code', monospace;
  box-shadow: 0 0 30px rgba(255, 102, 196, 0.5);
  color: #00ff88;
}

.terminal-avatar {
  text-align: center;
  margin-bottom: 2rem;
}

.terminal-avatar img {
  width: 200px;
  height: 200px;
  border-radius: 50%;
  border: 3px solid #ff66c4;
  box-shadow: 0 0 20px rgba(255, 102, 196, 0.6);
}

.terminal-prompt {
  color: #00ff88;
  font-weight: bold;
}

.terminal-output {
  color: #ff9ce4;
  margin-left: 1rem;
  line-height: 1.8;
}

.terminal-link {
  color: #00d9ff;
  text-decoration: none;
  border-bottom: 1px dotted #00d9ff;
}

.terminal-link:hover {
  color: #ffb3ff;
  border-bottom-color: #ffb3ff;
}

/* Portfolio Cards */
.portfolio-cards {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 2rem;
  margin: 3rem auto;
  max-width: 1200px;
}

.portfolio-card {
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
  border: 3px solid #ff66c4;
  border-radius: 16px;
  padding: 2.5rem;
  text-align: center;
  box-shadow: 0 0 20px rgba(255, 102, 196, 0.4);
  transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.portfolio-card:hover {
  transform: translateY(-8px);
  box-shadow: 0 0 30px rgba(255, 102, 196, 0.7);
}

.portfolio-card h2 {
  color: #ff90d6;
  font-size: 2rem;
  margin-bottom: 1rem;
}

.portfolio-card .icon {
  font-size: 3rem;
  margin-bottom: 1rem;
}

.portfolio-card ul {
  list-style: none;
  padding: 0;
  margin: 1.5rem 0;
  text-align: left;
}

.portfolio-card ul li {
  padding: 0.5rem 0;
  color: #f4c4eb;
}

.portfolio-card ul li::before {
  content: "▸ ";
  color: #00ff88;
  font-weight: bold;
  margin-right: 0.5rem;
}

.btn-portfolio {
  display: inline-block;
  background: linear-gradient(135deg, #ff66c4, #ff90d6);
  color: #121212 !important;
  padding: 0.9rem 2rem;
  border-radius: 999px;
  font-weight: 700;
  text-decoration: none;
  margin-top: 1rem;
  transition: all 0.3s ease;
  box-shadow: 0 0 15px rgba(255, 102, 196, 0.5);
}

.btn-portfolio:hover {
  transform: translateY(-2px);
  box-shadow: 0 0 25px rgba(255, 102, 196, 0.8);
  text-decoration: none;
}

/* Cert Grid */
.cert-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1.5rem;
  margin: 3rem auto;
  max-width: 1200px;
}

.cert-card {
  background-color: #1a1a1a;
  border: 2px solid #ff66c4;
  border-radius: 1rem;
  padding: 1.5rem;
  text-align: center;
  box-shadow: 0 0 16px rgba(255, 102, 196, 0.4);
  transition: transform .3s ease;
}

.cert-card:hover {
  transform: scale(1.05);
  box-shadow: 0 0 25px rgba(255, 102, 196, 0.7);
}

.cert-card img {
  width: 100%;
  max-height: 180px;
  object-fit: contain;
  margin-bottom: 1rem;
  border-radius: 0.5rem;
}

.cert-card h3 {
  color: #ff90d6;
  font-size: 1.1rem;
  margin-bottom: 0.5rem;
}

.cert-card p {
  color: #f4c4eb;
  font-size: 0.9rem;
}

@media (max-width: 768px) {
  .portfolio-cards {
    grid-template-columns: 1fr;
  }
  
  .terminal-hero {
    padding: 1.5rem;
  }
}
</style>

<!-- Terminal Hero -->
<div class="terminal-hero">
  <div class="terminal-avatar">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/tate-banner.png" alt="Tate Pannam Avatar">
  </div>
  
  <div class="terminal-content">
    <p><span class="terminal-prompt">$</span> <span class="terminal-output">whoami</span></p>
    <p class="terminal-output">Tate Pannam</p>
    <br>
    
    <p><span class="terminal-prompt">$</span> <span class="terminal-output">cat ~/role.txt</span></p>
    <p class="terminal-output">SOC Analyst | Blue Team Operations</p>
    <p class="terminal-output">Melbourne, Australia</p>
    <br>
    
    <p><span class="terminal-prompt">$</span> <span class="terminal-output">ls ~/portfolio</span></p>
    <p class="terminal-output">🛡️ blue-team/</p>
    <p class="terminal-output">⚔️ red-team/</p>
    <p class="terminal-output">📜 certifications/</p>
    <br>
    
    <p><span class="terminal-prompt">$</span> <span class="terminal-output">ls ~/experience</span></p>
    <p class="terminal-output">80+ documented investigations</p>
    <p class="terminal-output"><a href="https://app.letsdefend.io/user/inkedqt" target="_blank" class="terminal-link">→ LetsDefend Profile</a></p>
  </div>
</div>

<!-- Portfolio Cards -->
<div class="portfolio-cards">
  <!-- Blue Team Card -->
  <div class="portfolio-card">
    <div class="icon">🛡️</div>
    <h2>Blue Team Operations</h2>
    <p>SOC investigations, incident response, and defensive security analysis</p>
    <ul>
      <li>80+ documented investigations</li>
      <li>SIEM analysis & detection engineering</li>
      <li>Incident response workflows</li>
      <li>MITRE ATT&CK mapping</li>
    </ul>
    <a href="/portfolio-v2/blue-team/" class="btn-portfolio">View Portfolio →</a>
  </div>
  
  <!-- Red Team Card -->
  <div class="portfolio-card">
    <div class="icon">⚔️</div>
    <h2>Red Team Operations</h2>
    <p>Penetration testing, exploit development, and offensive security research</p>
    <ul>
      <li>HTB Seasonal: Top 1% ranking</li>
      <li>CPTS & BSCP certified</li>
      <li>50+ retired boxes solved</li>
      <li>Web & network exploitation</li>
    </ul>
    <a href="/portfolio-v2/red-team/" class="btn-portfolio">View Work →</a>
  </div>
</div>

<!-- Certifications Section -->
<h2 style="text-align: center; color: #ff90d6; margin: 3rem 0 2rem 0; font-size: 2rem;">📜 Security Certifications</h2>

<div class="cert-grid">
  <!-- CDSA -->
  <div class="cert-card">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/certs/cdsa.png" alt="HTB CDSA Certificate">
    <h3>CDSA</h3>
    <p>Certified Defensive Security Analyst</p>
    <p><a href="https://www.credly.com/badges/80ca0800-f89e-4be7-86c1-4e104d776233" target="_blank">Verify →</a></p>
  </div>
  
  <!-- BTL1 (In Progress) -->
  <div class="cert-card">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/certs/btl1-placeholder.png" alt="BTL1 In Progress" style="opacity: 0.7;">
    <h3>BTL1</h3>
    <p>Blue Team Level 1</p>
    <p><em>In Progress - Expected May 2026</em></p>
  </div>
  
  <!-- CPTS -->
  <div class="cert-card">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/certs/cpts.png" alt="HTB CPTS Certificate">
    <h3>CPTS</h3>
    <p>Certified Penetration Testing Specialist</p>
    <p><a href="https://www.credly.com/badges/3dff4822-f70f-40c8-a4b4-ee19a43b1d26" target="_blank">Verify →</a></p>
  </div>
  
  <!-- BSCP -->
  <div class="cert-card">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/certs/bscp.png" alt="PortSwigger BSCP">
    <h3>BSCP</h3>
    <p>Burp Suite Certified Practitioner</p>
    <p><a href="https://portswigger.net/web-security/e/c/3dcdb1592a81aeed" target="_blank">Verify →</a></p>
  </div>
  
  <!-- CWES -->
  <div class="cert-card">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/certs/cwes.png" alt="HTB CWES Certificate">
    <h3>CWES</h3>
    <p>Certified Web Exploitation Specialist</p>
    <p><a href="https://www.credly.com/badges/2bbefbd8-a51a-4459-a3eb-8f42e4953f17" target="_blank">Verify →</a></p>
  </div>
  
  <!-- eJPT -->
  <div class="cert-card">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/certs/ejpt.png" alt="INE eJPT Certificate">
    <h3>eJPT</h3>
    <p>Junior Penetration Tester</p>
    <p><a href="https://certs.ine.com/418db589-3ab5-4b4e-9a3c-236681afa28a" target="_blank">Verify →</a></p>
  </div>
  
  <!-- ICCA -->
  <div class="cert-card">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/certs/icca.png" alt="INE ICCA Certificate">
    <h3>ICCA</h3>
    <p>INE Certified Cloud Associate</p>
    <p><a href="https://certs.ine.com/7e00ab5d-87c4-426d-b3f0-2f97dcdd19b7" target="_blank">Verify →</a></p>
  </div>
  
  <!-- Cert IV Cyber -->
  <div class="cert-card">
    <img src="https://raw.githubusercontent.com/inkedqt/ctf-writeups/main/assets/certs/vu-cyber.png" alt="Cert IV Cyber Security">
    <h3>Cert IV</h3>
    <p>Cyber Security (TAFE)</p>
    <p><em>Completing August 2026</em></p>
  </div>
</div>

<!-- About/Contact -->
<div style="text-align: center; margin: 4rem auto; max-width: 800px; padding: 2rem; background: #1a1a1a; border: 2px solid #ff66c4; border-radius: 16px; box-shadow: 0 0 20px rgba(255, 102, 196, 0.4);">
  <h2 style="color: #ff90d6; margin-bottom: 1rem;">📬 Get In Touch</h2>
  <p style="color: #f4c4eb; margin-bottom: 1.5rem;">
    Seeking SOC Analyst Level 1 / Security Operations roles in Melbourne.<br>
    Open to contract or permanent positions.
  </p>
  <p style="color: #ffb3ff;">
    <a href="https://linkedin.com/in/tate-pannam-8b64b23a3" target="_blank" style="color: #00d9ff;">LinkedIn</a> •
    <a href="https://github.com/inkedqt" target="_blank" style="color: #00d9ff;">GitHub</a> •
    <a href="https://youtube.com/@inksec" target="_blank" style="color: #00d9ff;">YouTube</a>
  </p>
</div>
