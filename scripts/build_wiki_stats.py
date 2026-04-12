#!/usr/bin/env python3
"""
build_wiki_stats.py
Reads all wiki pages from the Obsidian vault and generates wiki-data.js for inksec.io

Usage:
  python3 scripts/build_wiki_stats.py

Output: ~/portfolio-v2/wiki-data.js
"""
# ── SETUP ──────────────────────────────────────────────────────────
# Reads YAML frontmatter + H1 headings from:
#   wiki/malware/     wiki/threat-actors/   wiki/ttps/
#   wiki/cves/        wiki/tools/
# Sorts each category by source_count descending.
# Re-run after any wiki update to refresh the portfolio stats page.
# ──────────────────────────────────────────────────────────────────

import re
from pathlib import Path
from datetime import datetime, timezone

VAULT_PATH = Path.home() / "Documents/Obsidian_vault/Hack Academy's Blue Team Obsidian Notes/wiki"
OUTPUT_PATH = Path.home() / "portfolio-v2/wiki-data.js"


# ── Parsers ───────────────────────────────────────────────────────

def parse_frontmatter(text):
    """Extract YAML frontmatter fields as a dict."""
    m = re.match(r'^---\n(.*?)\n---', text, re.DOTALL)
    if not m:
        return {}
    fm = {}
    for line in m.group(1).splitlines():
        if ':' not in line:
            continue
        key, _, val = line.partition(':')
        key = key.strip()
        val = val.strip()
        if val.startswith('[') and val.endswith(']'):
            items = [x.strip().strip('"\'') for x in val[1:-1].split(',') if x.strip()]
            fm[key] = items
        else:
            try:
                fm[key] = int(val)
            except ValueError:
                fm[key] = val
    return fm


def parse_h1(text):
    """Extract the first H1 heading."""
    m = re.search(r'^# (.+)$', text, re.MULTILINE)
    return m.group(1).strip() if m else ''


def parse_cvss(text):
    """Extract CVSS score + severity from a CVE page."""
    m = re.search(r'\*\*CVSS Score\*\*[:\s]+([\d.]+)\s*\((\w+)\)', text)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    m = re.search(r'CVSS[:\s]+([\d.]+)', text)
    return m.group(1) if m else 'N/A'


# ── Type derivation ───────────────────────────────────────────────

def malware_type(tags):
    """Human-readable malware type from frontmatter tags."""
    if 'ransomware' in tags and 'raas' in tags:
        return 'Ransomware / RaaS'
    if 'banking-trojan' in tags and 'loader' in tags:
        return 'Banking Trojan / Loader'
    priority = [
        ('ransomware',       'Ransomware'),
        ('banking-trojan',   'Banking Trojan'),
        ('infostealer',      'Info Stealer'),
        ('stealer',          'Info Stealer'),
        ('rat',              'Remote Access Trojan'),
        ('loader',           'Loader'),
        ('botnet',           'Botnet'),
        ('worm',             'Worm'),
        ('rootkit',          'Rootkit'),
        ('cryptominer',      'Cryptominer'),
        ('post-exploitation','Post-exploitation C2'),
        ('c2',               'C2 Framework'),
        ('macro',            'Macro-based'),
    ]
    for tag, label in priority:
        if tag in tags:
            return label
    return 'Malware'


def tactic_from_tags(tags):
    """MITRE tactic name from TTP frontmatter tags."""
    tactic_map = {
        'initial-access':        'Initial Access',
        'execution':             'Execution',
        'persistence':           'Persistence',
        'privilege-escalation':  'Privilege Escalation',
        'defense-evasion':       'Defense Evasion',
        'credential-access':     'Credential Access',
        'discovery':             'Discovery',
        'lateral-movement':      'Lateral Movement',
        'collection':            'Collection',
        'command-and-control':   'Command & Control',
        'exfiltration':          'Exfiltration',
        'impact':                'Impact',
        'reconnaissance':        'Reconnaissance',
        'resource-development':  'Resource Development',
    }
    for tag in tags:
        if tag in tactic_map:
            return tactic_map[tag]
    return 'Unknown'


def tool_category(tags):
    """Tool category from frontmatter tags."""
    checks = [
        ('network',          'Network Forensics'),
        ('pcap',             'Network Forensics'),
        ('siem',             'SIEM / Log Analysis'),
        ('memory',           'Memory Forensics'),
        ('disk',             'Disk Forensics'),
        ('endpoint',         'Endpoint Detection'),
        ('threat-intel',     'Threat Intelligence'),
        ('detection',        'Detection Engineering'),
        ('triage',           'Triage'),
        ('imaging',          'Forensic Imaging'),
        ('decoding',         'Data Analysis'),
        ('malware-detect',   'Malware Detection'),
        ('event-log',        'Event Log Analysis'),
    ]
    for tag in tags:
        for key, label in checks:
            if key in tag:
                return label
    return 'Security Tool'


# ── Loaders ───────────────────────────────────────────────────────

def load_malware():
    rows = []
    for f in sorted((VAULT_PATH / 'malware').glob('*.md')):
        text = f.read_text()
        fm = parse_frontmatter(text)
        tags = fm.get('tags', [])
        rows.append({
            'name':         parse_h1(text),
            'file':         f.stem,
            'type':         malware_type(tags),
            'source_count': fm.get('source_count', 0),
            'date_updated': fm.get('date_updated', ''),
        })
    return sorted(rows, key=lambda x: -x['source_count'])


def load_actors():
    rows = []
    for f in sorted((VAULT_PATH / 'threat-actors').glob('*.md')):
        text = f.read_text()
        fm = parse_frontmatter(text)
        tags = [t for t in fm.get('tags', []) if t != 'threat-actor']
        rows.append({
            'name':         parse_h1(text),
            'file':         f.stem,
            'source_count': fm.get('source_count', 0),
            'tags':         tags,
            'date_updated': fm.get('date_updated', ''),
        })
    return sorted(rows, key=lambda x: -x['source_count'])


def load_ttps():
    rows = []
    for f in sorted((VAULT_PATH / 'ttps').glob('*.md')):
        text = f.read_text()
        fm = parse_frontmatter(text)
        tags = fm.get('tags', [])
        # T1059-001.md → T1059.001 (only replace first hyphen after the 4-digit code)
        stem = f.stem
        tech_id = re.sub(r'^(T\d{4})-', r'\1.', stem)
        rows.append({
            'id':           tech_id,
            'name':         parse_h1(text),
            'tactic':       tactic_from_tags(tags),
            'source_count': fm.get('source_count', 0),
        })
    return sorted(rows, key=lambda x: -x['source_count'])


def load_cves():
    rows = []
    for f in sorted((VAULT_PATH / 'cves').glob('*.md')):
        text = f.read_text()
        fm = parse_frontmatter(text)
        h1 = parse_h1(text)
        # "CVE-2024-3400 — Palo Alto PAN-OS GlobalProtect Command Injection"
        product_m = re.search(r'CVE-[\d-]+\s*[—\-]+\s*(.+)', h1)
        product = product_m.group(1).strip() if product_m else h1
        rows.append({
            'id':           f.stem,
            'product':      product,
            'severity':     parse_cvss(text),
            'source_count': fm.get('source_count', 0),
        })
    return sorted(rows, key=lambda x: -x['source_count'])


def load_tools():
    rows = []
    for f in sorted((VAULT_PATH / 'tools').glob('*.md')):
        text = f.read_text()
        fm = parse_frontmatter(text)
        tags = fm.get('tags', [])
        rows.append({
            'name':         parse_h1(text),
            'file':         f.stem,
            'category':     tool_category(tags),
            'source_count': fm.get('source_count', 0),
        })
    return sorted(rows, key=lambda x: -x['source_count'])


# ── JS serialiser ─────────────────────────────────────────────────

def js_val(v):
    if isinstance(v, str):
        escaped = v.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return '[' + ', '.join(js_val(i) for i in v) + ']'
    return f'"{v}"'


def js_array(items, indent=2):
    pad = ' ' * indent
    lines = ['[']
    for item in items:
        fields = ', '.join(f'{k}: {js_val(v)}' for k, v in item.items())
        lines.append(f'{pad}  {{ {fields} }},')
    lines.append(f'{pad}]')
    return '\n'.join(lines)


# ── Writer ────────────────────────────────────────────────────────

def write_js(malware, actors, ttps, cves, tools):
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    total_pages = len(malware) + len(actors) + len(ttps) + len(cves) + len(tools)
    total_sources = sum(
        x['source_count']
        for x in malware + actors + ttps + cves + tools
    )

    js = f"""// Auto-generated by scripts/build_wiki_stats.py — do not edit manually
// Last updated: {now}
// Run: python3 scripts/build_wiki_stats.py
// Source: Obsidian vault wiki/ (malware, threat-actors, ttps, cves, tools)

const WIKI_DATA = {{
  malware: {js_array(malware)},
  actors: {js_array(actors)},
  ttps: {js_array(ttps)},
  cves: {js_array(cves)},
  tools: {js_array(tools)},
  meta: {{
    generated_at: "{now}",
    total_pages: {total_pages},
    total_sources: {total_sources}
  }}
}};
"""
    OUTPUT_PATH.write_text(js)
    print(f"\n[build_wiki_stats] ✓ Written to {OUTPUT_PATH}")
    print(f"  malware families:  {len(malware)}")
    print(f"  threat actors:     {len(actors)}")
    print(f"  TTP pages:         {len(ttps)}")
    print(f"  CVE pages:         {len(cves)}")
    print(f"  tool pages:        {len(tools)}")
    print(f"  total pages:       {total_pages}")
    print(f"  total sources:     {total_sources}")
    print(f"  generated:         {now}")


# ── Main ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    malware = load_malware()
    actors  = load_actors()
    ttps    = load_ttps()
    cves    = load_cves()
    tools   = load_tools()
    write_js(malware, actors, ttps, cves, tools)
