#!/usr/bin/env python3
"""
build.py — inksec.io alert pipeline
Scans SOC/01_Active_Alerts/*.md, parses frontmatter,
outputs alerts-data.js for alerts.html to consume.

Usage:
  python build.py
  python build.py --vault /path/to/obsidian/vault
  python build.py --out /path/to/inksec.io/alerts-data.js

Run this after each vault push, then push alerts-data.js to your site repo.
"""

import os
import re
import json
import argparse
from pathlib import Path
from datetime import datetime

# ── CONFIG ────────────────────────────────────────────────────────────────────
DEFAULT_VAULT = Path("/home/tate/Documents/Obsidian_vault/Hack Academy's Blue Team Obsidian Notes/SOC/01_Active_Alerts")

DEFAULT_OUT   = Path("/home/tate/portfolio-v2/alerts-data.js")

# ── FRONTMATTER PARSER ────────────────────────────────────────────────────────
def parse_frontmatter(text):
    """Extract YAML frontmatter from markdown. Returns dict."""
    match = re.match(r'^---\s*\n(.*?)\n---', text, re.DOTALL)
    if not match:
        return {}
    fm = {}
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' not in line:
            continue
        key, _, val = line.partition(':')
        key = key.strip()
        val = val.strip()
        # handle YAML lists: [a, b, c]
        if val.startswith('[') and val.endswith(']'):
            inner = val[1:-1]
            val = [v.strip().strip('"').strip("'") for v in inner.split(',') if v.strip()]
        # handle quoted strings
        elif val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        elif val.startswith("'") and val.endswith("'"):
            val = val[1:-1]
        fm[key] = val
    return fm

# ── FILENAME PARSER ───────────────────────────────────────────────────────────
def parse_filename(stem):
    """
    Extract date and alert_id from filename.
    Expected format: 2026-02-12 - SOC145 - Title Here
    Returns (date_str, alert_id, title_from_filename)
    """
    parts = [p.strip() for p in stem.split(' - ', 2)]
    date_str  = parts[0] if len(parts) > 0 else ''
    alert_id  = parts[1] if len(parts) > 1 else ''
    title_fn  = parts[2] if len(parts) > 2 else stem
    return date_str, alert_id, title_fn

# ── TAG SPLITTER ──────────────────────────────────────────────────────────────
def split_tags(tags):
    """
    Split tags list into mitre IDs and category tags.
    mitre/T1486 → mitre: ['T1486'], tags: []
    ransomware  → mitre: [],        tags: ['ransomware']
    """
    mitre = []
    cats  = []
    if isinstance(tags, str):
        tags = [tags]
    for t in (tags or []):
        t = t.strip()
        if t.lower().startswith('mitre/'):
            mitre.append(t.split('/', 1)[1].upper())
        elif t:
            cats.append(t)
    return mitre, cats

# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Build alerts-data.js from Obsidian vault')
    parser.add_argument('--vault', default=str(DEFAULT_VAULT), help='Path to Obsidian vault root')
    parser.add_argument('--out',   default=str(DEFAULT_OUT),   help='Output path for alerts-data.js')
    args = parser.parse_args()

    alerts_dir = Path(args.vault)

    if not alerts_dir.exists():
        print(f"[ERROR] Alerts directory not found: {alerts_dir}")
        print(f"        Check --vault path in script.")
        return

    alerts = []
    skipped = []

    for md_file in sorted(alerts_dir.glob('*.md'), reverse=True):
        stem = md_file.stem
        text = md_file.read_text(encoding='utf-8', errors='ignore')
        fm   = parse_frontmatter(text)

        # skip non-soc-case files (README, templates, etc.)
        if fm.get('type', '').lower() not in ('soc-case', 'soc_case', ''):
            if fm.get('type'):
                skipped.append(f"  skip (type={fm.get('type')}): {stem}")
                continue

        date_fn, alert_id_fn, title_fn = parse_filename(stem)

        # pull from frontmatter, fall back to filename
        date     = fm.get('date', date_fn)
        alert_id = fm.get('alert_id', alert_id_fn)
        title    = fm.get('title', title_fn)
        platform = fm.get('platform', 'letsdefend')
        status   = fm.get('status', 'closed')
        severity = fm.get('severity', '')
        outcome  = fm.get('outcome', '')

        # normalise date to ISO string
        for fmt in ('%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y'):
            try:
                date = datetime.strptime(str(date), fmt).strftime('%Y-%m-%d')
                break
            except ValueError:
                pass

        # split tags
        raw_tags = fm.get('tags', [])
        mitre, cats = split_tags(raw_tags)

        alert = {
            'id':       alert_id,
            'title':    title,
            'date':     str(date),
            'platform': platform,
            'severity': severity.lower(),
            'status':   status.lower(),
            'outcome':  outcome.lower(),
            'mitre':    mitre,
            'tags':     cats,
        }
        alerts.append(alert)
        print(f"  [OK] {date} · {alert_id} · {title[:50]}")

    if skipped:
        print("\nSkipped:")
        for s in skipped:
            print(s)

    # write output
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    js = f"// AUTO-GENERATED by build.py — do not edit manually\n"
    js += f"// Last built: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    js += f"// Total alerts: {len(alerts)}\n\n"
    js += f"const ALERTS = {json.dumps(alerts, indent=2)};\n"

    out_path.write_text(js, encoding='utf-8')
    print(f"\n✓ {len(alerts)} alerts written to {out_path}")

if __name__ == '__main__':
    main()
