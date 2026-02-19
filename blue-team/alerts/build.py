#!/usr/bin/env python3
"""
build.py — inksec.io alert pipeline
Scans 01_Active_Alerts/*.md, parses frontmatter,
copies files to _investigations/ with Jekyll front matter,
outputs alerts-data.js with url field for alerts.html.

Usage:
  python build.py
  python build.py --vault /path/to/01_Active_Alerts
  python build.py --out /path/to/alerts-data.js
  python build.py --investigations /path/to/portfolio-v2/_investigations

Daily workflow:
  1. Finish investigation in Obsidian
  2. python build.py
  3. cd ~/portfolio-v2 && git add . && git commit -m "add SOCxxx" && git push
"""

import re
import json
import shutil
import argparse
from pathlib import Path
from datetime import datetime

# ── CONFIG ────────────────────────────────────────────────────────────────────
DEFAULT_VAULT          = Path("/home/tate/Documents/Obsidian_vault/Hack Academy's Blue Team Obsidian Notes/SOC/01_Active_Alerts")
DEFAULT_OUT            = Path("/home/tate/portfolio-v2/alerts-data.js")
DEFAULT_INVESTIGATIONS = Path("/home/tate/portfolio-v2/_investigations")

# ── FRONTMATTER PARSER ────────────────────────────────────────────────────────
def parse_frontmatter(text):
    """
    Extract YAML frontmatter. Handles both:
      inline:    tags: [a, b, c]
      multiline: tags:\n  - a\n  - b
    """
    match = re.match(r'^---\s*\n(.*?)\n---', text, re.DOTALL)
    if not match:
        return {}

    fm = {}
    lines = match.group(1).splitlines()
    current_key  = None
    current_list = None

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        # multiline list item
        if stripped.startswith('- ') and current_list is not None:
            current_list.append(stripped[2:].strip().strip('"').strip("'"))
            continue

        # new key — save any pending list
        if ':' in stripped:
            if current_list is not None:
                fm[current_key] = current_list
                current_list = None

            key, _, val = stripped.partition(':')
            key = key.strip()
            val = val.strip()

            if val == '':
                current_key  = key
                current_list = []
            elif val.startswith('[') and val.endswith(']'):
                inner = val[1:-1]
                fm[key] = [v.strip().strip('"').strip("'") for v in inner.split(',') if v.strip()]
            elif val.startswith('"') and val.endswith('"'):
                fm[key] = val[1:-1]
            elif val.startswith("'") and val.endswith("'"):
                fm[key] = val[1:-1]
            else:
                fm[key] = val

    if current_list is not None:
        fm[current_key] = current_list

    return fm

# ── FILENAME PARSER ───────────────────────────────────────────────────────────
def parse_filename(stem):
    parts    = [p.strip() for p in stem.split(' - ', 2)]
    date_str = parts[0] if len(parts) > 0 else ''
    alert_id = parts[1] if len(parts) > 1 else ''
    title_fn = parts[2] if len(parts) > 2 else stem
    return date_str, alert_id, title_fn

# ── SLUG GENERATOR ────────────────────────────────────────────────────────────
def make_slug(stem):
    slug = stem.lower()
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'[\s_]+', '-', slug)
    slug = re.sub(r'-+', '-', slug)
    return slug.strip('-')

# ── TAG SPLITTER ──────────────────────────────────────────────────────────────
def split_tags(tags):
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

# ── JEKYLL FILE WRITER ────────────────────────────────────────────────────────
def write_investigation(md_file, dest_dir, title, slug):
    dest_dir.mkdir(parents=True, exist_ok=True)
    # use slug as filename — spaces in filenames break Jekyll silently
    dest_file = dest_dir / (slug + '.md')
    original  = md_file.read_text(encoding='utf-8', errors='ignore')

    # inject title into frontmatter if not already there
    fm_match = re.match(r'^(---\s*\n)(.*?)(\n---)', original, re.DOTALL)
    if fm_match and 'title:' not in fm_match.group(2):
        new_content = (
            fm_match.group(1)
            + f'title: "{title}"\n'
            + fm_match.group(2)
            + fm_match.group(3)
            + original[fm_match.end():]
        )
        dest_file.write_text(new_content, encoding='utf-8')
    else:
        dest_file.write_text(original, encoding='utf-8')

# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vault',          default=str(DEFAULT_VAULT))
    parser.add_argument('--out',            default=str(DEFAULT_OUT))
    parser.add_argument('--investigations', default=str(DEFAULT_INVESTIGATIONS))
    parser.add_argument('--no-copy',        action='store_true')
    args = parser.parse_args()

    alerts_dir = Path(args.vault)
    invest_dir = Path(args.investigations)

    if not alerts_dir.exists():
        print(f"[ERROR] Vault directory not found: {alerts_dir}")
        return

    alerts  = []
    skipped = []

    for md_file in sorted(alerts_dir.glob('*.md'), reverse=True):
        stem = md_file.stem
        text = md_file.read_text(encoding='utf-8', errors='ignore')
        fm   = parse_frontmatter(text)

        file_type = fm.get('type', '').lower()
        if file_type and file_type not in ('soc-case', 'soc_case'):
            skipped.append(f"  skip (type={file_type}): {stem}")
            continue

        date_fn, alert_id_fn, title_fn = parse_filename(stem)

        date     = fm.get('date',     date_fn)
        alert_id = fm.get('alert_id', alert_id_fn)
        title    = fm.get('title',    title_fn)
        platform = fm.get('platform', 'letsdefend')
        status   = fm.get('status',   'closed')
        severity = fm.get('severity', '')
        outcome  = fm.get('outcome',  '')

        for fmt in ('%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y'):
            try:
                date = datetime.strptime(str(date), fmt).strftime('%Y-%m-%d')
                break
            except ValueError:
                pass

        raw_tags    = fm.get('tags', [])
        mitre, cats = split_tags(raw_tags)
        slug        = make_slug(stem)
        url         = f'/investigations/{slug}/'

        alerts.append({
            'id':       alert_id,
            'title':    title,
            'date':     str(date),
            'platform': platform,
            'severity': severity.lower(),
            'status':   status.lower(),
            'outcome':  outcome.lower(),
            'mitre':    mitre,
            'tags':     cats,
            'url':      url,
        })
        print(f"  [OK] {date} · {alert_id} · {title[:50]}")

        if not args.no_copy:
            write_investigation(md_file, invest_dir, title, slug)

    if skipped:
        print("\nSkipped:")
        for s in skipped: print(s)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    js  = f"// AUTO-GENERATED by build.py — do not edit manually\n"
    js += f"// Last built: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    js += f"// Total alerts: {len(alerts)}\n\n"
    js += f"const ALERTS = {json.dumps(alerts, indent=2)};\n"
    out_path.write_text(js, encoding='utf-8')

    print(f"\n✓ {len(alerts)} alerts written to {out_path}")
    if not args.no_copy:
        print(f"✓ investigation pages synced to {invest_dir}")

if __name__ == '__main__':
    main()
