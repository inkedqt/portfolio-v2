#!/usr/bin/env python3
"""
retrofit_notes.py — inksec.io investigation note formatter
Converts plain text section headers to proper markdown headers
in existing Obsidian investigation notes.

Usage:
  python retrofit_notes.py
  python retrofit_notes.py --dir /path/to/01_Active_Alerts
  python retrofit_notes.py --dry-run   (preview without writing)
"""

import re
import argparse
from pathlib import Path

# ── CONFIG ────────────────────────────────────────────────────────────────────
DEFAULT_DIR = Path("/home/tate/Documents/Obsidian_vault/Hack Academy's Blue Team Obsidian Notes/SOC/01_Active_Alerts")

# ── SECTION MAP ───────────────────────────────────────────────────────────────
# Plain text label → markdown header replacement
# Order matters — more specific patterns first
SECTION_MAP = [
    # Main sections
    (r'^## 🧾 Alert Summary\s*$',   '## 🧾 Alert Summary'),   # already correct
    (r'^Alert Summary\s*$',          '## 🧾 Alert Summary'),
    (r'^MITRE ATT&CK\s*$',           '## 🎯 MITRE ATT&CK'),
    (r'^MITRE ATTACK\s*$',           '## 🎯 MITRE ATT&CK'),
    (r'^## MITRE ATT&CK\s*$',        '## 🎯 MITRE ATT&CK'),   # already correct, normalise emoji
    (r'^Investigation\s*$',          '## 🔍 Investigation'),
    (r'^## 🔍 Investigation\s*$',    '## 🔍 Investigation'),   # already correct
    (r'^Analysis\s*$',               '## 🧠 Analysis'),
    (r'^## 🧠 Analysis\s*$',         '## 🧠 Analysis'),        # already correct
    (r'^Response\s*$',               '## 📋 Response'),
    (r'^## 📋 Response\s*$',         '## 📋 Response'),        # already correct
    # 5W subsections
    (r'^Who\s*$',                    '### 👤 Who'),
    (r'^### 👤 Who\s*$',             '### 👤 Who'),            # already correct
    (r'^What\s*$',                   '### 🔎 What'),
    (r'^### 🔎 What\s*$',            '### 🔎 What'),           # already correct
    (r'^When\s*$',                   '### 🕐 When'),
    (r'^### 🕐 When\s*$',            '### 🕐 When'),           # already correct
    (r'^Where\s*$',                  '### 📍 Where'),
    (r'^### 📍 Where\s*$',           '### 📍 Where'),          # already correct
    (r'^Why\s*$',                    '### 💡 Why'),
    (r'^### 💡 Why\s*$',             '### 💡 Why'),            # already correct
]

def retrofit_file(path: Path, dry_run: bool = False) -> tuple[bool, list]:
    """
    Process a single .md file.
    Returns (changed: bool, changes: list of descriptions)
    """
    text = path.read_text(encoding='utf-8', errors='ignore')

    # Split into frontmatter and body
    fm_match = re.match(r'^(---\s*\n.*?\n---\s*\n)', text, re.DOTALL)
    if fm_match:
        frontmatter = fm_match.group(1)
        body = text[fm_match.end():]
    else:
        frontmatter = ''
        body = text

    original_body = body
    changes = []

    lines = body.split('\n')
    new_lines = []

    for line in lines:
        matched = False
        for pattern, replacement in SECTION_MAP:
            if re.match(pattern, line):
                if line.strip() != replacement:
                    changes.append(f'  {repr(line.strip())} → {repr(replacement)}')
                    new_lines.append(replacement)
                else:
                    new_lines.append(line)
                matched = True
                break
        if not matched:
            new_lines.append(line)

    new_body = '\n'.join(new_lines)

    if new_body != original_body:
        if not dry_run:
            path.write_text(frontmatter + new_body, encoding='utf-8')
        return True, changes
    return False, []


def main():
    parser = argparse.ArgumentParser(description='Retrofit investigation notes to proper markdown headers')
    parser.add_argument('--dir',     default=str(DEFAULT_DIR), help='Path to 01_Active_Alerts folder')
    parser.add_argument('--dry-run', action='store_true',      help='Preview changes without writing')
    args = parser.parse_args()

    notes_dir = Path(args.dir)
    if not notes_dir.exists():
        print(f'[ERROR] Directory not found: {notes_dir}')
        return

    mode = 'DRY RUN' if args.dry_run else 'WRITING'
    print(f'[{mode}] Retrofitting notes in: {notes_dir}\n')

    total = 0
    changed = 0

    for md_file in sorted(notes_dir.glob('*.md')):
        total += 1
        was_changed, changes = retrofit_file(md_file, dry_run=args.dry_run)
        if was_changed:
            changed += 1
            status = '✓ updated' if not args.dry_run else '~ would update'
            print(f'{status}: {md_file.name}')
            for c in changes:
                print(c)
        else:
            print(f'  ok: {md_file.name}')

    print(f'\n{"─"*50}')
    print(f'Total: {total} files · {changed} updated')
    if args.dry_run:
        print('Run without --dry-run to apply changes.')


if __name__ == '__main__':
    main()
