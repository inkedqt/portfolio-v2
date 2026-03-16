#!/usr/bin/env python3
"""
lab_to_js.py — parse a lab's index.md frontmatter and inject the entry
into labs-data.js (or a custom target via --inject).

Default target: looks for labs-data.js by walking up from the lab folder,
or falls back to LABS_DATA env var, or accepts --inject <path> explicitly.

Usage:
  python3 lab_to_js.py <lab_folder>                  # auto-find labs-data.js
  python3 lab_to_js.py <lab_folder> --inject <path>  # explicit target
  python3 lab_to_js.py <lab_folder> --dry-run        # print entry, don't write
"""

import sys
import yaml
import os
import re


# ── FRONTMATTER ────────────────────────────────────────────────────────────────

def parse_frontmatter(path):
    with open(path) as f:
        content = f.read()
    parts = content.split('---')
    if len(parts) < 3:
        raise ValueError(f"No frontmatter found in {path}")
    return yaml.safe_load(parts[1])


# ── ENTRY BUILDER ──────────────────────────────────────────────────────────────

def to_js_array(val):
    if isinstance(val, list):
        return '[' + ', '.join(f"'{v}'" for v in val) + ']'
    elif isinstance(val, str):
        return "['" + val + "']"
    return '[]'


def build_entry(fm):
    name     = fm.get('title', '').replace(' Lab', '').replace('"', '').replace("'", "\\'")
    platform = fm.get('platform', '')
    diff     = fm.get('difficulty', 'Easy')
    cats     = fm.get('category', [])
    tools    = fm.get('tools', [])
    tactics  = fm.get('tactics', [])
    mitre    = fm.get('mitre', [])   # explicit T-codes in frontmatter e.g. mitre: [T1059.003, T1547.001]
    skill    = fm.get('skill', 'Endpoint Forensics')
    proof    = fm.get('proof', None)
    art      = fm.get('art', None)
    writeup  = fm.get('permalink', '')
    summary  = fm.get('summary', '').strip('"').strip("'").replace("'", "\\'")
    type_    = fm.get('type', 'lab')

    # Merge cats / tools / tactics into one array, then append any explicit mitre codes
    all_cats = []
    for v in [cats, tools, tactics]:
        if isinstance(v, list):
            all_cats += v
        elif isinstance(v, str):
            v = v.strip().lstrip('[').rstrip(']')
            all_cats += [x.strip() for x in v.split(',')]

    # Explicit mitre T-codes go at the end of cats, deduplicated
    # Handle both list and Obsidian-quoted string e.g. '[T1055, T1071.001]'
    if isinstance(mitre, str):
        mitre = [x.strip() for x in mitre.strip().lstrip('[').rstrip(']').split(',')]
    if isinstance(mitre, list):
        for code in mitre:
            code = str(code).strip()
            if code and code not in all_cats:
                all_cats.append(code)

    skill_js = '[' + ', '.join(f"'{s}'" for s in skill) + ']' if isinstance(skill, list) else f"'{skill}'"
    proof_js = f"'{proof}'" if proof else 'null'
    art_js   = f"'{art}'" if art else 'null'

    return f"""  {{
    name:     '{name}',
    skill:    {skill_js},
    platform: '{platform}',
    diff:     '{diff}',
    cats:     {to_js_array(all_cats)},
    status:   'done',
    score:    null,
    summary:  '{summary}',
    art:      {art_js},
    writeup:  '{writeup}',
    proof:    {proof_js},
    type:     '{type_}',
  }},"""


# ── INJECT ─────────────────────────────────────────────────────────────────────

def inject_into_file(entry, target_path):
    """Append entry before the closing ];\n in labs-data.js (or any JS/HTML file)."""
    with open(target_path, 'r') as f:
        content = f.read()

    # Duplicate check by lab name
    name_match = re.search(r"name:\s*'([^']+)'", entry)
    if name_match:
        lab_name = name_match.group(1)
        if f"name:     '{lab_name}'" in content:
            print(f"  !! '{lab_name}' already exists in {target_path} — skipping")
            return False

    # Insert before the final ];\n
    # Works for both labs-data.js and legacy index.html
    marker = '\n];\n'
    if marker not in content:
        print(f"  !! Could not find array closing '];' in {target_path} — inject failed")
        return False

    new_content = content.replace(marker, f'\n{entry}\n{marker}', 1)

    with open(target_path, 'w') as f:
        f.write(new_content)

    print(f"  ++ Injected '{name_match.group(1) if name_match else '?'}' into {target_path}")
    return True


# ── TARGET RESOLUTION ──────────────────────────────────────────────────────────

def find_labs_data(start_dir):
    """
    Walk up from start_dir looking for labs-data.js.
    Also checks LABS_DATA env var as an override.
    """
    # Env var override
    env = os.environ.get('LABS_DATA')
    if env and os.path.isfile(env):
        return env

    # Walk up the directory tree
    current = os.path.abspath(start_dir)
    for _ in range(8):  # max 8 levels up
        candidate = os.path.join(current, 'labs-data.js')
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    return None


# ── MAIN ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 lab_to_js.py <lab_folder> [--inject <path>] [--dry-run]")
        sys.exit(1)

    folder   = sys.argv[1].rstrip('/')
    dry_run  = '--dry-run' in sys.argv
    index_md = os.path.join(folder, 'index.md')

    if not os.path.exists(index_md):
        print(f"Error: {index_md} not found")
        sys.exit(1)

    fm    = parse_frontmatter(index_md)
    entry = build_entry(fm)

    # ── Dry run: just print ──
    if dry_run:
        print(entry)
        return

    # ── Explicit --inject target ──
    if '--inject' in sys.argv:
        inject_idx = sys.argv.index('--inject')
        if inject_idx + 1 >= len(sys.argv):
            print("Error: --inject requires a file path")
            sys.exit(1)
        target = sys.argv[inject_idx + 1]
        inject_into_file(entry, target)
        return

    # ── Default: auto-find labs-data.js ──
    target = find_labs_data(folder)
    if target:
        inject_into_file(entry, target)
    else:
        # Couldn't find labs-data.js — print to stdout as fallback so nothing is lost
        print(f"  ?? labs-data.js not found from '{folder}' — printing to stdout instead")
        print(f"     Set LABS_DATA=/path/to/labs-data.js to fix this\n")
        print(entry)


if __name__ == '__main__':
    main()
