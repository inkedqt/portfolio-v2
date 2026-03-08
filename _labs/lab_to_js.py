#!/usr/bin/env python3
import sys
import yaml
import json
import os
import re

def parse_frontmatter(path):
    with open(path) as f:
        content = f.read()
    parts = content.split('---')
    if len(parts) < 3:
        raise ValueError("No frontmatter found")
    return yaml.safe_load(parts[1])

def to_js_array(val):
    if isinstance(val, list):
        return '[' + ', '.join(f"'{v}'" for v in val) + ']'
    elif isinstance(val, str):
        return "['" + val + "']"
    return '[]'

def build_entry(fm):
    name     = fm.get('title', '').replace(' Lab', '').replace('"', '')
    platform = fm.get('platform', '')
    diff     = fm.get('difficulty', 'Easy')
    cats     = fm.get('category', [])
    tools    = fm.get('tools', [])
    tactics  = fm.get('tactics', [])
    skill    = fm.get('skill', 'Endpoint Forensics')
    proof    = fm.get('proof', None)
    art      = fm.get('art', None)
    writeup  = fm.get('permalink', '')
    summary  = fm.get('summary', '').strip('"').strip("'")

    all_cats = []
    for v in [cats, tools, tactics]:
        if isinstance(v, list):
            all_cats += v
        elif isinstance(v, str):
            v = v.strip().lstrip('[').rstrip(']')
            all_cats += [x.strip() for x in v.split(',')]

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
  }},"""

def inject_into_html(entry, html_path):
    with open(html_path, 'r') as f:
        content = f.read()

    # Check if lab already exists by name
    name_match = re.search(r"name:\s*'([^']+)'", entry)
    if name_match:
        lab_name = name_match.group(1)
        if f"name:     '{lab_name}'" in content:
            print(f"  !! '{lab_name}' already exists in {html_path} — skipping inject")
            return

    # Insert before closing ];\n
    new_content = content.replace('\n];\n', f'\n{entry}\n\n];\n', 1)

    if new_content == content:
        print(f"  !! Could not find array closing in {html_path} — inject failed")
        return

    with open(html_path, 'w') as f:
        f.write(new_content)

    print(f"  ++ Injected into {html_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python lab_to_js.py <folder> [--inject /path/to/index.html]")
        sys.exit(1)

    folder = sys.argv[1].rstrip('/')
    index = os.path.join(folder, 'index.md')

    if not os.path.exists(index):
        print(f"Error: {index} not found")
        sys.exit(1)

    fm = parse_frontmatter(index)
    entry = build_entry(fm)

    # Check for --inject flag
    if '--inject' in sys.argv:
        inject_idx = sys.argv.index('--inject')
        if inject_idx + 1 < len(sys.argv):
            html_path = sys.argv[inject_idx + 1]
            inject_into_html(entry, html_path)
        else:
            print("Error: --inject requires a path to index.html")
            sys.exit(1)
    else:
        print(entry)

if __name__ == '__main__':
    main()
