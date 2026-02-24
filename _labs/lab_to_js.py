#!/usr/bin/env python3
import sys
import yaml
import json
import os

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

def main():
    if len(sys.argv) < 2:
        print("Usage: python lab_to_js.py <folder>")
        sys.exit(1)

    folder = sys.argv[1].rstrip('/')
    index = os.path.join(folder, 'index.md')

    if not os.path.exists(index):
        print(f"Error: {index} not found")
        sys.exit(1)

    fm = parse_frontmatter(index)

    name     = fm.get('title', '').replace(' Lab', '').replace('"', '')
    platform = fm.get('platform', '')
    diff     = fm.get('difficulty', 'Easy')
    cats     = fm.get('category', [])
    tools    = fm.get('tools', [])
    tactics  = fm.get('tactics', [])
    proof    = fm.get('proof', None)
    writeup  = fm.get('permalink', '')
    summary  = fm.get('summary', '').strip('"').strip("'")

    # merge cats + tools + tactics into cats array for the filter
    all_cats = []
    for v in [cats, tools, tactics]:
        if isinstance(v, list):
            all_cats += v
        elif isinstance(v, str):
            v = v.strip().lstrip('[').rstrip(']')
            all_cats += [x.strip() for x in v.split(',')]

    proof_js = f"'{proof}'" if proof else 'null'

    print(f"""  {{
    name:     '{name}',
    platform: '{platform}',
    diff:     '{diff}',
    cats:     {to_js_array(all_cats)},
    status:   'done',
    score:    null,
    summary:  '{summary}',
    writeup:  '{writeup}',
    proof:    {proof_js},
  }},""")

if __name__ == '__main__':
    main()
