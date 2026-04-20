#!/usr/bin/env python3
"""
get_wiki_commands.py
Extracts code blocks from wiki/tools/*.md and merges them into commands-data.js.
Uses the paragraph immediately above each code block as the auto-filled desc.

Usage:
  python3 _labs/get_wiki_commands.py              # add new commands from all pages
  python3 _labs/get_wiki_commands.py kql          # single page only
  python3 _labs/get_wiki_commands.py --refresh    # re-extract descs for all wiki entries
"""

import os
import re
import json
import sys

WIKI_TOOLS_DIR = os.path.expanduser(
    "~/Documents/Obsidian_vault/Hack Academy's Blue Team Obsidian Notes/wiki/tools"
)
OUTPUT_JS = os.path.expanduser(
    "~/portfolio-v2/blue-team/commands/commands-data.js"
)

TOOL_PATTERNS = [
    ("volatility", [r"\bvol\.py\b", r"\bvol\s+-f\b", r"windows\.\w+", r"volatility"]),
    ("splunk",     [r"\bindex=", r"\bsourcetype=", r"\bstats\s+", r"\btable\s+_time", r"\bdedup\b"]),
    ("zeek",       [r"sourcetype=zeek", r"\bzeek:", r"tx_hosts=", r"id\.orig_h"]),
    ("wireshark",  [r"http\.request", r"http\.response", r"tcp\.stream", r"ip\.src\s*==",
                    r"ip\.dst\s*==", r"ip\.addr\s*==", r"dns\.qry", r"ntlmssp\.",
                    r"smb2\.", r"llmnr", r"tcp\.port"]),
    ("nmap",       [r"\bnmap\b"]),
    ("aws",        [r"\baws\s+s3\b", r"\baws\s+cloudtrail\b", r"\baws\s+iam\b",
                    r"\baws\s+ec2\b", r"\baws\b"]),
    ("python",     [r"^\s*python3?\b", r"^\s*import\s", r"^\s*pip\b"]),
    ("powershell", [r"^\s*(?:Get-|Set-|New-|Remove-|Invoke-|Write-|Read-)",
                    r"\bPowerShell\b", r"\.ps1\b"]),
    ("tshark",     [r"\btshark\b"]),
    ("grep",       [r"^\s*grep\b"]),
]

LANG_TOOL_MAP = {
    "kql":        "kql",
    "powershell": "powershell",
    "python":     "python",
    "sql":        "sql",
    "cmd":        "shell",
}


def detect_tool(command: str) -> str:
    for tool, patterns in TOOL_PATTERNS:
        for pat in patterns:
            if re.search(pat, command, re.IGNORECASE):
                return tool
    return "shell"


def clean_markdown(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\*(.+?)\*",     r"\1", text)
    text = re.sub(r"`(.+?)`",        r"\1", text)
    text = re.sub(r"\[(.+?)\]\(.+?\)", r"\1", text)
    return text.strip()


def get_preceding_desc(content: str, block_start: int) -> str:
    """
    Scan backwards from block_start, skipping complete fenced code blocks,
    to find the nearest prose line or heading.
    """
    text_before = content[:block_start].rstrip("\n")
    lines = text_before.split("\n")

    in_fence   = False
    last_heading = ""

    for line in reversed(lines):
        stripped = line.strip()

        # Toggle fence state — going backwards, each ``` flips us in/out of a block
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue

        # Inside a previous code block — skip
        if in_fence:
            continue

        if not stripped:
            continue

        # Table row — skip
        if stripped.startswith("|"):
            continue

        # Heading — save as fallback and stop
        if stripped.startswith("#"):
            last_heading = clean_markdown(re.sub(r"^#+\s*", "", stripped))
            break

        # Prose line — return it
        stripped = re.sub(r"^[-*]\s+", "", stripped)
        result = clean_markdown(stripped)
        if result:
            return result

    return last_heading


def load_existing(filepath: str):
    if not os.path.exists(filepath):
        return [], {}
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    match = re.search(r"const COMMANDS_DATA = (\[.*?\]);", content, re.DOTALL)
    if not match:
        print("ERROR: Could not parse existing commands-data.js — aborting to prevent data loss.")
        sys.exit(1)
    try:
        existing_list = json.loads(match.group(1))
        existing_dict = {e["command"].strip(): e for e in existing_list}
        return existing_list, existing_dict
    except json.JSONDecodeError as e:
        print(f"ERROR: JSON parse error — {e} — aborting to prevent data loss.")
        sys.exit(1)


def write_output(filepath: str, commands: list):
    tool_set = sorted(set(c["tool"] for c in commands))
    lab_set  = sorted(set(c["lab"] for c in commands if c.get("source") != "wiki"))
    meta = {"total": len(commands), "labs": len(lab_set), "tools": tool_set}
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("// Auto-generated — do not edit manually\n")
        f.write("// Labs: python3 _labs/get_commands.py <labname>\n")
        f.write("// Wiki: python3 _labs/get_wiki_commands.py\n\n")
        f.write(f"const COMMANDS_DATA = {json.dumps(commands, indent=2)};\n")
        f.write(f"\nconst COMMANDS_META = {json.dumps(meta, indent=2)};\n")


def extract_commands(filepath: str, page_name: str) -> list:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = re.compile(
        r"```(bash|kql|cmd|powershell|python|sql)\s*\n(.*?)```",
        re.DOTALL | re.IGNORECASE,
    )

    results = []
    for match in pattern.finditer(content):
        lang          = match.group(1).strip().lower()
        block_content = match.group(2)

        lines = block_content.strip().split("\n")
        tool_override = None
        clean_lines   = []
        for line in lines:
            tm = re.match(r"#\s*tool:\s*(\w+)", line.strip())
            if tm:
                tool_override = tm.group(1).lower()
            elif line.strip() and not line.strip().startswith("#"):
                clean_lines.append(line.strip())

        if not clean_lines:
            continue

        full_command = " ".join(clean_lines)
        tool = tool_override or LANG_TOOL_MAP.get(lang) or detect_tool(full_command)
        desc = get_preceding_desc(content, match.start())

        results.append({
            "command": full_command,
            "tool":    tool,
            "lab":     page_name,
            "lab_url": "",
            "source":  "wiki",
            "desc":    desc,
            "tags":    f"wiki {tool} {page_name}",
        })

    return results


def refresh_wiki_descs(existing_list: list) -> int:
    """Re-extract desc for every existing wiki entry using the improved extractor."""
    page_cache = {}
    updated = 0

    for entry in existing_list:
        if entry.get("source") != "wiki":
            continue
        page_name = entry["lab"]
        filepath  = os.path.join(WIKI_TOOLS_DIR, page_name + ".md")
        if not os.path.exists(filepath):
            continue

        if page_name not in page_cache:
            with open(filepath, "r", encoding="utf-8") as f:
                page_cache[page_name] = f.read()

        content = page_cache[page_name]
        pattern = re.compile(
            r"```(bash|kql|cmd|powershell|python|sql)\s*\n(.*?)```",
            re.DOTALL | re.IGNORECASE,
        )

        for match in pattern.finditer(content):
            block_content = match.group(2)
            lines = block_content.strip().split("\n")
            clean_lines = [
                l.strip() for l in lines
                if l.strip() and not l.strip().startswith("#")
                and not re.match(r"#\s*tool:\s*", l.strip())
            ]
            if not clean_lines:
                continue
            candidate = " ".join(clean_lines)
            if candidate.strip() == entry["command"].strip():
                new_desc = get_preceding_desc(content, match.start())
                if new_desc != entry.get("desc", ""):
                    entry["desc"] = new_desc
                    updated += 1
                break

    return updated


def main():
    args = sys.argv[1:]

    # --refresh mode: re-extract descs for all existing wiki entries
    if "--refresh" in args:
        print("Refresh mode — re-extracting descriptions for all wiki entries...")
        existing_list, _ = load_existing(OUTPUT_JS)
        updated = refresh_wiki_descs(existing_list)
        if updated > 0:
            write_output(OUTPUT_JS, existing_list)
            print(f"  Updated {updated} descriptions")
            print(f"  Total commands unchanged: {len(existing_list)}")
        else:
            print("  No descriptions changed.")
        return

    target_page = args[0].lower().replace(".md", "") if args else None

    pages = [
        f for f in sorted(os.listdir(WIKI_TOOLS_DIR))
        if f.endswith(".md") and (not target_page or f.lower().replace(".md", "") == target_page)
    ]

    if not pages:
        print(f"No pages found{' matching: ' + target_page if target_page else ''}")
        sys.exit(0)

    existing_list, existing_dict = load_existing(OUTPUT_JS)
    print(f"Existing commands-data.js: {len(existing_list)} commands\n")

    total_added = total_skipped = 0

    for fname in pages:
        page_name = fname.replace(".md", "")
        filepath  = os.path.join(WIKI_TOOLS_DIR, fname)
        print(f"Processing: {fname}")

        new_cmds = extract_commands(filepath, page_name)
        if not new_cmds:
            print("  no code blocks found — skipping\n")
            continue

        print(f"  extracted {len(new_cmds)} commands")
        added = skipped = 0
        for cmd in new_cmds:
            key = cmd["command"].strip()
            if key in existing_dict:
                skipped += 1
            else:
                existing_list.append(cmd)
                existing_dict[key] = cmd
                added += 1
                print(f"  ++ {key[:72]}")

        if skipped:
            print(f"  skipped {skipped} duplicate(s)")
        print()
        total_added   += added
        total_skipped += skipped

    if total_added > 0:
        write_output(OUTPUT_JS, existing_list)
        print(f"── Done ──────────────────────────────────────────────────")
        print(f"  Added   : {total_added}")
        print(f"  Skipped : {total_skipped}")
        print(f"  Total   : {len(existing_list)} commands in commands-data.js")
    else:
        print("Nothing new to write — file unchanged.")


if __name__ == "__main__":
    main()
