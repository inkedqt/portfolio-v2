#!/usr/bin/env python3
"""
newlab.py
Scrapes a BTLO lab page and creates a pre-filled index.md in the Obsidian vault.

Usage:
  python3 newlab.py <lab-url>
  python3 newlab.py https://blueteamlabs.online/home/investigation/glazed-ba5693be7b
  python3 newlab.py <lab-url> --cookie "btlo_session=x; XSRF-TOKEN=y"
  python3 newlab.py <lab-url> --dry-run    # print output, don't write file

Cookie:
  Same as btlo_scraper.py — DevTools → Storage → Cookies → blueteamlabs.online
  Copy btlo_session + XSRF-TOKEN values.
  Cached to ~/.btlo_cookie between runs — only re-enter when expired.
"""

import re
import sys
import argparse
import textwrap
from datetime import date
from pathlib import Path
from urllib.parse import unquote, urlparse

try:
    import requests
except ImportError:
    print("[newlab] ERROR: requests not installed — pip install requests")
    sys.exit(1)

# ── Paths ──────────────────────────────────────────────────────────────────────

VAULT_LABS = Path.home() / "Documents/Obsidian_vault/Hack Academy's Blue Team Obsidian Notes/Cyber_Defenders/LABS"
COOKIE_CACHE = Path.home() / ".btlo_cookie"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-AU,en;q=0.9",
    "Referer": "https://blueteamlabs.online/",
}

# ── Cookie handling ────────────────────────────────────────────────────────────

def load_cached_cookie() -> str | None:
    if COOKIE_CACHE.exists():
        return COOKIE_CACHE.read_text().strip() or None
    return None


def save_cookie(cookie: str):
    COOKIE_CACHE.write_text(cookie)
    COOKIE_CACHE.chmod(0o600)


def prompt_cookie() -> str:
    print()
    print("── BTLO Cookie Setup ─────────────────────────────────────────")
    print("DevTools (F12) → Storage → Cookies → https://blueteamlabs.online")
    print()
    session = input("btlo_session value → ").strip().removeprefix("btlo_session=")
    xsrf    = input("XSRF-TOKEN value   → ").strip().removeprefix("XSRF-TOKEN=")
    if not session or not xsrf:
        print("[newlab] Cookie input incomplete — aborting")
        sys.exit(1)
    cookie = f"btlo_session={session}; XSRF-TOKEN={xsrf}"
    save_cookie(cookie)
    print(f"[newlab] Cookie cached to {COOKIE_CACHE}")
    return cookie


def get_cookie(args) -> str:
    if args.cookie:
        cookie = unquote(args.cookie.strip())
        save_cookie(cookie)
        return cookie
    cached = load_cached_cookie()
    if cached:
        return cached
    return prompt_cookie()

# ── URL / slug helpers ─────────────────────────────────────────────────────────

def slug_from_url(url: str) -> str:
    """glazed-ba5693be7b  →  glazed"""
    path = urlparse(url).path.rstrip("/")
    segment = path.split("/")[-1]           # glazed-ba5693be7b
    # strip trailing hash-like suffix (8+ hex chars after last hyphen)
    labname = re.sub(r'-[0-9a-f]{8,}$', '', segment)
    return labname


def normalise_url(url: str) -> str:
    """Ensure URL has no trailing slash."""
    return url.rstrip("/")

# ── Scraper ────────────────────────────────────────────────────────────────────

def scrape(url: str, cookie: str) -> dict | None:
    cookie = unquote(cookie)
    headers = {**HEADERS, "Cookie": cookie}
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    html = resp.text

    if 'action="https://blueteamlabs.online/login"' in html or "login" in resp.url.lower():
        print("[newlab] Cookie invalid or expired — re-run to enter fresh cookie")
        COOKIE_CACHE.unlink(missing_ok=True)
        return None

    def find(pattern, default=""):
        m = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else default

    def findall(pattern):
        return re.findall(pattern, html, re.IGNORECASE | re.DOTALL)

    # ── Title ──────────────────────────────────────────────────────────────────
    # BTLO renders title in an h1 or large heading — try a few patterns
    title = find(r'<h1[^>]*>\s*(.*?)\s*</h1>')
    if not title:
        title = find(r'class="[^"]*text-2xl[^"]*"[^>]*>\s*(.*?)\s*<')
    if not title:
        title = find(r'<title>\s*BTLO\s*[-|]\s*(.*?)\s*</title>')

    # ── Difficulty ─────────────────────────────────────────────────────────────
    # Anchor tightly to the Difficulty label to avoid landing on unrelated coloured badges
    difficulty = find(r'Difficulty\s*(?:<[^>]+>\s*){1,4}(Easy|Medium|Hard)\s*<')
    if not difficulty:
        difficulty = find(r'Difficulty[^<]*</[^>]+>\s*<[^>]+>\s*<[^>]+>\s*(Easy|Medium|Hard)')

    # ── Category / Skill ───────────────────────────────────────────────────────
    # BTLO uses category labels like "Incident Response", "Digital Forensics" etc
    category = find(r'(?:Category|Investigation Type)\s*[:\-]?\s*</[^>]+>\s*<[^>]+>\s*([\w\s&]+?)\s*<')
    if not category:
        # look for the category pill/badge  
        category = find(r'class="[^"]*badge[^"]*"[^>]*>\s*(Incident Response|Digital Forensics|Security Operations|Threat Intelligence|Reverse Engineering|Malware Analysis|Endpoint Forensics|Network Forensics|Cloud)\s*<')

    # ── Tools (badge chips) ────────────────────────────────────────────────────
    # Tool chips appear as coloured spans/divs — grab all non-MITRE, non-difficulty badges
    all_badges = findall(r'class="[^"]*(?:badge|chip|tag|rounded-full)[^"]*"[^>]*>\s*([\w\s\+\#\.\-]+?)\s*<')
    # Filter out MITRE IDs, difficulty words, platform names, and blank/whitespace entries
    skip = {'easy', 'medium', 'hard', 'btlo', 'windows', 'linux', 'free', 'pro'}
    mitre_pat = re.compile(r'^T\d{4}(?:\.\d{3})?$')
    tools = [b.strip() for b in all_badges if b.strip() and not mitre_pat.match(b.strip()) and b.strip().lower() not in skip]
    # Deduplicate while preserving order
    seen = set()
    tools = [t for t in tools if not (t in seen or seen.add(t))]

    # ── MITRE IDs ──────────────────────────────────────────────────────────────
    # Grab T#### and T####.### patterns from anywhere in the page
    mitre_ids = list(dict.fromkeys(re.findall(r'\b(T\d{4}(?:\.\d{3})?)\b', html)))

    # ── Art URL ────────────────────────────────────────────────────────────────
    art = find(r'(https://blueteamlabs\.online/storage/labs/[^"\'>\s]+\.(?:png|jpg|jpeg|webp))')

    # ── Scenario ───────────────────────────────────────────────────────────────
    # The actual scenario text sits in a plain div after the "Scenario" heading
    # From the HTML: two adjacent "Scenario" divs, then the real paragraph
    # Match the paragraph that follows the second Scenario label
    scenario = find(r'Scenario\s*</[^>]+>\s*<[^>]+>\s*Scenario\s*</[^>]+>\s*<[^>]+>\s*(.*?)\s*</div>')
    if not scenario:
        # fallback: grab largest text block after "Scenario" keyword
        scenario = find(r'Scenario[^<]*</[^>]+>\s*<[^>]*>\s*([A-Z][^<]{40,}?)\s*</(?:p|div)>')
    # Clean up any residual HTML tags
    scenario = re.sub(r'<[^>]+>', '', scenario).strip()
    scenario = re.sub(r'\s+', ' ', scenario)

    # ── Questions ──────────────────────────────────────────────────────────────
    # Anchor to the "Investigation Submission" section to avoid nav bleed
    submission_match = re.search(r'Investigation Submission(.*?)$', html, re.DOTALL | re.IGNORECASE)
    question_scope = submission_match.group(1) if submission_match else html

    # Format A: "1) Question text (N points)" — numbered
    questions = re.findall(r'\d+\)\s*(.*?)\s*\(\d+\s*points?\)', question_scope, re.DOTALL)

    # Format B: plain "Question text" with separate (N points) span — unnumbered
    # e.g. "PID and PPID of Viruskiller executable  (3 points)"
    if not questions:
        questions = re.findall(
            r'([A-Z][^<\n]{10,}?)\s*(?:<[^>]+>\s*)?\(\d+\s*points?\)',
            question_scope, re.DOTALL
        )

    # Strip HTML tags and collapse whitespace
    cleaned = []
    for q in questions:
        q = re.sub(r'<[^>]+>', '', q).strip()
        q = re.sub(r'\s+', ' ', q)
        if q:
            cleaned.append(q)
    questions = cleaned

    return {
        "title":      title,
        "difficulty": difficulty or "Medium",
        "category":   category or "Incident Response",
        "tools":      tools,
        "mitre":      mitre_ids,
        "art":        art,
        "scenario":   scenario,
        "questions":  questions,
        "url":        url,
    }

# ── Template builder ───────────────────────────────────────────────────────────

def build_frontmatter(data: dict, labname: str) -> str:
    title     = data["title"] or labname.title()
    diff      = data["difficulty"]
    category  = data["category"]
    tools_str = ", ".join(data["tools"]) if data["tools"] else ""
    mitre_str = ", ".join(data["mitre"]) if data["mitre"] else ""
    art       = data["art"] or ""
    url       = data["url"]
    today     = date.today().isoformat()

    # summary: single line, no newlines
    scenario_short = data["scenario"][:120].replace('"', "'") if data["scenario"] else ""
    summary = f'"{scenario_short}..."' if scenario_short else '""'

    fm = f"""---
layout: lab
title: {title}
platform: BTLO
difficulty: {diff}
category: {category}
skill: {category}
tools: "{tools_str}"
tactics:
mitre: "[{mitre_str}]"
proof:
challenge_url: {url}
permalink: /blue-team/labs/{labname}/
summary: {summary}
art: {art}
type: btlo
points:
youtube:
locked: tate
---"""
    return fm


def build_qa_blocks(questions: list[str]) -> str:
    if not questions:
        # Default empty blocks if scrape didn't get questions
        return """<div class="qa-item"> <div class="qa-question-text">QUESTION</div> <div class="flag-reveal"> <input type="checkbox"> <span class="r-placeholder">Click flag to reveal</span> <span class="r-answer">ANSWER</span> <button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)">copy</button> </div> </div>"""

    blocks = []
    for i, q in enumerate(questions):
        # Alternate flag-reveal / answer-reveal
        div_class = "flag-reveal" if i % 2 == 0 else "answer-reveal"
        placeholder = "Click flag to reveal" if div_class == "flag-reveal" else "Click to reveal answer"
        block = (
            f'<div class="qa-item"> '
            f'<div class="qa-question-text">{q}</div> '
            f'<div class="{div_class}"> '
            f'<input type="checkbox"> '
            f'<span class="r-placeholder">{placeholder}</span> '
            f'<span class="r-answer">ANSWER</span> '
            f'<button class="copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent=\'copied\';setTimeout(()=>this.textContent=\'copy\',1500)">copy</button> '
            f'</div> </div>'
        )
        blocks.append(block)
    return "\n\n".join(blocks)


def build_template(data: dict, labname: str) -> str:
    fm      = build_frontmatter(data, labname)
    scenario = data["scenario"] or "TODO: paste scenario."
    qa      = build_qa_blocks(data["questions"])

    mitre_rows = ""
    for tid in data["mitre"]:
        mitre_rows += f"|TODO|{tid}|TODO|\n"

    template = f"""{fm}
## Scenario

{scenario}

---

## Methodology

TODO

---

## Attack Summary

|Phase|Action|
|---|---|
|TODO|TODO|

---

## IOCs

|Type|Value|
|---|---|
|TODO|TODO|

---

## MITRE ATT&CK

|Technique|ID|Description|
|---|---|---|
{mitre_rows if mitre_rows else "|TODO|TODO|TODO|"}

---

## Defender Takeaways

TODO

---

{qa}
"""
    return template

# ── Writer ─────────────────────────────────────────────────────────────────────

def write_lab(labname: str, content: str, dry_run: bool):
    if dry_run:
        print("\n" + "─" * 60)
        print(content)
        print("─" * 60)
        print(f"\n[newlab] dry-run — would write to {VAULT_LABS / labname / 'index.md'}")
        return

    lab_dir = VAULT_LABS / labname
    lab_dir.mkdir(parents=True, exist_ok=True)
    out = lab_dir / "index.md"

    if out.exists():
        print(f"[newlab] WARNING: {out} already exists — not overwriting")
        print(f"[newlab] Use --force to overwrite, or delete manually")
        return

    out.write_text(content)
    print(f"\n[newlab] ✓ Created {out}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Create a pre-filled BTLO lab writeup in the Obsidian vault")
    parser.add_argument("url",       help="BTLO lab URL")
    parser.add_argument("--cookie",  help="Session cookie string (btlo_session=x; XSRF-TOKEN=y)", default=None)
    parser.add_argument("--dry-run", action="store_true", help="Print output without writing")
    parser.add_argument("--force",   action="store_true", help="Overwrite existing index.md")
    args = parser.parse_args()

    url     = normalise_url(args.url)
    labname = slug_from_url(url)
    print(f"[newlab] Lab: {labname}  ({url})")

    cookie = get_cookie(args)

    print(f"[newlab] Scraping...")
    data = scrape(url, cookie)

    if not data:
        print("[newlab] Scrape failed — cookie may have expired")
        print(f"[newlab] Delete {COOKIE_CACHE} and re-run to re-enter cookie")
        sys.exit(1)

    # Report what was found
    print(f"  title:      {data['title'] or '(not found)'}")
    print(f"  difficulty: {data['difficulty']}")
    print(f"  category:   {data['category']}")
    print(f"  tools:      {data['tools']}")
    print(f"  mitre:      {data['mitre']}")
    print(f"  art:        {'✓' if data['art'] else '(not found)'}")
    print(f"  scenario:   {'✓' if data['scenario'] else '(not found)'}")
    print(f"  questions:  {len(data['questions'])} found")

    content = build_template(data, labname)

    if args.force and (VAULT_LABS / labname / "index.md").exists():
        (VAULT_LABS / labname / "index.md").unlink()

    write_lab(labname, content, args.dry_run)

    if not args.dry_run:
        print(f"\n[newlab] Open in Obsidian: {VAULT_LABS / labname / 'index.md'}")
        print(f"[newlab] Fill: proof, tools/tactics (check badges), MITRE descriptions, methodology")


if __name__ == "__main__":
    main()
