#!/usr/bin/env python3
"""
newlab_cd.py
Scrapes a CyberDefenders lab page and creates a pre-filled index.md in the Obsidian vault.

Usage:
  python3 newlab_cd.py <lab-url>
  python3 newlab_cd.py https://cyberdefenders.org/blueteam-ctf-challenges/xmrig/
  python3 newlab_cd.py <lab-url> --cookie "sessionid=xxx"
  python3 newlab_cd.py <lab-url> --dry-run

Cookie:
  DevTools (F12) → Storage → Cookies → https://cyberdefenders.org
  Copy the sessionid value only.
  Cached to ~/.cd_cookie between runs.
"""

import re
import sys
import json
import argparse
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[newlab_cd] ERROR: requests not installed — pip install requests")
    sys.exit(1)

# ── Paths ──────────────────────────────────────────────────────────────────────

VAULT_LABS  = Path.home() / "Documents/Obsidian_vault/Hack Academy's Blue Team Obsidian Notes/Cyber_Defenders/LABS"
COOKIE_CACHE = Path.home() / ".cd_cookie"
CD_BASE     = "https://cyberdefenders.org"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-AU,en;q=0.9",
    "Referer": "https://cyberdefenders.org/",
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
    print("── CyberDefenders Cookie Setup ──────────────────────────────")
    print("DevTools (F12) → Storage → Cookies → https://cyberdefenders.org")
    print("Need: _Secure-sessionid and _Secure-csrftoken")
    print()
    session = input("_Secure-sessionid value → ").strip().removeprefix("_Secure-sessionid=")
    csrf    = input("_Secure-csrftoken value  → ").strip().removeprefix("_Secure-csrftoken=")
    if not session:
        print("[newlab_cd] No session provided — aborting")
        sys.exit(1)
    cookie = f"_Secure-sessionid={session}"
    if csrf:
        cookie += f"; _Secure-csrftoken={csrf}"
    save_cookie(cookie)
    print(f"[newlab_cd] Cookie cached to {COOKIE_CACHE}")
    return cookie


def get_cookie(args) -> str:
    if args.cookie:
        cookie = args.cookie.strip()
        save_cookie(cookie)
        return cookie
    cached = load_cached_cookie()
    if cached:
        return cached
    return prompt_cookie()

# ── URL / slug helpers ─────────────────────────────────────────────────────────

def slug_from_url(url: str) -> str:
    """https://cyberdefenders.org/blueteam-ctf-challenges/xmrig/  →  xmrig"""
    path = urlparse(url).path.rstrip("/")
    return path.split("/")[-1]


def normalise_url(url: str) -> str:
    url = url.rstrip("/")
    if not url.endswith("/"):
        url += "/"
    return url

# ── Scraper ────────────────────────────────────────────────────────────────────

def scrape(url: str, cookie: str) -> dict | None:
    headers = {**HEADERS, "Cookie": cookie}
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    html = resp.text

    # Check for redirect to login
    if "/accounts/login" in resp.url or "login" in resp.url.lower():
        print("[newlab_cd] Cookie invalid or expired")
        COOKIE_CACHE.unlink(missing_ok=True)
        return None

    # ── Parse contextData JSON blob ────────────────────────────────────────────
    # CD server-renders all lab metadata as JSON in a <script id="contextData"> tag
    ctx_match = re.search(
        r'<script[^>]+id="contextData"[^>]*type="application/json"[^>]*>(.*?)</script>',
        html, re.DOTALL
    )
    if not ctx_match:
        print("[newlab_cd] contextData JSON not found — page structure may have changed")
        return None

    try:
        ctx = json.loads(ctx_match.group(1))
    except json.JSONDecodeError as e:
        print(f"[newlab_cd] Failed to parse contextData JSON: {e}")
        return None

    lab = ctx.get("lab", {})
    if not lab:
        print("[newlab_cd] No lab data in contextData")
        return None

    # ── Extract fields from JSON ───────────────────────────────────────────────
    title      = lab.get("name", "")
    slug       = lab.get("slug", slug_from_url(url))
    difficulty = lab.get("difficulty", "medium").capitalize()
    lab_image  = lab.get("lab_image", "")
    art        = f"{CD_BASE}{lab_image}" if lab_image else ""
    objective  = lab.get("learning_objective", "")
    meta_desc  = lab.get("meta_description", "")
    scenario   = objective or meta_desc  # learning_objective is the scenario equivalent

    # Categories
    categories = [c["title"] for c in lab.get("categories", [])]
    category   = categories[0] if categories else "Incident Response"

    # Tactics
    tactics = [t["title"] for t in lab.get("tactics", [])]

    # Tools
    tools = [t["title"] for t in lab.get("tools", [])]

    # MITRE IDs — CD doesn't always put them in contextData, scan HTML as fallback
    mitre_ids = list(dict.fromkeys(re.findall(r'\b(T\d{4}(?:\.\d{3})?)\b', html)))

    # ── Fetch questions via API ────────────────────────────────────────────────
    lab_id = lab.get("id")
    questions = fetch_questions(slug, cookie, lab_id)

    return {
        "title":      title,
        "slug":       slug,
        "difficulty": difficulty,
        "category":   category,
        "tactics":    tactics,
        "tools":      tools,
        "mitre":      mitre_ids,
        "art":        art,
        "scenario":   scenario,
        "questions":  questions,
        "url":        url,
    }


def fetch_questions(slug: str, cookie: str, lab_id: int | None = None) -> list[str]:
    """
    CD questions are Vue-rendered client-side and gated behind lab enrollment.
    Not accessible via REST API or headless scraping.
    Q&A blocks are populated as placeholders — fill manually from the lab page.
    """
    return []


def extract_question_text(items: list) -> list[str]:
    """Extract text from various CD question response shapes."""
    questions = []
    for item in items:
        if isinstance(item, dict):
            for key in ("question", "text", "title", "description", "body"):
                if key in item and isinstance(item[key], str) and item[key].strip():
                    questions.append(item[key].strip())
                    break
        elif isinstance(item, str) and item.strip():
            questions.append(item.strip())
    return questions

# ── Template builder ───────────────────────────────────────────────────────────

def build_frontmatter(data: dict) -> str:
    title      = data["title"]
    labname    = data["slug"]
    diff       = data["difficulty"]
    category   = data["category"]
    tools_str  = ", ".join(data["tools"])
    tactics_str = ", ".join(data["tactics"])
    mitre_str  = ", ".join(data["mitre"])
    art        = data["art"]
    url        = data["url"]

    scenario_short = data["scenario"][:120].replace('"', "'") if data["scenario"] else ""
    summary = f'"{scenario_short}..."' if scenario_short else '""'

    return f"""---
layout: lab
title: {title}
platform: CyberDefenders
difficulty: {diff}
category: {category}
skill: {category}
tools: "{tools_str}"
tactics: "{tactics_str}"
mitre: "[{mitre_str}]"
proof:
challenge_url: {url}
permalink: /blue-team/labs/{labname}/
summary: {summary}
art: {art}
type: cyberdefenders
points:
youtube:
locked: tate
---"""


def build_qa_blocks(questions: list[str]) -> str:
    source = questions if questions else ["QUESTION"] * 10
    copy_btn = "event.stopPropagation();navigator.clipboard.writeText(this.previousElementSibling.textContent);this.textContent='copied';setTimeout(()=>this.textContent='copy',1500)"
    blocks = []
    for i, q in enumerate(source):
        div_class   = "flag-reveal" if i % 2 == 0 else "answer-reveal"
        placeholder = "Click flag to reveal" if div_class == "flag-reveal" else "Click to reveal answer"
        block = (
            f'<div class="qa-item"> '
            f'<div class="qa-question-text">{q}</div> '
            f'<div class="{div_class}"> '
            f'<input type="checkbox"> '
            f'<span class="r-placeholder">{placeholder}</span> '
            f'<span class="r-answer">ANSWER</span> '
            f'<button class="copy-btn" onclick="{copy_btn}">copy</button> '
            f'</div> </div>'
        )
        blocks.append(block)
    return "\n\n".join(blocks)


def build_template(data: dict) -> str:
    fm      = build_frontmatter(data)
    scenario = data["scenario"] or "TODO: paste scenario."
    qa      = build_qa_blocks(data["questions"])

    mitre_rows = ""
    for tid in data["mitre"]:
        mitre_rows += f"|TODO|{tid}|TODO|\n"

    tactics_display = ", ".join(data["tactics"]) if data["tactics"] else "TODO"

    return f"""{fm}
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

# ── Writer ─────────────────────────────────────────────────────────────────────

def write_lab(labname: str, content: str, dry_run: bool, force: bool):
    if dry_run:
        print("\n" + "─" * 60)
        print(content)
        print("─" * 60)
        print(f"\n[newlab_cd] dry-run — would write to {VAULT_LABS / labname / 'index.md'}")
        return

    lab_dir = VAULT_LABS / labname
    lab_dir.mkdir(parents=True, exist_ok=True)
    out = lab_dir / "index.md"

    if out.exists() and not force:
        print(f"[newlab_cd] WARNING: {out} already exists — use --force to overwrite")
        return

    out.write_text(content)
    print(f"\n[newlab_cd] ✓ Created {out}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Create a pre-filled CyberDefenders lab writeup in the Obsidian vault")
    parser.add_argument("url",       help="CyberDefenders lab URL")
    parser.add_argument("--cookie",  help="sessionid cookie value", default=None)
    parser.add_argument("--dry-run", action="store_true", help="Print output without writing")
    parser.add_argument("--force",   action="store_true", help="Overwrite existing index.md")
    args = parser.parse_args()

    url     = normalise_url(args.url)
    labname = slug_from_url(url)
    print(f"[newlab_cd] Lab: {labname}  ({url})")

    cookie = get_cookie(args)

    print(f"[newlab_cd] Scraping...")
    data = scrape(url, cookie)

    if not data:
        print("[newlab_cd] Scrape failed — cookie may have expired")
        print(f"[newlab_cd] Delete {COOKIE_CACHE} and re-run to re-enter cookie")
        sys.exit(1)

    print(f"  title:      {data['title'] or '(not found)'}")
    print(f"  difficulty: {data['difficulty']}")
    print(f"  category:   {data['category']}")
    print(f"  tactics:    {data['tactics']}")
    print(f"  tools:      {data['tools']}")
    print(f"  mitre:      {data['mitre']}")
    print(f"  art:        {'✓' if data['art'] else '(not found)'}")
    print(f"  scenario:   {'✓' if data['scenario'] else '(not found)'}")
    print(f"  questions:  {len(data['questions'])} found")

    if not data['questions']:
        print(f"  [note] Questions are Vue-rendered/enrollment-gated — add Q&A blocks manually")

    content = build_template(data)
    write_lab(labname, content, args.dry_run, args.force)

    if not args.dry_run:
        print(f"\n[newlab_cd] Open: {VAULT_LABS / labname / 'index.md'}")


if __name__ == "__main__":
    main()
