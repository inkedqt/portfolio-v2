#!/usr/bin/env python3
"""
btlo_scraper.py
Scrapes the BTLO profile for inksec using a session cookie and writes assets/js/btlo-stats.js

Usage:
  python3 btlo_scraper.py                           # prompts for cookie
  python3 btlo_scraper.py --cookie "btlo_session=x; XSRF-TOKEN=y"
  python3 btlo_scraper.py --fallback                # write fallback values only

How to get your cookie:
  1. Log into blueteamlabs.online in your browser
  2. Open DevTools → Storage tab → Cookies → blueteamlabs.online
  3. Copy btlo_session value and XSRF-TOKEN value
  4. Paste as:  btlo_session=VALUE; XSRF-TOKEN=VALUE
"""
# ── HOW TO GET YOUR COOKIE (30 seconds) ──────────────────────────
# 1. Log into blueteamlabs.online in Zen Browser
# 2. Press F12 → Storage tab → Cookies → https://blueteamlabs.online
# 3. Run this script: python3 scripts/btlo_scraper.py
# 4. Copy the VALUE (not the name) for each field when prompted:
#      btlo_session  → long eyJ... string
#      XSRF-TOKEN    → long eyJ... string
# Note: cookies expire ~weekly, just grab fresh ones when it fails
# ─────────────────────────────────────────────────────────────────

import re
import sys
import argparse
import requests
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import unquote

PROFILE_URL = "https://blueteamlabs.online/home/user/32e88e341c0c66519ed676"
OUTPUT_PATH = Path("assets/js/btlo-stats.js")

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

# Fallback values — update manually when scrape fails
FALLBACK = {
    "username":         "inksec",
    "rank":             "Junior Defender",
    "points":           "1282",
    "global_position":  "416",
    "country_position": "23",
    "investigations":   "32",
    "challenges":       "23",
    "latest_lab":       "You're Hired!",
}


def scrape(cookie: str) -> dict:
    # URL-decode cookie in case it was copied with %3D etc
    cookie = unquote(cookie)
    headers = {**HEADERS, "Cookie": cookie}
    resp = requests.get(PROFILE_URL, headers=headers, timeout=15)
    resp.raise_for_status()
    html = resp.text

    # Check if we got redirected to login
    if "login" in resp.url.lower() or 'action="https://blueteamlabs.online/login"' in html:
        print("[btlo_scraper] Cookie appears invalid — redirected to login")
        return None

    def find(pattern, default="N/A"):
        m = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else default

    # Patterns matched against actual BTLO HTML structure from debug dump:
    # <div class="font-semibold text-3xl text-yellow-500">1282</div>
    # <div class="text-gray-600">Points <span class="opacity-0">Lorem</span></div>
    # Global/Country use text-yellow-400
    # Rank: <span style="color:#218c74">Junior Defender</span>

    # Points (yellow-500)
    points = find(r'<div[^>]*text-yellow-500[^>]*>\s*(\d[\d,]*)\s*</div>')

    # Global and Country positions (yellow-400, appear in order: global, country, points...)
    positions = re.findall(r'<div[^>]*text-yellow-400[^>]*>\s*(\d[\d,]*)\s*(?:\n\s*)?\n?\s*</div>', html)
    global_pos   = positions[0].replace(",", "") if len(positions) > 0 else FALLBACK["global_position"]
    country_pos  = positions[1].replace(",", "") if len(positions) > 1 else FALLBACK["country_position"]

    # Investigations and challenges (teal-400 and green-400)
    investigations = find(r'<div[^>]*text-teal-400[^>]*>\s*(\d+)\s*</div>')
    challenges_val = find(r'<div[^>]*text-green-400[^>]*>\s*(\d+)\s*</div>')

    # Rank from profile section
    rank = find(r'Rank:\s*<span[^>]*>\s*([\w\s]+?)\s*</span>')

    # Latest badge (first badge in Recent Badges list)
    latest_lab = find(r'<a class="font-medium" href="">(.*?)</a>')

    # Clean commas
    points = points.replace(",", "") if points != "N/A" else "N/A"

    if points == "N/A":
        print("[btlo_scraper] Parse failed — points not found")
        print("[btlo_scraper] The cookie may have expired or page structure changed")
        return None

    return {
        "username":         "inksec",
        "rank":             rank if rank != "N/A" else FALLBACK["rank"],
        "points":           points,
        "global_position":  global_pos,
        "country_position": country_pos,
        "investigations":   investigations if investigations != "N/A" else FALLBACK["investigations"],
        "challenges":       challenges_val if challenges_val != "N/A" else FALLBACK["challenges"],
        "latest_lab":       latest_lab if latest_lab != "N/A" else FALLBACK["latest_lab"],
    }


def write_js(data: dict):
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    updated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    js = f"""// Auto-generated by scripts/btlo_scraper.py — do not edit manually
// Last updated: {updated}
// Run: python3 scripts/btlo_scraper.py
// Paste your BTLO session cookie when prompted
// DevTools → Storage → Cookies → blueteamlabs.online
// Copy btlo_session + XSRF-TOKEN values, format as:
//   btlo_session=VALUE; XSRF-TOKEN=VALUE

const BTLO_STATS = {{
  username:        "{data['username']}",
  rank:            "{data['rank']}",
  points:          "{data['points']}",
  globalPosition:  "{data['global_position']}",
  countryPosition: "{data['country_position']}",
  investigations:  "{data['investigations']}",
  challenges:      "{data['challenges']}",
  latestLab:       "{data.get('latest_lab', '')}",
  updatedAt:       "{updated}",
  profileUrl:      "{PROFILE_URL}"
}};
"""
    OUTPUT_PATH.write_text(js)
    print(f"\n[btlo_scraper] ✓ Written to {OUTPUT_PATH}")
    print(f"  rank:            {data['rank']}")
    print(f"  points:          {data['points']}")
    print(f"  global position: #{data['global_position']}")
    print(f"  AU position:     #{data['country_position']}")
    print(f"  investigations:  {data['investigations']}")
    print(f"  challenges:      {data['challenges']}")
    print(f"  latest badge:    {data.get('latest_lab', '')}")
    print(f"  updated:         {updated}")


def get_cookie(args) -> str:
    if args.cookie:
        return args.cookie.strip()

    print()
    print("── BTLO Cookie Setup ─────────────────────────────────────────")
    print("DevTools (F12) → Storage → Cookies → https://blueteamlabs.online")
    print()

    session = input("btlo_session value → ").strip()
    if not session:
        print("[btlo_scraper] No session provided — using fallback values")
        return None
    # Strip prefix if user accidentally pasted the full key=value
    session = session.removeprefix("btlo_session=")

    xsrf = input("XSRF-TOKEN value   → ").strip()
    if not xsrf:
        print("[btlo_scraper] No XSRF token provided — using fallback values")
        return None
    xsrf = xsrf.removeprefix("XSRF-TOKEN=")

    cookie = f"btlo_session={session}; XSRF-TOKEN={xsrf}"
    print()
    return cookie


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape BTLO stats for inksec.io")
    parser.add_argument("--cookie",   help="Session cookie string", default=None)
    parser.add_argument("--fallback", help="Write fallback values without scraping", action="store_true")
    args = parser.parse_args()

    if args.fallback:
        print("[btlo_scraper] Writing fallback values")
        write_js(FALLBACK)
        sys.exit(0)

    cookie = get_cookie(args)

    if not cookie:
        print("[btlo_scraper] Writing fallback values")
        write_js(FALLBACK)
        sys.exit(0)

    try:
        data = scrape(cookie)
        if data:
            write_js(data)
        else:
            print("[btlo_scraper] Scrape failed — writing fallback values")
            write_js(FALLBACK)
            sys.exit(0)
    except Exception as e:
        print(f"[btlo_scraper] ERROR: {e}", file=sys.stderr)
        print("[btlo_scraper] Writing fallback values")
        write_js(FALLBACK)
        sys.exit(0)
