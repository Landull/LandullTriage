#!/usr/bin/env python3
"""
Download the memory acquisition tool for this platform into assets/bin before building:

  Windows: WinPmem  (Velocidex/WinPmem, Apache 2.0)  -> assets/bin/winpmem.exe
  Linux:   AVML     (microsoft/avml, MIT)            -> assets/bin/avml
  macOS:   nothing (no free RAM capture on modern macOS)

The build scripts and the GitHub Actions workflow run this automatically. Versions and SHA-256
hashes are written to assets/bin/TOOLS.txt, which ships inside the app.
"""

import hashlib
import json
import os
import re
import stat
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "assets", "bin")

TOOLS = {
    "win32": ("Velocidex/WinPmem", r"^winpmem_mini_x64.*\.exe$", "winpmem.exe"),
    "linux": ("microsoft/avml", r"^avml$", "avml"),
}


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "LandullTriage-build", "Accept": "application/vnd.github+json"})
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def fetch(platform=None):
    plat = platform or ("win32" if sys.platform.startswith("win") else sys.platform)
    plat = "linux" if plat.startswith("linux") else plat
    if plat not in TOOLS:
        print("No memory acquisition tool to bundle on this platform.")
        return 0
    repo, pattern, out_name = TOOLS[plat]
    os.makedirs(BIN, exist_ok=True)
    dest = os.path.join(BIN, out_name)
    if os.path.exists(dest) and os.path.getsize(dest) > 100_000:
        print(f"{out_name} already present")
        return 0
    releases = json.loads(_get(f"https://api.github.com/repos/{repo}/releases?per_page=15"))
    for rel in releases:
        if rel.get("draft"):
            continue
        for a in rel.get("assets", []):
            if re.match(pattern, a["name"]):
                print(f"Downloading {repo} {rel['tag_name']}: {a['name']}")
                data = _get(a["browser_download_url"])
                with open(dest, "wb") as fh:
                    fh.write(data)
                if not plat.startswith("win"):
                    os.chmod(dest, os.stat(dest).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                digest = hashlib.sha256(data).hexdigest()
                with open(os.path.join(BIN, "TOOLS.txt"), "a", encoding="utf-8") as fh:
                    fh.write(f"{out_name}\t{repo}\t{rel['tag_name']}\t{a['name']}\t{len(data)} bytes\tsha256 {digest}\n")
                print(f"  -> {dest} ({len(data)} bytes, sha256 {digest})")
                return 0
    print(f"No release asset matching {pattern} in {repo}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(fetch(sys.argv[1] if len(sys.argv) > 1 else None))
