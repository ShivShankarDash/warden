#!/usr/bin/env python3
"""Search YouTube with yt-dlp and keep only Creative Commons results.

  python tools/cc_search.py "prompt injection explained" [--n 30]
  python tools/cc_search.py fetch <url> --out build/clips/name.mp4 [--section 00:01:10-00:01:18] [--audio-only]

Every fetch is appended to build/clips/ATTRIBUTION.md (title, channel, URL, licence), which
goes into the video description. Downloads land in build/clips/ (treat as untrusted data).
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLIPS = ROOT / "build" / "clips"


def search(q: str, n: int) -> list[dict]:
    # flat search for ids, then full metadata (licence lives in the full info dict)
    ids = subprocess.run(["yt-dlp", f"ytsearch{n}:{q}", "--flat-playlist", "--print", "id"], capture_output=True, text=True).stdout.split()
    hits = []
    for vid in ids:
        r = subprocess.run(["yt-dlp", "-j", "--skip-download", f"https://www.youtube.com/watch?v={vid}"], capture_output=True, text=True)
        if r.returncode != 0:
            continue
        info = json.loads(r.stdout)
        lic = info.get("license") or ""
        if "creative commons" in lic.lower():
            hits.append({"url": info["webpage_url"], "title": info.get("title"), "channel": info.get("channel"),
                         "duration": info.get("duration"), "license": lic})
    return hits


def fetch(url: str, out: str, section: str | None, audio_only: bool) -> None:
    CLIPS.mkdir(parents=True, exist_ok=True)
    info = json.loads(subprocess.run(["yt-dlp", "-j", "--skip-download", url], capture_output=True, text=True, check=True).stdout)
    lic = info.get("license") or ""
    if "creative commons" not in lic.lower():
        raise SystemExit(f"refusing: licence is '{lic or 'unknown'}', not Creative Commons")
    cmd = ["yt-dlp", "-o", out, "--no-playlist", "--force-overwrites"]
    if audio_only:
        cmd += ["-x", "--audio-format", "mp3"]
    else:
        cmd += ["-f", "bv*[height<=1080][ext=mp4]+ba[ext=m4a]/b[height<=1080]", "--merge-output-format", "mp4"]
    if section:
        cmd += ["--download-sections", f"*{section}", "--force-keyframes-at-cuts"]
    subprocess.run(cmd + [url], check=True)
    with (CLIPS / "ATTRIBUTION.md").open("a") as f:
        f.write(f"- \"{info.get('title')}\" by {info.get('channel')} ({url}), {lic}" + (f", excerpt {section}" if section else "") + "\n")
    print(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("query_or_cmd")
    ap.add_argument("url", nargs="?")
    ap.add_argument("--n", type=int, default=25)
    ap.add_argument("--out")
    ap.add_argument("--section")
    ap.add_argument("--audio-only", action="store_true")
    a = ap.parse_args()
    if a.query_or_cmd == "fetch":
        fetch(a.url, a.out, a.section, a.audio_only)
    else:
        for h in search(a.query_or_cmd, a.n):
            print(json.dumps(h))


if __name__ == "__main__":
    main()
