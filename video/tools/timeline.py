#!/usr/bin/env python3
"""Lay narration lines on a master clock and emit plan/timeline.json.

Every visual (Manim scene, HyperFrames composition, Motion Canvas scene, footage cut)
reads its section's start/duration and per-line cue times from this file, so pictures
are cut to the voice rather than the other way round.

  python tools/timeline.py [--gap 0.45] [--lead 0.6]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Extra air before a section's first line (titles, transitions) and after its last line.
PAD = {
    "intro": (2.2, 0.6),
    "problem": (0.8, 0.6),
    "demo": (0.6, 0.8),
    "ai": (0.8, 0.6),
    "features": (0.6, 0.6),
    "impact": (0.6, 0.6),
    "closing": (0.6, 4.0),   # end card holds after the last word
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gap", type=float, default=0.45, help="silence between lines inside a section")
    a = ap.parse_args()
    script = json.loads((ROOT / "plan" / "script.json").read_text())
    man = json.loads((ROOT / "build" / "vo" / "manifest.json").read_text())

    t = 0.0
    sections = []
    for sec in script["sections"]:
        lead, tail = PAD.get(sec["id"], (0.6, 0.6))
        start = t
        t += lead
        lines = []
        for n, line in enumerate(sec["lines"], 1):
            name = f"{sec['id']}_{n:02d}"
            d = man[name]["duration"]
            lines.append({"id": name, "file": f"build/vo/{name}.wav", "start": round(t, 3), "local": round(t - start, 3),
                          "duration": d, "text": line["text"]})
            t += d + (a.gap if n < len(sec["lines"]) else 0)
        t += tail
        sections.append({"id": sec["id"], "name": sec["name"], "start": round(start, 3), "duration": round(t - start, 3), "lines": lines})

    out = {"fps": 30, "width": 1920, "height": 1080, "duration": round(t, 3), "sections": sections}
    (ROOT / "plan" / "timeline.json").write_text(json.dumps(out, indent=2))
    for s in sections:
        print(f"{s['id']:9s} start {s['start']:7.2f}  dur {s['duration']:6.2f}  cues " + " ".join(f"{l['local']:.1f}" for l in s["lines"]))
    print(f"TOTAL {t:.1f}s ({int(t // 60)}:{int(t % 60):02d})")


if __name__ == "__main__":
    main()
