#!/usr/bin/env python3
"""Animatic: one still per narration line, held for the line's duration, cut to the real voice.

Run this BEFORE spending on renders or AI video. Each still comes from (in priority order):
  1. build/keyframes/<line_id>.png   AI keyframes (GPT Image 2.5 Sunburst via tools/media.py image)
  2. build/storyboard/<line_id>.png  hand-made or HyperFrames/Manim snapshot stills
  3. a frame grabbed from an existing draft render of that section (build/scenes or build/test)
  4. a title card with the line text (so the animatic is always complete)

  python tools/animatic.py           -> build/animatic/<scene>.mp4 per section, then
  python tools/assemble.py animatic  -> build/final/warden_animatic.mp4 (same OTIO timeline, VO + music)
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
B = ROOT / "build"
SCENE_FILE = {"intro": "intro", "problem": "problem", "demo": "demo", "ai": "pipeline", "features": "features", "impact": "impact"}


def title_card(text: str, label: str, out: Path) -> None:
    im = Image.new("RGB", (1920, 1080), (10, 14, 20))
    d = ImageDraw.Draw(im)
    font_dir = ROOT / "assets" / "fonts"
    big = ImageFont.truetype(str(font_dir / "Inter-SemiBold.ttf"), 46)
    small = ImageFont.truetype(str(font_dir / "Inter-SemiBold.ttf"), 26)
    d.text((140, 120), label.upper(), font=small, fill=(134, 182, 239))
    words, lines, cur = text.split(), [], ""
    for w in words:
        if d.textlength(cur + " " + w, font=big) > 1600:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    lines.append(cur)
    for i, ln in enumerate(lines):
        d.text((140, 420 + i * 64), ln, font=big, fill=(232, 237, 245))
    im.save(out)


def grab(video: Path, t: float, out: Path) -> bool:
    if not video.exists():
        return False
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-ss", f"{t:.2f}", "-i", str(video), "-frames:v", "1", "-vf", "scale=1920:1080", str(out)])
    return out.exists()


def main() -> None:
    tl = json.loads((ROOT / "plan" / "timeline.json").read_text())
    stills = B / "animatic" / "stills"
    stills.mkdir(parents=True, exist_ok=True)
    for s in tl["sections"]:
        segs = []
        for k, l in enumerate(s["lines"]):
            out = stills / f"{l['id']}.png"
            src = next((p for p in (B / "keyframes" / f"{l['id']}.png", B / "storyboard" / f"{l['id']}.png") if p.exists()), None)
            if src:
                Image.open(src).convert("RGB").resize((1920, 1080)).save(out)
            else:
                name = SCENE_FILE.get(s["id"], "closing")
                vid = next((p for p in (B / "scenes" / f"{name}.mp4", B / "test" / f"{name}_draft.mp4") if p.exists()), None)
                if not (vid and grab(vid, min(l["local"] + 1.2, s["duration"] - 0.2), out)):
                    title_card(l["text"], s["name"], out)
            start = 0 if k == 0 else l["local"]
            end = s["lines"][k + 1]["local"] if k + 1 < len(s["lines"]) else s["duration"]
            segs.append((out, end - start))
        lst = B / "animatic" / f"{s['id']}.txt"
        lst.write_text("".join(f"file '{p.resolve()}'\nduration {d:.3f}\n" for p, d in segs) + f"file '{segs[-1][0].resolve()}'\n")
        name = SCENE_FILE.get(s["id"], s["id"])
        target = B / "animatic" / f"{name}.mp4"
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(lst), "-vf", "fps=30,format=yuv420p",
                        "-c:v", "libx264", "-crf", "26", "-t", f"{s['duration']:.3f}", str(target)], check=True)
        if s["id"] == "closing":   # assemble.py expects closing (diagram) + endcard (from the 2nd line on)
            subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-loop", "1", "-i", str(segs[-1][0]), "-t", f"{segs[-1][1] + 1:.3f}",
                            "-vf", "fps=30,format=yuv420p", "-c:v", "libx264", "-crf", "26", str(B / "animatic" / "endcard.mp4")], check=True)
        print(f"{s['id']:9s} {len(segs)} stills -> {target.name}")


if __name__ == "__main__":
    main()
