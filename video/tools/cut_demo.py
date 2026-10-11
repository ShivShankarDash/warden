#!/usr/bin/env python3
"""Conform real screen footage to the narration.

Reads build/footage/terminal_marks.tsv (beat markers written while recording) and the
'demo' section cues in plan/timeline.json, then retimes each beat of the terminal take so
its action lands under the matching narration line. Speed is clamped to a natural range;
when a beat is too short it is held on its last frame rather than slowed to a crawl.
The dashboard beat uses hand-picked sub-clips of the Playwright take.

Outputs (1920x1080, 30 fps, no audio):
  build/footage/demo_base.mp4    the whole demo section, exactly section-length
  build/footage/review_cut.mp4   review-queue clip for the features section
  build/footage/cuts.json        the edit decision list (for OTIO and the critic)
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FT = ROOT / "build" / "footage"
MIN_SPEED, MAX_SPEED = 0.9, 2.6

# dashboard sub-clips (source seconds) chosen from dashboard_marks.tsv: tiles, heatmap + decision path, live feed + explain
DASH_CROP = "crop=1280:720:320:0"  # the dashboard content column, punched in to full frame
DASH_CLIPS = [(0.3, 4.6), (15.2, 19.6), (31.2, 36.2)]


def marks(path: Path) -> dict[str, float]:
    return {k: float(v) for k, v in (l.split("\t") for l in path.read_text().split("\n") if l.strip())}


def ff(*args: str) -> None:
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *args], check=True)


def seg(src: Path, a: float, b: float, target: float, out: Path, crop: str | None = None, size: str = "2880:1620") -> dict:
    """Cut [a,b] from src and fit it to `target` seconds."""
    src_d = b - a
    speed = max(MIN_SPEED, min(MAX_SPEED, src_d / target))
    played = src_d / speed
    hold = max(0.0, target - played)
    if played > target:  # too long even at max speed: trim the head (typing), keep the result
        a = b - target * speed
        played = target
    vf = []
    if crop:
        vf.append(crop)
    vf += [f"scale={size}:flags=lanczos", f"setpts=(PTS-STARTPTS)/{speed:.4f}", "fps=30"]
    if hold > 0.01:
        vf.append(f"tpad=stop_mode=clone:stop_duration={hold:.3f}")
    vf.append("format=yuv420p")
    ff("-ss", f"{a:.3f}", "-t", f"{b - a:.3f}", "-i", str(src), "-vf", ",".join(vf), "-t", f"{target:.3f}",
       "-an", "-c:v", "libx264", "-crf", "15", "-preset", "medium", "-g", "30", "-keyint_min", "30", "-movflags", "+faststart", str(out))
    return {"src": src.name, "in": round(a, 3), "out": round(b, 3), "speed": round(speed, 3), "hold": round(hold, 3), "duration": round(target, 3)}


def main() -> None:
    tl = json.loads((ROOT / "plan" / "timeline.json").read_text())
    demo = next(s for s in tl["sections"] if s["id"] == "demo")
    feat = next(s for s in tl["sections"] if s["id"] == "features")
    cues = [l["local"] for l in demo["lines"]]
    # beat boundaries on the section clock: start at 0, change at each later line cue, end at section end
    bounds = [0.0] + cues[1:] + [demo["duration"]]
    tm = marks(FT / "terminal_marks.tsv")
    term = FT / "terminal.mov"
    src_beats = [("install", "setup"), ("setup", "attack"), ("attack", "benign"), ("benign", "kiro"), ("kiro", "summary")]

    parts, edl = [], []
    tmp = FT / "cut_parts"
    tmp.mkdir(exist_ok=True)
    for i, (m0, m1) in enumerate(src_beats):
        a, b = tm[m0] - 0.3, tm[m1] - 0.2
        out = tmp / f"beat{i + 1}.mp4"
        e = seg(term, max(0, a), b, bounds[i + 1] - bounds[i], out)
        e.update(beat=demo["lines"][i]["id"], at=bounds[i])
        edl.append(e)
        parts.append(out)

    # dashboard beat
    total = bounds[-1] - bounds[5]
    each = total / len(DASH_CLIPS)
    for j, (a, b) in enumerate(DASH_CLIPS):
        out = tmp / f"dash{j + 1}.mp4"
        e = seg(FT / "dashboard.mp4", a, b, each, out, crop=DASH_CROP)
        e.update(beat=demo["lines"][5]["id"], at=round(bounds[5] + j * each, 3))
        edl.append(e)
        parts.append(out)

    lst = tmp / "list.txt"
    lst.write_text("".join(f"file '{p.name}'\n" for p in parts))
    ff("-f", "concat", "-safe", "0", "-i", str(lst), "-c", "copy", str(FT / "demo_base.mp4"))

    # features: review queue under the second features line
    fc = [l["local"] for l in feat["lines"]]
    rv = marks(FT / "review_marks.tsv") if (FT / "review_marks.tsv").exists() else {"open": 3.6, "end": 12.7}
    r = seg(FT / "review.mp4", rv["open"] + 0.3, rv["end"], feat["duration"] - fc[1] + 0.6, FT / "review_cut.mp4", crop=DASH_CROP, size="1920:1080")
    r.update(beat=feat["lines"][1]["id"], at=round(fc[1] - 0.6, 3))
    edl.append(r)

    (FT / "cuts.json").write_text(json.dumps(edl, indent=2))
    for e in edl:
        print(f"{e['beat']:12s} at {e['at']:6.2f}  {e['src']:14s} {e['in']:6.2f}-{e['out']:6.2f}  x{e['speed']}  hold {e['hold']}")
    d = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(FT / "demo_base.mp4")],
                       capture_output=True, text=True).stdout.strip()
    print(f"demo_base {d}s (section {demo['duration']}s)")


if __name__ == "__main__":
    main()
