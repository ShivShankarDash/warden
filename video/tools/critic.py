#!/usr/bin/env python3
"""Critic pass: check a rendered video against the plan, with screenshots and transcription.

  python tools/critic.py build/final/warden_demo.mp4 [--asr-model small.en]

Writes build/critic/:
  report.md            human-readable verdict with every finding
  report.json          machine-readable findings (severity, time, check, detail)
  sheet_<section>.png  contact sheet of frames sampled across each section (look at these)
  words.json           ASR word timings of the final mix (reused by the caption skill)

Checks
  video  black frames, frozen frames, resolution/fps, duration within the 2-4 minute brief
  audio  integrated loudness (target -14 LUFS for YouTube), true peak, long silences, clipping
  speech per-line similarity of ASR vs script, timing drift of each line vs plan,
         low-confidence key terms (product names)
  plan   every required section present, in order, with non-trivial duration
"""
from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "build" / "critic"
REQUIRED = ["intro", "problem", "demo", "ai", "features", "impact", "closing"]
KEY_TERMS = ["warden", "kiro", "bun", "mcp"]


def run(cmd: list[str]) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout + r.stderr


def norm(s: str) -> list[str]:
    return re.sub(r"[^a-z0-9' ]+", " ", s.lower()).split()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("video")
    ap.add_argument("--asr-model", default="small.en")
    ap.add_argument("--skip-asr", action="store_true")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    tl = json.loads((ROOT / "plan" / "timeline.json").read_text())
    findings: list[dict] = []

    def add(sev: str, check: str, detail: str, t: float | None = None) -> None:
        findings.append({"severity": sev, "check": check, "time": t, "detail": detail})

    # ---------- container
    probe = json.loads(run(["ffprobe", "-v", "error", "-show_entries", "stream=codec_type,width,height,r_frame_rate:format=duration", "-of", "json", a.video]))
    dur = float(probe["format"]["duration"])
    v = next(s for s in probe["streams"] if s["codec_type"] == "video")
    if (v["width"], v["height"]) != (1920, 1080):
        add("high", "resolution", f"{v['width']}x{v['height']}, expected 1920x1080")
    if not 120 <= dur <= 240:
        add("high", "duration", f"{dur:.1f}s is outside the 2-4 minute brief")
    if not any(s["codec_type"] == "audio" for s in probe["streams"]):
        add("high", "audio", "no audio stream")

    # ---------- plan coverage
    ids = [s["id"] for s in tl["sections"]]
    for r in REQUIRED:
        if r not in ids:
            add("high", "sections", f"missing required section '{r}'")
    if ids[: len(REQUIRED)] != REQUIRED:
        add("medium", "sections", f"section order {ids} differs from the brief")

    # ---------- video defects
    log = run(["ffmpeg", "-hide_banner", "-i", a.video, "-vf", "blackdetect=d=0.4:pix_th=0.06,freezedetect=n=0.0015:d=4", "-an", "-f", "null", "-"])
    for m in re.finditer(r"black_start:([\d.]+) black_end:([\d.]+)", log):
        s, e = float(m.group(1)), float(m.group(2))
        add("medium" if e - s > 0.8 else "low", "black", f"black frames {s:.2f}-{e:.2f}s", s)
    for m in re.finditer(r"freeze_start: ([\d.]+)[\s\S]*?freeze_duration: ([\d.]+)", log):
        s, d = float(m.group(1)), float(m.group(2))
        add("medium" if d > 6 else "low", "freeze", f"frozen picture {s:.2f}s for {d:.1f}s (fine for a held title, bad mid-demo)", s)

    # ---------- audio
    log = run(["ffmpeg", "-hide_banner", "-i", a.video, "-vn", "-af", "ebur128=peak=true,silencedetect=n=-45dB:d=2.5", "-f", "null", "-"])
    I = re.findall(r"I:\s+(-?[\d.]+) LUFS", log)
    TP = re.findall(r"Peak:\s+(-?[\d.]+) dBFS", log)
    lufs = float(I[-1]) if I else None
    peak = float(TP[-1]) if TP else None
    if lufs is not None and not -16 <= lufs <= -12:
        add("medium", "loudness", f"integrated {lufs:.1f} LUFS, target -14")
    if peak is not None and peak > -0.5:
        add("medium", "peak", f"true peak {peak:.1f} dBFS, risk of clipping")
    for m in re.finditer(r"silence_start: ([\d.]+)[\s\S]*?silence_duration: ([\d.]+)", log):
        s, d = float(m.group(1)), float(m.group(2))
        if s > 1 and s + d < dur - 1:
            add("medium", "silence", f"{d:.1f}s of silence at {s:.1f}s", s)

    # ---------- screenshots per section
    for s in tl["sections"]:
        n = 8
        step = s["duration"] / (n + 1)
        fps = 1 / step
        run(["ffmpeg", "-y", "-loglevel", "error", "-ss", f"{s['start'] + step / 2:.2f}", "-t", f"{s['duration'] - step / 2:.2f}", "-i", a.video,
             "-vf", f"fps={fps:.4f},scale=480:-1,tile=4x2", "-frames:v", "1", str(OUT / f"sheet_{s['id']}.png")])

    # ---------- speech vs script
    line_rows = []
    if not a.skip_asr:
        sys.path.insert(0, str(ROOT / "tools"))
        from captions import transcribe  # noqa: E402
        words = transcribe(a.video, str(OUT / "words.json"), a.asr_model, "Warden, Kiro, Bun, MCP, prompt injection.")
        for s in tl["sections"]:
            for l in s["lines"]:
                ws = [w for w in words if l["start"] - 0.4 <= w["s"] <= l["start"] + l["duration"] + 0.4]
                heard = " ".join(w["w"] for w in ws)
                sim = difflib.SequenceMatcher(None, norm(l["text"]), norm(heard)).ratio()
                drift = (ws[0]["s"] - l["start"]) if ws else None
                line_rows.append({"id": l["id"], "similarity": round(sim, 3), "drift": None if drift is None else round(drift, 2), "heard": heard})
                if sim < 0.85:
                    add("high" if sim < 0.6 else "medium", "speech", f"{l['id']}: ASR matches script at {sim:.0%}. Heard: \"{heard[:140]}\"", l["start"])
                if drift is not None and abs(drift) > 0.6:
                    add("low", "sync", f"{l['id']}: speech starts {drift:+.2f}s from plan", l["start"])
        for w in words:
            if norm(w["w"]) and norm(w["w"])[0] in KEY_TERMS and w["p"] < 0.5:
                add("low", "pronunciation", f"'{w['w']}' recognised with low confidence ({w['p']:.2f}); check the voice says it clearly", w["s"])

    sev_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (sev_rank[f["severity"]], f["time"] or 0))
    verdict = "FAIL" if any(f["severity"] == "high" for f in findings) else ("REVIEW" if any(f["severity"] == "medium" for f in findings) else "PASS")
    (OUT / "report.json").write_text(json.dumps({"verdict": verdict, "duration": dur, "lufs": lufs, "true_peak": peak,
                                                 "lines": line_rows, "findings": findings}, indent=2))
    md = [f"# Critic report: {Path(a.video).name}", "", f"**Verdict:** {verdict}", "",
          f"| Duration | Loudness | True peak | Lines checked | Mean line match |", "|---|---|---|---|---|",
          f"| {dur:.1f}s | {lufs} LUFS | {peak} dBFS | {len(line_rows)} | "
          f"{(sum(r['similarity'] for r in line_rows) / len(line_rows)) if line_rows else 0:.1%} |", "", "## Findings", ""]
    md += [f"- **{f['severity']}** · {f['check']}" + (f" · {f['time']:.1f}s" if f["time"] is not None else "") + f" · {f['detail']}" for f in findings] or ["- none"]
    md += ["", "## Contact sheets", ""] + [f"- sheet_{s['id']}.png" for s in tl["sections"]]
    (OUT / "report.md").write_text("\n".join(md) + "\n")
    print("\n".join(md[:8]))
    print(f"{len(findings)} findings -> {OUT / 'report.md'}")


if __name__ == "__main__":
    main()
