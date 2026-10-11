---
name: video-critic
description: Reviews a rendered video for audio and visual quality by sampling screenshots per section, transcribing the mix and comparing it line by line to the script, and running black-frame, freeze, silence, loudness and peak checks, producing a PASS/REVIEW/FAIL report. Use after every render, before publishing, or when asked whether a video is good enough.
---

# Video critic

```bash
cd video
.venv/bin/python tools/critic.py build/final/warden_demo.mp4             # full pass, including ASR
.venv/bin/python tools/critic.py build/final/warden_demo.mp4 --skip-asr  # fast visual and audio checks only
```

Output in `build/critic/`: `report.md`, `report.json`, `sheet_<section>.png` (8 frames per section) and `words.json`.

## What it checks

| Area | Check | Threshold |
|---|---|---|
| Brief | duration, resolution, required sections in order | 120–240 s, 1920×1080, intro…closing |
| Picture | `blackdetect`, `freezedetect` | black > 0.8 s is medium; freeze > 6 s is medium |
| Sound | EBU R128 loudness, true peak, `silencedetect` | −16…−12 LUFS, peak ≤ −0.5 dBTP, no silence > 2.5 s mid-film |
| Speech | ASR text vs script per line (difflib ratio), start drift vs plan, low-confidence product names | < 85% medium, < 60% high, drift > 0.6 s |

Verdict: **FAIL** on any high finding, **REVIEW** on any medium, otherwise **PASS**.

## How to use the result

1. Fix every high and medium finding, re-render, and re-run until PASS.
2. **Then look at every contact sheet yourself**, because the automated checks can't judge taste. Look for overlapping UI, unreadable text, captions covering the key moment, empty or unbalanced frames, logos or "subscribe" plates in stock clips, private paths or usernames, and anything on screen that the product did not really do.
3. Spot-check the transitions between sections (`tools/frames_at.sh <video> out.png 4 t1 t2 …`).
4. Report the verdict and the remaining low findings honestly when handing over.
