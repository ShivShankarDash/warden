---
name: otio-assembly
description: Assembles the final cut as an OpenTimelineIO timeline (scenes, B-roll, captions, narration and music tracks) and renders it with ffmpeg, including the animatic variant. Use when assembling, re-cutting, re-timing or exporting the video, or when handing the edit to another NLE.
---

# Assembly with OpenTimelineIO

Tool: `video/tools/assemble.py` (uses `opentimelineio` in `video/.venv`).

```bash
cd video
.venv/bin/python tools/assemble.py build      # plan/timeline.json + build/scenes -> build/timeline.otio
.venv/bin/python tools/assemble.py render     # build/timeline.otio -> build/final/warden_demo.mp4
.venv/bin/python tools/assemble.py all
.venv/bin/python tools/assemble.py animatic   # storyboard stills on the same timeline -> build/final/warden_animatic.mp4
```

## Tracks

| Track | Content | Notes |
|---|---|---|
| V1 scenes | intro, problem, demo, ai (pipeline), features, impact, closing diagram + end card | hard cuts; each scene fades itself; Manim/MC sections get a slow 3.5% push-in |
| V2 b-roll | Creative Commons clips, AI shots from `build/shots/*.json` | fades, dark grade, metadata on each clip |
| V3 captions | `build/scenes/captions_overlay.webm` (VP9 alpha) | decoded with `-c:v libvpx-vp9` to keep alpha |
| A1 narration | one clip per script line at its `timeline.json` start | |
| A2 music | `build/music/bed.wav` | ducked under A1, final loudnorm −14 LUFS |

The `.otio` file is the edit decision list: open it in DaVinci Resolve or any OTIO-aware tool (`otioview build/timeline.otio`) to inspect or hand-finish the cut. Media references are absolute paths into `video/build`.

## Gotchas

- ffmpeg 8 removed `-filter_complex_script`; the tool uses `-/filter_complex <file>` (script saved to `build/final/filter_complex.txt`).
- Every V1 clip is normalised to 1920×1080/30 fps and padded with `tpad` to its exact section length, so a short render can't shift later sections.
- Re-run `tools/timeline.py` after any voice change, then re-render scenes; the assembler trusts `timeline.json`.
