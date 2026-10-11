---
name: motion-graphics
description: Builds motion graphics for HTML-grounded product video with three engines, Manim for technical diagrams, HyperFrames for HTML/GSAP scenes, real-footage compositing and transparent overlays, and Motion Canvas for data and chart scenes, all timed to the narration and sharing one design system. Use when a section needs a diagram, title card, animated chart, lower third, callout, caption overlay or a composited screen recording.
---

# Motion graphics

All scenes read their length and cue times from `video/plan/timeline.json`, so animation beats land on the narration. All engines share the tokens in `video/motion/hf/brand.css` and `video/motion/manim/brand.py`.

## Which engine

| Need | Engine | Why |
|---|---|---|
| Mechanism diagrams, flows, pipelines, before/after | **Manim** (`video/motion/manim/*.py`) | precise vector motion, `Timed.at(t)` cue clock |
| Titles, UI-like cards, composited screen recordings with camera moves, lower thirds, callouts, captions | **HyperFrames** (`video/motion/hf/*.html`) | real HTML/CSS (same fonts as the product), GSAP, deterministic render, alpha output |
| Data scenes: counters, bars, donuts | **Motion Canvas** (`video/motion/mc/src/scenes/*.tsx`) | signal-driven tweens, crisp at any value |

## Manim

```bash
bash tools/render_manim.sh draft problem pipeline closing   # 480p15 previews in build/manim
bash tools/render_manim.sh final                            # 1080p30 -> build/scenes/<file>.mp4
```
- Subclass `Timed` from `brand.py`; call `self.at(cue)` to wait until an absolute time; read cues with `timeline_section("<id>")`.
- Fonts are registered from `video/assets/fonts` at import (Inter, Inter Display, JetBrains Mono).
- Gotchas: chained `.animate` calls snapshot state at build time, so use `UpdateFromAlphaFunc` for multi-leg paths. `.animate` re-adds a mobject on top, so set `z_index` on text over cards. Keep six cards within 14 units of frame width.

## HyperFrames

```bash
bash tools/render_hf.sh draft intro           # draft mp4 + contact sheet in build/test
bash tools/render_hf.sh final intro demo features endcard
bash tools/render_hf.sh final captions_overlay  # names containing "overlay" render as alpha WebM with 1 worker
```
- One HTML file per composition: root `data-composition-id`, `data-duration`; a paused GSAP timeline registered on `window.__timelines[id]`; timed media need `class="clip" data-start data-duration`.
- Deterministic only: no `Date.now()`, `Math.random()` or network calls.
- Videos must have dense keyframes (`-g 30`), or seeks freeze. `cut_demo.py` already encodes that way.
- For screen recordings, keep the source at native Retina size (2880×1620) and zoom with a transform on a wrapper (`cam()` in `demo.html`) so text stays sharp at 1.5×.
- Multi-worker alpha renders spool PNG frames to disk (~55 GB for 3.5 min). Use `-w 1` (streamed) for long overlays.
- Run `npx hyperframes lint` / `check` in `motion/hf` after edits; `npx hyperframes docs gsap` for the API.

## Motion Canvas

```bash
node tools/render_mc.mjs build/scenes/impact.mp4    # starts vite, opens the editor with ?render, waits for the ffmpeg exporter
```
- Project in `video/motion/mc` (vite + `@motion-canvas/*` 3.17.2). Render settings are in `src/project.meta` (1920×1080, 30 fps, ffmpeg exporter).
- Fonts load from `public/fonts` via `src/global.css`.
- Use `useTime()` to hold until absolute section times; `createSignal` for counters.
- The vite plugins ship as CJS; `vite.config.ts` unwraps `.default`.

## Taste checklist

- One idea per frame; one accent colour (blue), red only for attacks, green only for allowed or safe.
- Type: Inter Display for headlines, Inter for UI, JetBrains Mono for anything a computer printed.
- Nothing on screen that the product did not do. Numbers on screen are real and sourced (README, capture JSON, dashboard).
- Keep lower-thirds and callouts above y≈930 so the caption band (bottom ~120 px) stays clear.
- Every hold over ~4 s needs some motion (parallax, push-in). `assemble.py` adds a slow 3.5% push-in to Manim and Motion Canvas sections.
