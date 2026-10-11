---
name: video-director
description: Orchestrates the whole Warden product-video pipeline in Claude Code (script, voice, screen capture, motion graphics, AI keyframes and shots, animatic, OpenTimelineIO assembly, captions, critic, publishing). Use when asked to make, update or re-cut a demo, explainer or launch video, or to run any stage of it end to end.
---

# Video director

You are directing a short, well-designed product film. Work in `video/` (Python venv at `video/.venv`, Node 22 at `~/.nvm/versions/node/v22.23.3/bin`). Every stage has its own skill; this one fixes the order, the budget and the rules that hold across stages.

## Order of work (do not skip the animatic)

1. **Plan the script** with `video-script-planner` → `video/plan/script.json`.
2. **Voice** with `emotive-tts` → `build/vo/*.wav` + `manifest.json`. Then `python tools/timeline.py` → `plan/timeline.json`. From here on, *pictures are cut to the voice*: every scene reads its duration and cue times from `timeline.json`.
3. **Capture real product footage** with `screen-capture` (terminal take, Playwright dashboard takes) and conform it with `python tools/cut_demo.py`.
4. **Keyframes and reference images** with `openrouter-media` (GPT Image 2.5 Sunburst), saved as `build/keyframes/<line_id>.png`.
5. **Animatic**: `python tools/animatic.py && python tools/assemble.py animatic` → `build/final/warden_animatic.mp4`. Watch it (or run `video-critic` on it) and fix pacing *before* paying for video generation or long renders.
6. **Motion graphics** with `motion-graphics` (Manim for diagrams, HyperFrames for HTML-grounded scenes and overlays, Motion Canvas for data scenes) → `build/scenes/*.mp4`.
7. **AI shots** with `openrouter-media` (Seedance 2.5 for motion, Veo 3.1 for photoreal holds), image-to-video from the approved keyframes only.
8. **Real-world clips** with `cc-clips` (Creative Commons only, attribution logged).
9. **Music** with `music-bed` (ElevenLabs first).
10. **Assemble** with `otio-assembly` → `build/timeline.otio` → `build/final/warden_demo.mp4`.
11. **Captions** with `captions` (word-level, aligned to the script) → overlay track V3, re-assemble.
12. **Critic** with `video-critic`. Fix every high/medium finding, re-run until PASS, and look at every contact sheet yourself.
13. **Publish** with `publish-video`, then verify the link opens logged-out.

## House rules

- **Truth over polish.** Every terminal line, verdict, number and UI frame on screen must come from the real product, captured in this session. Never mock a CLI result or a dashboard value. If a run doesn't show what the script says, change the script, not the footage.
- **Narration voice:** a university professor giving a guest lecture. See `video-script-planner` for the banned "Claudisms".
- **Design system:** tokens live in `video/motion/hf/brand.css` and `video/motion/manim/brand.py` (navy `#0a0e14`, Warden blue `#2a78d6`, Inter / Inter Display / JetBrains Mono from `video/assets/fonts`). Every renderer uses the same tokens.
- **Budget:** OpenRouter spend is logged in `build/media_ledger.jsonl`. Check `curl -s https://openrouter.ai/api/v1/credits` before generating; a 402 means the account has no balance. Image keyframes cost cents, video seconds cost tens of cents. Generate video only for shots that survived the animatic.
- **Screen etiquette:** screen recording takes over the user's display. Use `scripts/record_when_idle.sh` so the take starts only after the user has been idle, and verify the take afterwards (the script prints CLEAN or INTERRUPTED).
- **Brief for this film:** 2–4 minutes, sections in order: Introduction, Problem Overview, Live Product Demonstration, AI Capabilities, Key Features, Business Impact, Closing Summary.

## One-shot rebuild (after edits)

```bash
cd video
.venv/bin/python tools/voice.py --engine auto      # only if the script changed
.venv/bin/python tools/timeline.py
.venv/bin/python tools/cut_demo.py
bash tools/render_manim.sh final
bash tools/render_hf.sh final intro demo features endcard
node tools/render_mc.mjs build/scenes/impact.mp4
.venv/bin/python tools/assemble.py all
.venv/bin/python tools/captions.py transcribe build/final/warden_demo.mp4 --out build/captions/words.json
.venv/bin/python tools/captions.py align build/captions/words.json
.venv/bin/python tools/captions_overlay.py build/captions/words.json && bash tools/render_hf.sh final captions_overlay
.venv/bin/python tools/assemble.py all
.venv/bin/python tools/critic.py build/final/warden_demo.mp4
```
