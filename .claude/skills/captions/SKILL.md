---
name: captions
description: Produces word-level timed subtitles for the final video with a local ASR model (faster-whisper), corrects spellings against the script, and renders them as karaoke-style burned captions (HyperFrames alpha overlay) plus SRT and ASS files. Use when adding, fixing or restyling captions or subtitles.
---

# Captions

Tools: `video/tools/captions.py` (ASR, alignment, SRT/ASS) and `video/tools/captions_overlay.py` (burned-in overlay).

```bash
cd video
.venv/bin/python tools/captions.py transcribe build/final/warden_demo.mp4 --out build/captions/words.json   # faster-whisper small.en, word timestamps
.venv/bin/python tools/captions.py align build/captions/words.json                                        # spellings from plan/script.json, timing from ASR
.venv/bin/python tools/captions.py srt build/captions/words.json --out build/captions/final.srt            # upload as a YouTube caption track too
.venv/bin/python tools/captions_overlay.py build/captions/words.json                                     # -> motion/hf/captions_overlay.html
bash tools/render_hf.sh final captions_overlay                                                            # -> build/scenes/captions_overlay.webm (alpha)
.venv/bin/python tools/assemble.py all                                                                   # V3 track composites it
```

## Details

- ASR: `faster-whisper` (`small.en`, int8 on CPU; use `medium.en` for noisier mixes). Audio is decoded with ffmpeg to 16 kHz float, avoiding PyAV version drift. `condition_on_previous_text=False` plus VAD stops long-form drift (without it the last segment was dropped).
- `initial_prompt` carries a glossary (Warden, Kiro, Bun, MCP) to bias recognition; `align` then replaces recognised words with the script's own spelling while keeping ASR timing.
- Style: one lower-centre pill (Inter 600 38 px, 78% navy), at most 7 words per group, breaking on punctuation and pauses over 0.6 s. The spoken word turns white while upcoming words stay dimmed. Groups never overlap: each ends before the next starts.
- Keep on-screen UI (step cards, callouts) above the caption band, around 120 px from the bottom.
- If the local ffmpeg has libass (`ffmpeg -filters | grep subtitles`), `captions.py ass` + `captions.py burn` is a quicker alternative. Homebrew's default ffmpeg build lacks it.
