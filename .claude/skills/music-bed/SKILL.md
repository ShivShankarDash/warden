---
name: music-bed
description: Creates the background music bed for a narrated video, using ElevenLabs Music first, OpenRouter Lyria second and an offline synthesised ambient bed as a last resort, mixed under the narration with sidechain ducking. Use when a video needs background music, a new mood, or a re-timed music bed.
---

# Music bed

```bash
cd video
# 1. ElevenLabs Music (preferred). Needs ELEVENLABS_API_KEY in env or video/.env
.venv/bin/python tools/media.py music --provider elevenlabs --seconds 221 --out build/music/bed.mp3 \
  --prompt "Calm, intelligent ambient electronica for a technical lecture: warm analog pads, soft plucked arpeggio, light sub, 72 bpm, D major, no drums for the first 20 seconds, gentle lift in the final 20 seconds, no vocals"
# 2. Lyria via OpenRouter (needs >= $0.50 balance)
.venv/bin/python tools/media.py music --provider lyria --seconds 180 --out build/music/bed.mp3 --prompt "…"
# 3. Offline fallback (original, royalty-free, deterministic)
.venv/bin/python tools/music_local.py --seconds 221 --out build/music/bed.wav
```

`assemble.py` uses `build/music/bed.wav`; convert an mp3 with `ffmpeg -i bed.mp3 -ar 48000 bed.wav`.

## Mixing rules (applied in `assemble.py`)

- The bed enters at −9 dB and is **ducked under the voice** with `sidechaincompress` (threshold 0.02, ratio 8, attack 40 ms, release 600 ms), so it swells between lines and steps back under speech.
- The final mix is normalised to **−14 LUFS integrated, −1 dBTP** (YouTube's reference). The critic checks both.
- Section-aware intensity: quieter under the live demo, fuller at the intro and end card (`music_local.py` follows `timeline.json`; for generated music, ask for the shape in the prompt).
- Instrumental only. Avoid melodies in the 1–4 kHz speech band; pads and low plucks sit under a voice best.
- Length = film length + 1 s; fade in 2.5 s, fade out 4 s.
