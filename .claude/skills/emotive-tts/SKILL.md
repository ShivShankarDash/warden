---
name: emotive-tts
description: Generates expressive narration with Gemini 3.8 Flash TTS through OpenRouter's /audio/speech endpoint, steering emotion with inline audio tags and a persona prompt, one file per script line with measured durations. Use when creating or re-recording voiceover, changing the narrator's delivery, or fixing a mispronounced word.
---

# Emotive TTS (Gemini 3.8 Flash TTS via OpenRouter)

Tool: `video/tools/voice.py` (wraps `video/tools/media.py`). Key: `OPENROUTER_API_KEY` in env or `video/.env`.

```bash
cd video
.venv/bin/python tools/voice.py --engine gemini          # all lines, with emotion tags
.venv/bin/python tools/voice.py --engine gemini --only demo
.venv/bin/python tools/voice.py --engine auto            # Gemini, falls back to the free voice on HTTP 402
.venv/bin/python tools/timeline.py                       # always re-run after any voice change
```

## API facts (verified)

- Endpoint: `POST https://openrouter.ai/api/v1/audio/speech` (OpenAI-compatible). Body: `model`, `input`, `voice`, `response_format` (`mp3` or `pcm` only, not `wav`), optional `instructions`.
- Model ids: `google/gemini-3.8-flash-tts` (default), `google/gemini-3.8-flash-lite-tts` (cheaper), older `google/gemini-3.1-flash-tts-preview`.
- Response is raw audio bytes. An `application/json` response is an error; a 402 means no OpenRouter balance.
- Free fallback that works without credits: `fish-audio/s2.1-pro-free:free` (no emotion tags, no voice choice).
- List speech models: `curl -s "https://openrouter.ai/api/v1/models?output_modalities=speech"`.

## Putting emotion into the voice

1. **Persona prompt** (`script.json → voice.persona`, sent as `instructions`) fixes the overall character for every line: "A university professor giving a well-prepared guest lecture: warm, unhurried, curious, precise."
2. **Inline audio tags** at the start of a line set its delivery: `[warmly]`, `[serious]`, `[curious]`, `[reassuring]`, `[leaning in]`. Gemini TTS also understands mid-line tags such as `[pause]`, `[short pause]`, `[laughs softly]`, `[emphasis]word`. Use them sparingly; one per line is usually enough.
3. **Voice choice:** `Charon` (calm, low, informative) suits a lecturer. Alternatives worth an A/B: `Orus` (firm), `Iapetus` (clear), `Sulafat` (warm), `Gacrux` (mature).
4. **Pacing** comes from punctuation. Commas and full stops create the professor's breathing; avoid ellipses.

## Quality loop

- Each line is trimmed of leading/trailing silence and loudness-normalised (−16 LUFS, −1.5 dBTP) to `build/vo/<section>_<nn>.wav`.
- Run `video-critic` after assembly: it transcribes the mix and flags lines whose ASR text drifts from the script, and product names recognised with low confidence (e.g. "Warden", "Kiro", "Bun"). For a mispronounced name, respell it phonetically in the TTS input only (e.g. "Ward-en"), keep the script spelling for captions, and re-render that line with `--only`.
- Keep the same voice and persona for the whole film; re-render every line if either changes.
