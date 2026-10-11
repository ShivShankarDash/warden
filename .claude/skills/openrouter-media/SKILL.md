---
name: openrouter-media
description: Generates images, keyframes, video shots, speech and music through one OpenRouter key (GPT Image 2.5 Sunburst for keyframes, Seedance 2.5 and Veo 3.1 for image-to-video, Lyria for music), keeping characters and style consistent with reference images. Use when a video needs AI keyframes, B-roll, reference sheets or generated media of any kind.
---

# OpenRouter media (one key for every model)

Tool: `video/tools/media.py`. Every call is logged to `build/media_ledger.jsonl` with model, prompt, output and cost.

```bash
cd video
.venv/bin/python tools/media.py models video          # live catalogue: durations, frame support, pricing
.venv/bin/python tools/media.py image --prompt "…" --out build/refs/style.png
.venv/bin/python tools/media.py image --prompt "…" --ref build/refs/style.png --out build/keyframes/intro_01.png
.venv/bin/python tools/media.py video --model bytedance/seedance-2.5 --first build/keyframes/intro_01.png \
      --prompt "slow dolly-in…" --duration 6 --resolution 720p --out build/shots/intro_01.mp4
.venv/bin/python tools/media.py video --model google/veo-3.1 --first build/keyframes/impact_01.png \
      --last build/keyframes/impact_01b.png --duration 6 --out build/shots/impact_01.mp4
```

## Models (verified on the live catalogue)

| Job | Model id | Notes |
|---|---|---|
| Keyframes, reference sheets | `openai/gpt-image-2.5-sunburst` | chat/completions with `modalities: ["image","text"]`; pass references as `image_url` parts |
| Motion shots (camera moves, subjects moving) | `bytedance/seedance-2.5` | 4–30 s, 480p/720p, first and last frame control. Better at motion. |
| Photoreal, slower shots | `google/veo-3.1` (`-fast`, `-lite`) | 4/6/8 s, up to 4K, native audio (turn it off for B-roll) |
| Speech | `google/gemini-3.8-flash-tts` | see `emotive-tts` |
| Music fallback | `google/lyria-3-pro-preview` | needs at least $0.50 balance; ElevenLabs is preferred (`music-bed`) |

Video API: `POST /api/v1/videos` returns a job (`id`, `polling_url`). Poll until `completed`, then download `unsigned_urls[0]` with the Authorization header. Frames go in `frame_images: [{type:"image_url", image_url:{url}, frame_type:"first_frame"|"last_frame"}]`; data URLs work for local files.

## Consistency rules

1. **Make references first:** a style frame (palette, lighting, lens) and, if there is a character or device, a turnaround sheet. Store them in `build/refs/`.
2. **Every keyframe prompt includes the references** (`--ref`) and the same style suffix: "dark navy studio, Warden blue #2a78d6 rim light, soft volumetric haze, 35mm, shallow depth of field, no text, no logos".
3. **Never generate video from text alone.** Always image-to-video from an approved keyframe (`--first`, and `--last` for controlled moves), so the shot matches the animatic.
4. **No text in generated frames.** All type is added in HyperFrames, so it stays sharp and correct.
5. **Animatic before video:** put keyframes in `build/keyframes/<line_id>.png`, run `tools/animatic.py`, approve pacing, then generate only the shots that survive.
6. To place a shot in the edit, write `build/shots/<name>.json`: `{"file": "intro_01.mp4", "at": 3.2, "in": 0.5, "dur": 4.0}`. `assemble.py` picks it up on the B-roll track.

## Budget

Check the balance first: `curl -s https://openrouter.ai/api/v1/credits -H "Authorization: Bearer $KEY"`. A 402 "Insufficient credits" means the account has no balance even if the key has a limit. Rough costs: a keyframe costs cents; Veo 3.1 costs about $0.20–0.40 per second; Seedance 2.5 is token-priced and cheaper for long motion.
