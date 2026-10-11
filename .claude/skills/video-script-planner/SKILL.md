---
name: video-script-planner
description: Writes and plans narration scripts for product and explainer videos in a measured university-lecturer voice, with per-line emotion tags, section structure, timing budget and a shot list. Use when drafting or revising a video script, planning sections for a demo video, or checking a script for AI-sounding writing.
---

# Script planning

Output is `video/plan/script.json` (schema below). The voice, timeline and every visual are derived from it, so get it right first.

## Voice: narrate like a university professor

Picture a well-prepared guest lecture: warm, unhurried, curious, precise. The speaker explains *why* before showing *what*, and trusts the audience.

- Write full sentences that breathe, usually 15–30 words, with natural subordinate clauses.
- Explain, then show. Let the picture carry the proof; the narration carries the reasoning.
- Spoken English: "base sixty-four", "about five minutes", contractions only where a lecturer would use them.

## Avoid Claudisms (hard rules)

- No short punchy fragments. No one-word sentences. No "Here's the thing." No "Let that sink in."
- No staccato triads ("Fast. Local. Private.") and no "It's not X, it's Y" constructions.
- **Few numbers.** At most one figure per section, spoken in words, and only when it changes the viewer's mind. Put precise figures on screen, not in the voice.
- No hype vocabulary: revolutionary, game-changing, seamless, supercharge, unleash, cutting-edge, robust, leverage, delve.
- No em-dash rhythm, no rhetorical questions stacked in pairs, no "imagine a world".
- Don't address the viewer as "you guys" or "folks"; "you" is fine.

Run this check before finalising:

```bash
grep -nEi "game.chang|seamless|supercharg|unleash|cutting.edge|delve|leverage|here's the thing|let that sink|imagine a world|—" video/plan/script.json
```

## Structure for a 2–4 minute product film

| Section | Job | Typical length |
|---|---|---|
| Introduction | name the subject, promise what the viewer will learn | 15–20 s |
| Problem Overview | the mechanism of the problem, concretely | 25–35 s |
| Live Product Demonstration | install, connect, one attack blocked, one benign allowed, a real agent protected, dashboard | 60–80 s |
| AI Capabilities | how it decides, layer by layer | 30–40 s |
| Key Features | two or three capabilities beyond the core | 15–25 s |
| Business Impact | cost, privacy, evidence | 15–25 s |
| Closing Summary | restate the idea in one sentence, invitation to try | 15–20 s |

Budget about 150 words per minute. 3:30 ≈ 520 words of narration.

## Truthfulness

Every claim must be checkable in the repo or in a capture from this session (README benchmark table, `src/detect/orchestrator.ts`, real `/scan` responses saved under `build/capture/`). If a demo run does not show a behaviour, cut the line.

## Emotion tags (for Gemini TTS)

Each line gets one leading tag that describes delivery, not content: `[warmly]`, `[thoughtful]`, `[curious]`, `[serious]`, `[measured]`, `[brightly]`, `[intrigued]`, `[reassuring]`, `[leaning in]`, `[explaining]`, `[pleased]`, `[confident]`, `[reflective]`. Use `""` for neutral. Vary them gently; a lecturer does not swing between extremes.

## Schema

```json
{
  "title": "…",
  "voice": { "persona": "style prompt sent to TTS", "gemini_voice": "Charon", "pace_wpm": 150 },
  "style_rules": ["…"],
  "sections": [
    { "id": "intro", "name": "Introduction",
      "lines": [ { "tag": "[warmly]", "text": "Good afternoon. …" } ] }
  ]
}
```

One line ≈ one shot. Keep lines under ~15 seconds so pictures can change with them.

## Shot list

After the script, write `video/plan/shots.md`: for each line, the visual (real capture, Manim, HyperFrames, Motion Canvas, AI keyframe or CC clip), what must be legible on screen, and the source of truth for any number shown.
