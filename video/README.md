# Warden product video pipeline

This folder builds the Warden walkthrough video (2–4 minutes): real CLI, Kiro and dashboard footage, three motion-graphics engines, AI media through one OpenRouter key, OpenTimelineIO assembly, word-level captions and an automated critic. The Claude Code skills in `../.claude/skills/` drive it; start with `video-director`.

| Skill | What it does | Main tool |
|---|---|---|
| video-director | order of work, rules, budget | (this README) |
| video-script-planner | professor-voice script, no Claudisms | `plan/script.json` |
| emotive-tts | Gemini 3.8 Flash TTS with emotion tags | `tools/voice.py` |
| openrouter-media | GPT Image 2.5 Sunburst keyframes, Seedance 2.5 / Veo 3.1 shots | `tools/media.py` |
| screen-capture | Terminal/tmux and Playwright takes | `scripts/term_reel.sh`, `scripts/record_*.mjs`, `tools/cut_demo.py` |
| motion-graphics | Manim, HyperFrames, Motion Canvas | `motion/`, `tools/render_*.{sh,mjs}` |
| cc-clips | yt-dlp search, Creative Commons only | `tools/cc_search.py` |
| music-bed | ElevenLabs Music → Lyria → offline bed | `tools/media.py music`, `tools/music_local.py` |
| otio-assembly | OTIO timeline and ffmpeg render, animatic | `tools/assemble.py`, `tools/animatic.py` |
| captions | faster-whisper word timings, script-aligned karaoke overlay | `tools/captions.py`, `tools/captions_overlay.py` |
| video-critic | screenshots, ASR vs script, loudness, black and freeze checks | `tools/critic.py` |
| publish-video | Google Drive (rclone) or YouTube (Data API) | `tools/publish.py` |

## Setup (once)

```bash
cd video
uv venv .venv -p 3.12 && uv pip install --python .venv/bin/python manim opentimelineio faster-whisper requests pillow numpy scipy
brew install cairo pango pkg-config rclone            # manim needs cairo/pango
mkdir hf && cd hf && npm init -y && npm i -D hyperframes@0.8.146 playwright@1.58.0 && cd ..   # Node 22 for HyperFrames
cd motion/mc && npm install && cd ../..
mkdir -p motion/hf/assets motion/mc/public && cp -R assets/fonts motion/hf/assets/ && cp -R assets/fonts motion/mc/public/
echo "OPENROUTER_API_KEY=sk-or-..." > .env            # gitignored
```

## Build

See the one-shot rebuild in `../.claude/skills/video-director/SKILL.md`. The final file lands in `build/final/warden_demo.mp4`, the animatic in `build/final/warden_animatic.mp4`, and the critic report in `build/critic/report.md`.
