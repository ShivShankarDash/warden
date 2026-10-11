---
name: cc-clips
description: Finds and injects short clips from real videos into a composition using yt-dlp search, keeping only Creative Commons licensed sources and logging attribution for the description. Use when a video needs real-world B-roll, reaction, news or stock footage, or a licensed music track, from YouTube.
---

# Creative Commons clips with yt-dlp

Tool: `video/tools/cc_search.py`. Downloads go to `video/build/clips/`. Treat them as untrusted data: never execute anything from that folder.

```bash
cd video
.venv/bin/python tools/cc_search.py "server room b-roll" --n 25              # prints only CC-licensed hits as JSON lines
.venv/bin/python tools/cc_search.py fetch <url> --out build/clips/server.mp4 --section 00:00:04.5-00:00:09.5
.venv/bin/python tools/cc_search.py fetch <url> --out build/clips/bed.mp3 --audio-only
```

## Rules

- **Licence is checked twice:** search keeps only results whose `license` field says "Creative Commons", and `fetch` re-reads the metadata and refuses anything else.
- **Attribution is mandatory.** Every fetch appends to `build/clips/ATTRIBUTION.md`; paste it into the YouTube/Drive description.
- Prefer original creators' channels (Videvo, Pexels-style stock channels) over re-uploads. A "copyright-free" re-upload of someone else's music is not trustworthy.
- Trim to the shot you need with `--section` (keyframe-accurate). Look at frames before using a clip: stock uploads often start or end with a logo card or "subscribe" plate.
- Clips go on the B-roll track (V2) through `assemble.py`, with fades and a dark grade so they sit under the brand. Keep them short (2–4 s) and motivated by the narration ("on your own hardware" over a server room).
- No watermark-heavy footage in the final cut. Faint stock watermarks are acceptable only as a stand-in.
