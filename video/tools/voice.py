#!/usr/bin/env python3
"""Render narration line by line from plan/script.json.

Each line becomes build/vo/<section>_<nn>.wav (48 kHz mono, loudness-normalised), and
build/vo/manifest.json records exact durations so the edit can be cut to the voice.

  python tools/voice.py                       # Gemini 3.8 Flash TTS with emotion tags (needs credits)
  python tools/voice.py --engine free         # fish-audio free tier (tags stripped)
  python tools/voice.py --only demo           # re-render one section
  python tools/voice.py --engine auto         # try Gemini, fall back to free on 402

Emotion: Gemini TTS reads inline audio tags such as [warmly], [serious], [whispers], [pause].
The persona string from script.json is sent as a style prompt so every line shares one delivery.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
import media  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
VO = ROOT / "build" / "vo"

ENGINES = {
    "gemini": {"model": "google/gemini-3.8-flash-tts", "tags": True},
    "free": {"model": "fish-audio/s2.1-pro-free:free", "tags": False},
}


def speak(engine: str, text: str, persona: str, voice: str, out_raw: Path) -> None:
    cfg = ENGINES[engine]
    body = {"model": cfg["model"], "input": text, "response_format": "mp3"}
    if engine == "gemini":
        body["voice"] = voice
        body["instructions"] = persona
    r = requests.post(f"{media.API}/audio/speech", headers=media.hdr(), json=body, timeout=300)
    if r.status_code == 402:
        raise PermissionError(r.text[:200])
    if r.status_code != 200 or r.headers.get("content-type", "").startswith("application/json"):
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
    out_raw.write_bytes(r.content)


def normalise(src: Path, dst: Path) -> float:
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(src),
                    "-af", "silenceremove=start_periods=1:start_threshold=-50dB,areverse,silenceremove=start_periods=1:start_threshold=-50dB,areverse,loudnorm=I=-16:TP=-1.5:LRA=7",
                    "-ar", "48000", "-ac", "1", str(dst)], check=True)
    d = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(dst)],
                       capture_output=True, text=True, check=True).stdout.strip()
    return float(d)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="auto", choices=["auto", "gemini", "free"])
    ap.add_argument("--only")
    ap.add_argument("--script", default=str(ROOT / "plan" / "script.json"))
    a = ap.parse_args()

    script = json.loads(Path(a.script).read_text())
    persona = script["voice"]["persona"]
    voice = script["voice"].get("gemini_voice", "Charon")
    VO.mkdir(parents=True, exist_ok=True)
    man_path = VO / "manifest.json"
    manifest = json.loads(man_path.read_text()) if man_path.exists() else {}
    engine = "gemini" if a.engine in ("auto", "gemini") else "free"

    for sec in script["sections"]:
        if a.only and sec["id"] != a.only:
            continue
        for n, line in enumerate(sec["lines"], 1):
            name = f"{sec['id']}_{n:02d}"
            text = f"{line['tag']} {line['text']}".strip() if ENGINES[engine]["tags"] else line["text"]
            raw = VO / f"{name}.raw"
            try:
                speak(engine, text, persona, voice, raw)
            except PermissionError:
                if a.engine != "auto":
                    sys.exit("402 from OpenRouter: add credits or use --engine free")
                print("Gemini TTS needs credits; falling back to the free voice", file=sys.stderr)
                engine = "free"
                speak(engine, line["text"], persona, voice, raw)
            dur = normalise(raw, VO / f"{name}.wav")
            raw.unlink()
            manifest[name] = {"section": sec["id"], "text": line["text"], "tag": line["tag"], "engine": engine,
                              "model": ENGINES[engine]["model"], "duration": round(dur, 3)}
            media.ledger(kind="tts", model=ENGINES[engine]["model"], text=text, out=f"build/vo/{name}.wav")
            print(f"{name}\t{dur:6.2f}s\t{engine}")
    man_path.write_text(json.dumps(manifest, indent=2))
    total = sum(v["duration"] for v in manifest.values())
    print(f"total narration {total:.1f}s across {len(manifest)} lines")


if __name__ == "__main__":
    main()
