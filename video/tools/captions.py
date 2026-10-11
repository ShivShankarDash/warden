#!/usr/bin/env python3
"""Word-level captions with faster-whisper.

  python tools/captions.py transcribe <media> [--out build/captions/words.json] [--model small.en] [--prompt "Warden, Kiro, MCP"]
  python tools/captions.py ass <words.json> --out build/captions/final.ass [--max-words 7]
  python tools/captions.py srt <words.json> --out build/captions/final.srt
  python tools/captions.py burn <video> <subs.ass> --out final_captioned.mp4

The ASS style highlights each word as it is spoken (karaoke \\kf timing) in a lower-third
pill that stays out of the way of terminal and dashboard content.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

GLOSSARY = "Warden, Kiro, Bun, bunx, MCP, prompt injection, base sixty-four, dashboard, Claude Code, Cursor."


def transcribe(media: str, out: str, model: str, prompt: str) -> list[dict]:
    from faster_whisper import WhisperModel
    import numpy as np
    # Decode with ffmpeg (avoids PyAV version drift): 16 kHz mono float32.
    pcm = subprocess.run(["ffmpeg", "-loglevel", "error", "-i", media, "-f", "f32le", "-ac", "1", "-ar", "16000", "-"],
                         capture_output=True, check=True).stdout
    audio = np.frombuffer(pcm, dtype=np.float32)
    m = WhisperModel(model, device="cpu", compute_type="int8")
    segs, info = m.transcribe(audio,word_timestamps=True, vad_filter=True, initial_prompt=prompt, beam_size=5,
                              condition_on_previous_text=False, vad_parameters={"min_silence_duration_ms": 400})
    words = []
    for s in segs:
        for w in s.words or []:
            words.append({"w": w.word.strip(), "s": round(w.start, 3), "e": round(w.end, 3), "p": round(w.probability, 3)})
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps({"language": info.language, "words": words}, indent=1))
    print(f"{len(words)} words -> {out}")
    return words


def align_to_script(words_json: str, script_json: str) -> None:
    """Keep ASR timing, take spelling from the script (product names, punctuation).

    Aligns normalised ASR tokens to normalised script tokens with difflib; on equal or
    same-length replace blocks the caption text becomes the script's own word.
    """
    import difflib
    import re

    data = json.loads(Path(words_json).read_text())
    words = data["words"]
    script = json.loads(Path(script_json).read_text())
    toks = [w for sec in script["sections"] for line in sec["lines"] for w in line["text"].split()]
    n = lambda s: re.sub(r"[^a-z0-9]+", "", s.lower())  # noqa: E731
    a = [n(w["w"]) for w in words]
    b = [n(t) for t in toks]
    fixed = 0
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op in ("equal", "replace") and (i2 - i1) == (j2 - j1):
            for k in range(i2 - i1):
                if words[i1 + k]["w"] != toks[j1 + k]:
                    fixed += 1
                words[i1 + k]["w"] = toks[j1 + k]
    data["aligned_to_script"] = True
    Path(words_json).write_text(json.dumps(data, indent=1))
    print(f"aligned {len(words)} words to script, {fixed} spellings corrected")


def chunks(words: list[dict], max_words: int, max_gap: float = 0.6) -> list[list[dict]]:
    out, cur = [], []
    for w in words:
        brk = cur and (len(cur) >= max_words or w["s"] - cur[-1]["e"] > max_gap or cur[-1]["w"][-1:] in ".?!:;")
        if brk:
            out.append(cur)
            cur = []
        cur.append(w)
    if cur:
        out.append(cur)
    return out


def ts_ass(t: float) -> str:
    h, r = divmod(t, 3600)
    m, s = divmod(r, 60)
    return f"{int(h)}:{int(m):02d}:{s:05.2f}"


def ts_srt(t: float) -> str:
    h, r = divmod(t, 3600)
    m, s = divmod(r, 60)
    return f"{int(h):02d}:{int(m):02d}:{int(s):02d},{int((s % 1) * 1000):03d}"


ASS_HEAD = """[Script Info]
ScriptType: v4.00+
PlayResX: 1920
PlayResY: 1080
WrapStyle: 2

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Cap,Inter,44,&H00FFFFFF,&H00B4B4B4,&H00000000,&HA0101418,1,0,0,0,100,100,0.3,0,3,14,0,2,160,160,64,1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""


def to_ass(words_json: str, out: str, max_words: int) -> None:
    words = json.loads(Path(words_json).read_text())["words"]
    lines = [ASS_HEAD]
    for c in chunks(words, max_words):
        start, end = c[0]["s"], c[-1]["e"] + 0.25
        parts = []
        for i, w in enumerate(c):
            nxt = c[i + 1]["s"] if i + 1 < len(c) else w["e"]
            k = max(1, int(round((nxt - w["s"]) * 100)))
            parts.append(f"{{\\kf{k}}}{w['w']}")
        # lead-in delay before the first word is already 0 because start == first word start
        lines.append(f"Dialogue: 0,{ts_ass(start)},{ts_ass(end)},Cap,,0,0,0,,{' '.join(parts)}")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text("\n".join(lines) + "\n")
    print(f"ASS -> {out}")


def to_srt(words_json: str, out: str, max_words: int) -> None:
    words = json.loads(Path(words_json).read_text())["words"]
    rows = []
    for i, c in enumerate(chunks(words, max_words), 1):
        rows.append(f"{i}\n{ts_srt(c[0]['s'])} --> {ts_srt(c[-1]['e'] + 0.2)}\n{' '.join(w['w'] for w in c)}\n")
    Path(out).write_text("\n".join(rows))
    print(f"SRT -> {out}")


def burn(video: str, subs: str, out: str) -> None:
    fonts = Path(__file__).resolve().parent.parent / "assets" / "fonts"
    vf = f"subtitles={subs}:fontsdir={fonts}" if fonts.exists() else f"subtitles={subs}"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", video, "-vf", vf, "-c:v", "libx264", "-crf", "17",
                    "-preset", "slow", "-c:a", "copy", out], check=True)
    print(f"burned -> {out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    t = sp.add_parser("transcribe"); t.add_argument("media"); t.add_argument("--out", default="build/captions/words.json")
    t.add_argument("--model", default="small.en"); t.add_argument("--prompt", default=GLOSSARY)
    s = sp.add_parser("ass"); s.add_argument("words"); s.add_argument("--out", required=True); s.add_argument("--max-words", type=int, default=7)
    r = sp.add_parser("srt"); r.add_argument("words"); r.add_argument("--out", required=True); r.add_argument("--max-words", type=int, default=9)
    b = sp.add_parser("burn"); b.add_argument("video"); b.add_argument("subs"); b.add_argument("--out", required=True)
    al = sp.add_parser("align"); al.add_argument("words"); al.add_argument("--script", default="plan/script.json")
    a = ap.parse_args()
    if a.cmd == "align":
        align_to_script(a.words, a.script)
    elif a.cmd == "transcribe":
        transcribe(a.media, a.out, a.model, a.prompt)
    elif a.cmd == "ass":
        to_ass(a.words, a.out, a.max_words)
    elif a.cmd == "srt":
        to_srt(a.words, a.out, a.max_words)
    else:
        burn(a.video, a.subs, a.out)


if __name__ == "__main__":
    main()
