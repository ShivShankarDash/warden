#!/usr/bin/env python3
"""One-key media generation through OpenRouter (images, video, speech, music).

Reads OPENROUTER_API_KEY from the environment or from video/.env.
Every call appends a line to build/media_ledger.jsonl (model, prompt, output, cost when known),
which the critic and the final credits use.

  image  : python tools/media.py image  --prompt "..." --out kf/s01.png [--ref ref.png ...] [--model openai/gpt-image-2.5-sunburst] [--aspect 16:9]
  video  : python tools/media.py video  --prompt "..." --out shots/s01.mp4 [--first kf/s01.png] [--last kf/s01b.png]
                                         [--model bytedance/seedance-2.5|google/veo-3.1] [--duration 6] [--resolution 720p] [--audio]
  tts    : python tools/media.py tts    --text "[warmly] Hello" --out vo/l01.wav [--model google/gemini-3.8-flash-tts] [--voice Charon]
  music  : python tools/media.py music  --prompt "..." --out music/bed.mp3 [--seconds 180] [--provider elevenlabs|lyria]
  models : python tools/media.py models [image|video|speech]
"""
from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
API = "https://openrouter.ai/api/v1"
LEDGER = ROOT / "build" / "media_ledger.jsonl"

DEFAULTS = {
    "image": "openai/gpt-image-2.5-sunburst",
    "video_motion": "bytedance/seedance-2.5",   # better for camera/subject motion
    "video_static": "google/veo-3.1",            # better for photoreal, slower moves
    "tts": "google/gemini-3.8-flash-tts",
    "tts_free": "fish-audio/s2.1-pro-free:free",
    "music_lyria": "google/lyria-3-pro-preview",
}


def key(name: str = "OPENROUTER_API_KEY") -> str:
    if os.environ.get(name):
        return os.environ[name]
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip('"')
    sys.exit(f"{name} not set (env or {env})")


def hdr(json_body: bool = True) -> dict:
    h = {"Authorization": f"Bearer {key()}", "HTTP-Referer": "https://github.com/ShivShankarDash/warden", "X-Title": "warden-video"}
    if json_body:
        h["Content-Type"] = "application/json"
    return h


def ledger(**row) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    row["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with LEDGER.open("a") as f:
        f.write(json.dumps(row) + "\n")


def data_url(path: str) -> str:
    mime = mimetypes.guess_type(path)[0] or "image/png"
    return f"data:{mime};base64,{base64.b64encode(Path(path).read_bytes()).decode()}"


def fail(r: requests.Response) -> None:
    try:
        msg = r.json().get("error", {}).get("message", r.text)
    except Exception:
        msg = r.text
    sys.exit(f"HTTP {r.status_code}: {msg[:400]}")


# ---------------------------------------------------------------- image
def cmd_image(a) -> None:
    content: list = [{"type": "text", "text": a.prompt + (f"\nAspect ratio {a.aspect}." if a.aspect else "")}]
    for ref in a.ref or []:
        content.append({"type": "image_url", "image_url": {"url": data_url(ref)}})
    body = {"model": a.model, "modalities": ["image", "text"], "messages": [{"role": "user", "content": content}]}
    if a.aspect:
        body["image_config"] = {"aspect_ratio": a.aspect}
    r = requests.post(f"{API}/chat/completions", headers=hdr(), json=body, timeout=300)
    if r.status_code != 200:
        fail(r)
    j = r.json()
    imgs = j["choices"][0]["message"].get("images") or []
    if not imgs:
        sys.exit("model returned no image: " + json.dumps(j)[:400])
    url = imgs[0]["image_url"]["url"]
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(base64.b64decode(url.split(",", 1)[1]) if url.startswith("data:") else requests.get(url, timeout=120).content)
    ledger(kind="image", model=a.model, prompt=a.prompt, refs=a.ref, out=str(out), cost=j.get("usage", {}).get("cost"))
    print(out)


# ---------------------------------------------------------------- video
def cmd_video(a) -> None:
    body: dict = {"model": a.model, "prompt": a.prompt, "duration": a.duration, "resolution": a.resolution,
                  "aspect_ratio": a.aspect, "generate_audio": bool(a.audio)}
    frames = []
    if a.first:
        frames.append({"type": "image_url", "image_url": {"url": data_url(a.first)}, "frame_type": "first_frame"})
    if a.last:
        frames.append({"type": "image_url", "image_url": {"url": data_url(a.last)}, "frame_type": "last_frame"})
    if frames:
        body["frame_images"] = frames
    if a.ref:
        body["input_references"] = [{"type": "image_url", "image_url": {"url": data_url(p)}} for p in a.ref]
    if a.seed is not None:
        body["seed"] = a.seed
    r = requests.post(f"{API}/videos", headers=hdr(), json=body, timeout=120)
    if r.status_code not in (200, 201, 202):
        fail(r)
    job = r.json()
    poll = job.get("polling_url") or f"{API}/videos/{job['id']}"
    print(f"job {job['id']} submitted; polling", file=sys.stderr)
    t0 = time.time()
    while True:
        time.sleep(a.poll)
        s = requests.get(poll, headers=hdr(False), timeout=60).json()
        st = s.get("status")
        print(f"  {int(time.time() - t0)}s {st}", file=sys.stderr)
        if st == "completed":
            break
        if st in ("failed", "cancelled", "expired"):
            sys.exit(f"video job {st}: {json.dumps(s.get('error'))[:400]}")
        if time.time() - t0 > a.timeout:
            sys.exit(f"timed out; job {job['id']} still {st}")
    url = (s.get("unsigned_urls") or [f"{API}/videos/{job['id']}/content?index=0"])[0]
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(requests.get(url, headers=hdr(False), timeout=600).content)
    ledger(kind="video", model=a.model, prompt=a.prompt, first=a.first, last=a.last, out=str(out),
           duration=a.duration, cost=(s.get("usage") or {}).get("cost"))
    print(out)


# ---------------------------------------------------------------- tts
def cmd_tts(a) -> None:
    fmt = Path(a.out).suffix.lstrip(".")
    fmt = fmt if fmt in ("mp3", "pcm") else "mp3"   # the endpoint accepts only mp3 or pcm
    body = {"model": a.model, "input": a.text, "response_format": fmt}
    if a.voice:
        body["voice"] = a.voice
    if a.instructions:
        body["instructions"] = a.instructions
    if a.speed:
        body["speed"] = a.speed
    r = requests.post(f"{API}/audio/speech", headers=hdr(), json=body, timeout=300)
    if r.status_code != 200 or r.headers.get("content-type", "").startswith("application/json"):
        fail(r)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(r.content)
    ledger(kind="tts", model=a.model, voice=a.voice, text=a.text, out=str(out), gen=r.headers.get("x-generation-id"))
    print(out)


# ---------------------------------------------------------------- music
def cmd_music(a) -> None:
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if a.provider == "elevenlabs":
        # ElevenLabs Music API (needs ELEVENLABS_API_KEY). Instrumental bed under narration.
        r = requests.post("https://api.elevenlabs.io/v1/music", params={"output_format": "mp3_44100_192"},
                          headers={"xi-api-key": key("ELEVENLABS_API_KEY"), "Content-Type": "application/json"},
                          json={"prompt": a.prompt, "music_length_ms": int(a.seconds * 1000), "force_instrumental": True},
                          timeout=600)
        if r.status_code != 200:
            fail(r)
        out.write_bytes(r.content)
    else:
        body = {"model": a.model or DEFAULTS["music_lyria"], "modalities": ["text", "audio"],
                "audio": {"format": "mp3"},
                "messages": [{"role": "user", "content": f"{a.prompt}. Instrumental only. About {int(a.seconds)} seconds."}]}
        r = requests.post(f"{API}/chat/completions", headers=hdr(), json=body, timeout=600)
        if r.status_code != 200:
            fail(r)
        msg = r.json()["choices"][0]["message"]
        audio = msg.get("audio") or {}
        b64 = audio.get("data") or next((p.get("audio", {}).get("data") for p in (msg.get("content") or []) if isinstance(p, dict) and p.get("audio")), None)
        if not b64:
            sys.exit("no audio in response: " + json.dumps(msg)[:400])
        out.write_bytes(base64.b64decode(b64))
    ledger(kind="music", provider=a.provider, prompt=a.prompt, seconds=a.seconds, out=str(out))
    print(out)


def cmd_models(a) -> None:
    if a.kind == "video":
        d = requests.get(f"{API}/videos/models", headers=hdr(False), timeout=60).json()
        for m in d.get("data", d):
            print(m["id"], m.get("supported_durations"), m.get("supported_frame_images"), m.get("pricing_skus"))
        return
    mod = {"image": "image", "speech": "speech", "audio": "audio"}[a.kind]
    d = requests.get(f"{API}/models", params={"output_modalities": mod}, timeout=60).json()
    for m in d["data"]:
        print(m["id"])


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)

    i = sp.add_parser("image"); i.add_argument("--prompt", required=True); i.add_argument("--out", required=True)
    i.add_argument("--ref", action="append"); i.add_argument("--model", default=DEFAULTS["image"]); i.add_argument("--aspect", default="16:9")
    i.set_defaults(fn=cmd_image)

    v = sp.add_parser("video"); v.add_argument("--prompt", required=True); v.add_argument("--out", required=True)
    v.add_argument("--first"); v.add_argument("--last"); v.add_argument("--ref", action="append")
    v.add_argument("--model", default=DEFAULTS["video_motion"]); v.add_argument("--duration", type=int, default=6)
    v.add_argument("--resolution", default="720p"); v.add_argument("--aspect", default="16:9")
    v.add_argument("--audio", action="store_true"); v.add_argument("--seed", type=int)
    v.add_argument("--poll", type=int, default=15); v.add_argument("--timeout", type=int, default=1200)
    v.set_defaults(fn=cmd_video)

    t = sp.add_parser("tts"); t.add_argument("--text", required=True); t.add_argument("--out", required=True)
    t.add_argument("--model", default=DEFAULTS["tts"]); t.add_argument("--voice", default="Charon")
    t.add_argument("--instructions"); t.add_argument("--speed", type=float)
    t.set_defaults(fn=cmd_tts)

    m = sp.add_parser("music"); m.add_argument("--prompt", required=True); m.add_argument("--out", required=True)
    m.add_argument("--seconds", type=float, default=180); m.add_argument("--provider", default="elevenlabs", choices=["elevenlabs", "lyria"])
    m.add_argument("--model"); m.set_defaults(fn=cmd_music)

    mo = sp.add_parser("models"); mo.add_argument("kind", choices=["image", "video", "speech", "audio"]); mo.set_defaults(fn=cmd_models)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
