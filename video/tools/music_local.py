#!/usr/bin/env python3
"""Offline fallback music bed: an original, royalty-free ambient track synthesised with numpy.

Used when neither ElevenLabs (ELEVENLABS_API_KEY) nor OpenRouter Lyria (needs balance) is available.
Warm maj7 pads, a soft plucked arpeggio and a sub, 72 bpm, with section-aware intensity:
quieter under the demo, a lift at the end card.

  python tools/music_local.py --seconds 221 --out build/music/bed.wav
"""
from __future__ import annotations

import argparse
import json
import subprocess
import wave
from pathlib import Path

import numpy as np

SR = 48000
ROOT = Path(__file__).resolve().parent.parent


def midi(n: float) -> float:
    return 440.0 * 2 ** ((n - 69) / 12)


def lowpass(x: np.ndarray, cutoff: float) -> np.ndarray:
    from scipy.signal import butter, sosfilt
    sos = butter(2, cutoff, btype="low", fs=SR, output="sos")
    return sosfilt(sos, x)


def pad_voice(freq: float, n: int, rng: np.random.Generator) -> np.ndarray:
    t = np.arange(n) / SR
    out = np.zeros(n)
    for det in (-0.07, 0.0, 0.06):
        f = freq * 2 ** (det / 12)
        ph = rng.uniform(0, 2 * np.pi)
        # band-limited-ish saw via a few harmonics
        for k in range(1, 7):
            out += np.sin(2 * np.pi * f * k * t + ph * k) / k * (0.85 ** k)
    return out / 6


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=221)
    ap.add_argument("--out", default=str(ROOT / "build" / "music" / "bed.wav"))
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)

    bpm = 72
    beat = 60 / bpm
    bar = 4 * beat
    # Dmaj7 - Bm9 - Gmaj7 - A6/9 (two bars each)
    chords = [[50, 57, 61, 64, 66], [47, 54, 57, 61, 62], [43, 50, 54, 57, 59], [45, 52, 54, 57, 59]]
    total = int(a.seconds * SR)
    mix = np.zeros(total)

    # pads
    chord_len = 2 * bar
    n_ch = int(np.ceil(a.seconds / chord_len))
    for c in range(n_ch):
        notes = chords[c % 4]
        s = int(c * chord_len * SR)
        n = int((chord_len + 1.5) * SR)
        seg = np.zeros(n)
        for m in notes:
            seg += pad_voice(midi(m), n, rng)
        env = np.ones(n)
        att, rel = int(1.2 * SR), int(1.8 * SR)
        env[:att] = np.linspace(0, 1, att)
        env[-rel:] = np.linspace(1, 0, rel)
        seg *= env * 0.16
        e = min(total, s + n)
        mix[s:e] += seg[: e - s]
    mix = lowpass(mix, 1400)

    # sub
    t = np.arange(total) / SR
    sub = np.zeros(total)
    for c in range(n_ch):
        root = chords[c % 4][0] - 12
        s = int(c * chord_len * SR)
        e = min(total, int((c + 1) * chord_len * SR))
        sub[s:e] = np.sin(2 * np.pi * midi(root) * t[s:e]) * 0.18
    mix += lowpass(sub, 200)

    # plucked arpeggio, eighth notes, quiet
    arp = np.zeros(total)
    step = beat / 2
    n_steps = int(a.seconds / step)
    pattern = [0, 2, 3, 4, 3, 2, 1, 2]
    for i in range(n_steps):
        c = int(i * step // chord_len)
        notes = chords[c % 4]
        m = notes[pattern[i % 8] % len(notes)] + 12
        s = int(i * step * SR)
        n = int(1.2 * SR)
        tt = np.arange(n) / SR
        tone = (np.sin(2 * np.pi * midi(m) * tt) + 0.3 * np.sin(2 * np.pi * midi(m) * 2 * tt)) * np.exp(-tt * 4.5)
        e = min(total, s + n)
        vel = 0.05 + 0.015 * ((i % 8) == 0)
        arp[s:e] += tone[: e - s] * vel
    mix += lowpass(arp, 3200)

    # section-aware intensity from the timeline (if present)
    tl_path = ROOT / "plan" / "timeline.json"
    gain = np.ones(total)
    if tl_path.exists():
        tl = json.loads(tl_path.read_text())
        level = {"intro": 1.0, "problem": 0.85, "demo": 0.7, "ai": 0.85, "features": 0.8, "impact": 0.9, "closing": 1.05}
        pts_t, pts_g = [], []
        for s in tl["sections"]:
            pts_t += [s["start"] + 0.5, s["start"] + s["duration"] - 0.5]
            pts_g += [level.get(s["id"], 0.85)] * 2
        gain = np.interp(t, pts_t, pts_g)
    mix *= gain
    # fades
    fi, fo = int(2.5 * SR), int(4.0 * SR)
    mix[:fi] *= np.linspace(0, 1, fi)
    mix[-fo:] *= np.linspace(1, 0, fo)

    # simple stereo: Haas-widened copy
    d = int(0.012 * SR)
    left = mix
    right = np.concatenate([np.zeros(d), mix[:-d]])
    st = np.stack([left, right], axis=1)
    st /= np.max(np.abs(st)) + 1e-9
    st *= 0.8
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    raw = out.with_suffix(".raw.wav")
    with wave.open(str(raw), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes((st * 32767).astype("<i2").tobytes())
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(raw), "-af", "loudnorm=I=-20:TP=-2:LRA=9", "-ar", str(SR), str(out)], check=True)
    raw.unlink()
    print(out)


if __name__ == "__main__":
    main()
