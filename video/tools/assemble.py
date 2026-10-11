#!/usr/bin/env python3
"""Assemble the film with OpenTimelineIO, then render the OTIO timeline with ffmpeg.

  python tools/assemble.py build      # writes build/timeline.otio from plan/timeline.json + rendered scenes
  python tools/assemble.py render     # renders build/timeline.otio -> build/final/warden_demo.mp4
  python tools/assemble.py all
  python tools/assemble.py animatic   # same timeline, but every scene replaced by its storyboard still

Tracks
  V1  section renders (HyperFrames / Manim / Motion Canvas)       hard cuts, each scene fades itself
  V2  B-roll overlays (Creative Commons clips, AI shots)           metadata: fade_in / fade_out / grade
  A1  narration lines (Gemini TTS or fallback)                    placed at timeline.json cue times
  A2  music bed                                                   ducked under A1 by sidechain compression
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import opentimelineio as otio

ROOT = Path(__file__).resolve().parent.parent
B = ROOT / "build"
FPS = 30
DRIFT = {"problem", "ai", "impact"}  # static-ish renders get a slow 3.5% push-in so holds never read as frozen


def rt(sec: float) -> otio.opentime.RationalTime:
    return otio.opentime.RationalTime(round(sec * FPS), FPS)


def tr(start: float, dur: float) -> otio.opentime.TimeRange:
    return otio.opentime.TimeRange(rt(start), rt(dur))


def clip(name: str, path: Path, src_in: float, dur: float, **meta) -> otio.schema.Clip:
    c = otio.schema.Clip(name=name, media_reference=otio.schema.ExternalReference(target_url=str(path)), source_range=tr(src_in, dur))
    c.metadata["warden"] = meta
    return c


def gap(dur: float) -> otio.schema.Gap:
    return otio.schema.Gap(source_range=tr(0, dur))


def place(track: otio.schema.Track, items: list[tuple[float, otio.schema.Clip]]) -> None:
    """Place clips at absolute times, filling the holes with gaps."""
    t = 0.0
    for at, c in sorted(items, key=lambda x: x[0]):
        if at > t + 1e-3:
            track.append(gap(at - t))
            t = at
        track.append(c)
        t += c.source_range.duration.to_seconds()


def build(animatic: bool = False) -> Path:
    tl = json.loads((ROOT / "plan" / "timeline.json").read_text())
    S = {s["id"]: s for s in tl["sections"]}
    scenes = B / ("animatic" if animatic else "scenes")
    timeline = otio.schema.Timeline(name="Warden: a firewall for AI agents" + (" (animatic)" if animatic else ""))
    timeline.global_start_time = rt(0)

    # V1: section renders. Closing = Manim diagram + HyperFrames end card.
    v1 = otio.schema.Track(name="V1 scenes", kind=otio.schema.TrackKind.Video)
    order = [("intro", "intro.mp4"), ("problem", "problem.mp4"), ("demo", "demo.mp4"), ("ai", "pipeline.mp4"),
             ("features", "features.mp4"), ("impact", "impact.mp4")]
    for sid, f in order:
        v1.append(clip(sid, scenes / f, 0, S[sid]["duration"], section=sid, drift=sid in DRIFT))
    cl = S["closing"]
    split = cl["lines"][1]["local"] + 0.4
    v1.append(clip("closing-diagram", scenes / "closing.mp4", 0, split, section="closing", drift=True))
    v1.append(clip("endcard", scenes / "endcard.mp4", 0, cl["duration"] - split, section="closing"))
    timeline.tracks.append(v1)

    # V2: B-roll overlays (Creative Commons), only if fetched.
    v2 = otio.schema.Track(name="V2 b-roll", kind=otio.schema.TrackKind.Video)
    broll = []
    if (B / "clips" / "typing.mp4").exists():
        broll.append((S["demo"]["start"], clip("cc-typing", B / "clips" / "typing.mp4", 0.6, 2.3, fade_in=0.0, fade_out=0.6,
                                               grade="dark", credit="Videvo, CC BY")))
    if (B / "clips" / "server.mp4").exists():
        broll.append((S["impact"]["start"] + 0.2, clip("cc-server", B / "clips" / "server.mp4", 1.6, 3.3, fade_in=0.4, fade_out=0.7,
                                                       grade="dark", credit="101GreenLight TV, CC BY")))
    for p in sorted((B / "shots").glob("*.json")) if (B / "shots").exists() else []:
        spec = json.loads(p.read_text())   # AI b-roll written by the media skill: {file, at, in, dur}
        broll.append((spec["at"], clip(p.stem, B / "shots" / spec["file"], spec.get("in", 0), spec["dur"], fade_in=.3, fade_out=.3, grade="none")))
    place(v2, broll)
    timeline.tracks.append(v2)

    # V3: captions overlay (transparent HyperFrames render of the word timings), when present
    v3 = otio.schema.Track(name="V3 captions", kind=otio.schema.TrackKind.Video)
    cap = scenes / "captions_overlay.webm"
    if cap.exists() and not animatic:
        v3.append(clip("captions", cap, 0, tl["duration"], alpha=True))
    timeline.tracks.append(v3)

    # A1: narration
    a1 = otio.schema.Track(name="A1 narration", kind=otio.schema.TrackKind.Audio)
    vo = []
    for s in tl["sections"]:
        for l in s["lines"]:
            vo.append((l["start"], clip(l["id"], ROOT / l["file"], 0, l["duration"], text=l["text"])))
    place(a1, vo)
    timeline.tracks.append(a1)

    # A2: music
    a2 = otio.schema.Track(name="A2 music", kind=otio.schema.TrackKind.Audio)
    bed = B / "music" / "bed.wav"
    if bed.exists():
        a2.append(clip("music-bed", bed, 0, tl["duration"], duck_db=14))
    timeline.tracks.append(a2)

    out = B / ("animatic.otio" if animatic else "timeline.otio")
    otio.adapters.write_to_file(timeline, str(out))
    print(f"wrote {out}  ({timeline.duration().to_seconds():.2f}s, {len(vo)} VO clips, {len(broll)} b-roll)")
    return out


def items_with_time(track: otio.schema.Track):
    for c in track:
        if isinstance(c, otio.schema.Clip):
            r = track.range_of_child(c)
            yield c, r.start_time.to_seconds(), r.duration.to_seconds()


def render(otio_path: Path, out: Path, crf: int = 16) -> None:
    timeline = otio.adapters.read_from_file(str(otio_path))
    total = timeline.duration().to_seconds()
    byname = {t.name.split()[0]: t for t in timeline.tracks}
    v1, v2, a1, a2 = byname["V1"], byname["V2"], byname["A1"], byname["A2"]
    v3 = byname.get("V3")
    inputs: list[str] = []
    fc: list[str] = []

    def add_input(path: str, extra: list[str] | None = None) -> int:
        inputs.extend((extra or []) + ["-i", path])
        return len([x for x in inputs if x == "-i"]) - 1

    # V1 concat, each normalised to exact length
    labels = []
    for k, (c, at, d) in enumerate(items_with_time(v1)):
        i = add_input(c.media_reference.target_url)
        sin = c.source_range.start_time.to_seconds()
        drift = (f",scale=w='trunc(1920*(1+0.035*t/{d:.3f})/2)*2':h=-2:eval=frame:flags=bicubic,crop=1920:1080" if c.metadata.get("warden", {}).get("drift") else "")
        fc.append(f"[{i}:v]trim=start={sin:.3f},setpts=PTS-STARTPTS,fps={FPS},scale=1920:1080:flags=lanczos{drift},setsar=1,format=yuv420p,"
                  f"tpad=stop_mode=clone:stop_duration=2,trim=duration={d:.3f}[v{k}]")
        labels.append(f"[v{k}]")
    fc.append(f"{''.join(labels)}concat=n={len(labels)}:v=1:a=0[base]")
    cur = "base"

    # V2 overlays with fades and a dark grade so they sit under the brand
    for k, (c, at, d) in enumerate(items_with_time(v2)):
        m = c.metadata.get("warden", {})
        i = add_input(c.media_reference.target_url)
        sin = c.source_range.start_time.to_seconds()
        grade = ",eq=brightness=-0.06:saturation=0.75,colorbalance=bs=0.05:bm=0.03" if m.get("grade") == "dark" else ""
        fi, fo = m.get("fade_in", 0.3), m.get("fade_out", 0.3)
        fades = (f",fade=t=in:st=0:d={fi}:alpha=1" if fi else "") + f",fade=t=out:st={d - fo:.3f}:d={fo}:alpha=1"
        fc.append(f"[{i}:v]trim=start={sin:.3f}:duration={d:.3f},setpts=PTS-STARTPTS,fps={FPS},"
                  f"scale=1920:1080:force_original_aspect_ratio=increase,crop=1920:1080{grade},format=yuva420p{fades},"
                  f"setpts=PTS+{at:.3f}/TB[o{k}]")
        fc.append(f"[{cur}][o{k}]overlay=eof_action=pass:format=auto[b{k}]")
        cur = f"b{k}"
    # V3 captions on top (VP9 alpha needs the libvpx decoder to keep transparency)
    for k, (c, at, d) in enumerate(items_with_time(v3) if v3 is not None else []):
        i = add_input(c.media_reference.target_url, ["-c:v", "libvpx-vp9"])
        fc.append(f"[{i}:v]setpts=PTS-STARTPTS,fps={FPS},format=yuva420p[cap{k}]")
        fc.append(f"[{cur}][cap{k}]overlay=eof_action=pass:format=auto[cc{k}]")
        cur = f"cc{k}"
    fc.append(f"[{cur}]format=yuv420p[vout]")

    # A1 narration
    vo_labels = []
    for k, (c, at, d) in enumerate(items_with_time(a1)):
        i = add_input(c.media_reference.target_url)
        ms = int(round(at * 1000))
        fc.append(f"[{i}:a]aresample=48000,aformat=channel_layouts=stereo,atrim=duration={d:.3f},adelay={ms}|{ms}[n{k}]")
        vo_labels.append(f"[n{k}]")
    fc.append(f"{''.join(vo_labels)}amix=inputs={len(vo_labels)}:normalize=0:dropout_transition=0,apad=whole_dur={total:.3f},atrim=duration={total:.3f}[vo]")

    # A2 music, ducked under the voice
    music = list(items_with_time(a2))
    if music:
        c, at, d = music[0]
        i = add_input(c.media_reference.target_url)
        fc.append(f"[vo]asplit=2[vo1][vokey]")
        fc.append(f"[{i}:a]aresample=48000,aformat=channel_layouts=stereo,atrim=duration={total:.3f},volume=-9dB[mus]")
        fc.append("[mus][vokey]sidechaincompress=threshold=0.02:ratio=8:attack=40:release=600:makeup=1[duck]")
        fc.append("[vo1][duck]amix=inputs=2:normalize=0:duration=first,loudnorm=I=-14:TP=-1.0:LRA=9[aout]")
    else:
        fc.append("[vo]loudnorm=I=-14:TP=-1.0:LRA=9[aout]")

    out.parent.mkdir(parents=True, exist_ok=True)
    fc_path = B / "final" / "filter_complex.txt"
    fc_path.write_text(";\n".join(fc))
    cmd = ["ffmpeg", "-y", "-loglevel", "error", "-stats", *inputs, "-/filter_complex", str(fc_path),
           "-map", "[vout]", "-map", "[aout]", "-c:v", "libx264", "-preset", "slow", "-crf", str(crf), "-profile:v", "high",
           "-pix_fmt", "yuv420p", "-r", str(FPS), "-c:a", "aac", "-b:a", "256k", "-ar", "48000", "-movflags", "+faststart",
           "-t", f"{total:.3f}", str(out)]
    subprocess.run(cmd, check=True)
    print(f"rendered {out}")


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd in ("build", "all"):
        build()
    if cmd in ("render", "all"):
        render(B / "timeline.otio", B / "final" / "warden_demo.mp4")
    if cmd == "animatic":
        p = build(animatic=True)
        render(p, B / "final" / "warden_animatic.mp4", crf=28)


if __name__ == "__main__":
    main()
