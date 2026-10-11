#!/usr/bin/env python3
"""Build a transparent HyperFrames caption overlay from word timings (karaoke highlight).

Used when the local ffmpeg has no libass (so `captions.py burn` is unavailable), and because
an HTML overlay matches the rest of the design system. Output: motion/hf/captions_overlay.html,
rendered to build/scenes/captions_overlay.mov (ProRes 4444 with alpha) and composited last.

  python tools/captions_overlay.py build/captions/words.json [--max-words 7]
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from captions import chunks  # noqa: E402

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8" />
<meta name="viewport" content="width=1920, height=1080" />
<script src="https://cdn.jsdelivr.net/npm/gsap@3.14.2/dist/gsap.min.js"></script>
<link rel="stylesheet" href="brand.css" />
<style>
  html, body { background: transparent; }
  .cap { position: absolute; left: 50%; bottom: 46px; transform: translateX(-50%); max-width: 1180px; text-align: center;
         padding: 14px 26px; border-radius: 16px; background: rgba(8,11,16,.78); border: 1px solid rgba(134,182,239,.14);
         font: 600 38px/1.3 var(--sans); letter-spacing: -.005em; color: rgba(232,237,245,.62); opacity: 0; white-space: nowrap; }
  .cap .w { display: inline-block; margin: 0 .14em; }
  .cap .w.on { color: #fff; }
</style></head>
<body>
<div id="root" data-composition-id="captions" data-start="0" data-duration="__DUR__" data-width="1920" data-height="1080">
  <div class="stage clip" data-start="0" data-duration="__DUR__" style="background:transparent">
__CAPS__
  </div>
</div>
<script>
  const tl = gsap.timeline({ paused: true });
  const C = __DATA__;
  C.forEach((c, i) => {
    const el = "#c" + i;
    tl.set(el, { opacity: 1 }, c.s).set(el, { opacity: 0 }, c.e);
    c.w.forEach((w, j) => { tl.set(el + " .w" + j, { className: "w w" + j + " on" }, w); });
  });
  window.__timelines = window.__timelines || {};
  window.__timelines["captions"] = tl;
  tl.seek(0);
</script>
</body></html>
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("words")
    ap.add_argument("--max-words", type=int, default=7)
    ap.add_argument("--out", default=str(ROOT / "motion" / "hf" / "captions_overlay.html"))
    a = ap.parse_args()
    words = json.loads(Path(a.words).read_text())["words"]
    tl = json.loads((ROOT / "plan" / "timeline.json").read_text())
    groups = chunks(words, a.max_words)
    data, divs = [], []
    for i, g in enumerate(groups):
        s = g[0]["s"]
        nxt = groups[i + 1][0]["s"] if i + 1 < len(groups) else tl["duration"]
        e = min(g[-1]["e"] + 0.35, nxt - 0.02)
        data.append({"s": round(s, 3), "e": round(e, 3), "w": [round(w["s"], 3) for w in g]})
        spans = "".join(f'<span class="w w{j}">{html.escape(w["w"])}</span>' for j, w in enumerate(g))
        divs.append(f'    <div class="cap" id="c{i}">{spans}</div>')
    page = (TEMPLATE.replace("__DUR__", f"{tl['duration']:.3f}").replace("__CAPS__", "\n".join(divs))
            .replace("__DATA__", json.dumps(data)))
    Path(a.out).write_text(page)
    print(f"{len(groups)} caption groups -> {a.out}")


if __name__ == "__main__":
    main()
