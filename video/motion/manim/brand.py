"""Shared Warden design tokens for Manim scenes (match HyperFrames/Motion Canvas CSS vars)."""
from __future__ import annotations

import json
from pathlib import Path

from manim import *  # noqa: F401,F403

ROOT = Path(__file__).resolve().parents[2]
FONTS = ROOT / "assets" / "fonts"

BG = "#0A0E14"
PANEL = "#111823"
STROKE = "#223047"
INK = "#E8EDF5"
MUTED = "#8390A3"
FAINT = "#4A5568"
BLUE = "#2A78D6"
BLUE_L = "#86B6EF"
RED = "#E5484D"
RED_L = "#FF8589"
GREEN = "#3DBE7A"
AMBER = "#F5B83D"

SANS = "Inter"
DISPLAY = "Inter Display"
MONO = "JetBrains Mono"


def timeline_section(sec_id: str) -> dict:
    tl = json.loads((ROOT / "plan" / "timeline.json").read_text())
    return next(s for s in tl["sections"] if s["id"] == sec_id)


def T(text: str, size: float = 28, color: str = INK, weight: str = MEDIUM, font: str = SANS, **kw) -> Text:
    return Text(text, font=font, font_size=size, color=color, weight=weight, **kw)


def M(text: str, size: float = 22, color: str = INK, **kw) -> Text:
    return Text(text, font=MONO, font_size=size, color=color, **kw)


def card(w: float, h: float, fill: str = PANEL, stroke: str = STROKE, r: float = 0.18, sw: float = 2) -> RoundedRectangle:
    return RoundedRectangle(width=w, height=h, corner_radius=r, fill_color=fill, fill_opacity=1, stroke_color=stroke, stroke_width=sw)


def chip(text: str, color: str = MUTED, fill: str = "#151D2A", size: float = 18, pad: float = 0.22, mono: bool = True) -> VGroup:
    t = M(text, size, color) if mono else T(text, size, color)
    box = RoundedRectangle(width=t.width + pad * 2, height=t.height + pad * 1.3, corner_radius=0.12,
                           fill_color=fill, fill_opacity=1, stroke_color=STROKE, stroke_width=1.5)
    t.move_to(box)
    return VGroup(box, t)


def shield(scale: float = 1.0, color: str = BLUE) -> VGroup:
    """Simple shield glyph with a 'W' — the Warden mark."""
    pts = [UP * 1.0, RIGHT * 0.85 + UP * 0.7, RIGHT * 0.78 + DOWN * 0.15, DOWN * 1.0, LEFT * 0.78 + DOWN * 0.15, LEFT * 0.85 + UP * 0.7]
    body = Polygon(*pts, fill_color=color, fill_opacity=1, stroke_color=BLUE_L, stroke_width=3).round_corners(0.12)
    w = Text("W", font=DISPLAY, weight=BOLD, font_size=64, color=WHITE).move_to(body).shift(UP * 0.05)
    return VGroup(body, w).scale(scale)


class Timed(Scene):
    """Scene with an absolute clock: self.at(t) waits until scene time t (seconds)."""

    def at(self, t: float) -> None:
        now = self.renderer.time
        if t > now + 1e-3:
            self.wait(t - now)

    def setup(self) -> None:
        self.camera.background_color = BG


def _register_fonts() -> None:
    import manimpango
    for f in sorted(FONTS.glob("*.ttf")):
        manimpango.register_font(str(f))


_register_fonts()
