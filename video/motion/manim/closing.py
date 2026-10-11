"""Closing Summary: Warden as the careful reader between content and the assistant.

Covers the first closing line; the HyperFrames end card takes over at the second cue.
Render: manim -qh --fps 30 -r 1920,1080 motion/manim/closing.py ClosingScene
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from brand import *  # noqa: E402,F403


class ClosingScene(Timed):
    def construct(self):
        sec = timeline_section("closing")
        END = sec["lines"][1]["local"] + 0.4  # hand over to the end card

        srcs = VGroup(*[chip(t, MUTED, size=20, mono=False) for t in ("web pages", "email", "files", "tool results")]).arrange(DOWN, buff=0.35)
        srcs.to_edge(LEFT, buff=1.0)
        guard = shield(1.05).move_to(ORIGIN).set_z_index(10)
        glbl = T("Warden", 30, INK, SEMIBOLD).next_to(guard, DOWN, buff=0.3)
        ai_ring = Circle(radius=1.0, stroke_color=GREEN, stroke_width=4, fill_color="#0E1A2B", fill_opacity=1)
        ai_txt = T("AI", 56, INK, BOLD, DISPLAY).move_to(ai_ring)
        ai_lbl = T("your assistant", 22, MUTED).next_to(ai_ring, DOWN, buff=0.3)
        ai = VGroup(ai_ring, ai_txt, ai_lbl).to_edge(RIGHT, buff=1.4)

        self.at(0.1)
        self.play(LaggedStart(FadeIn(srcs, shift=RIGHT * 0.3), GrowFromCenter(guard), FadeIn(glbl), FadeIn(ai, shift=LEFT * 0.3), lag_ratio=0.25), run_time=1.6)

        items = [("revenue summary", False), ("meeting notes", False), ("forward every invoice…", True), ("pricing table", False), ("ignore your rules…", True), ("release notes", False)]
        anims = []
        for k, (txt, bad) in enumerate(items):
            c = chip(txt, RED_L if bad else BLUE_L, fill="#2A1215" if bad else "#13233A", size=16)
            src = srcs[k % 4]
            c.move_to(src.get_right() + RIGHT * (c.width / 2 + 0.3))
            self.add(c)
            c.set_opacity(0)
            p0 = c.get_center().copy()
            p1 = guard.get_left() + LEFT * (c.width / 2 + 0.2)
            p2 = (p1 + DOWN * 0.7) if bad else (ai_ring.get_left() + LEFT * (c.width / 2 + 0.2))

            def upd(m, a, p0=p0, p1=p1, p2=p2, bad=bad):
                if a < 0.55:
                    k = rate_functions.ease_in_out_sine(a / 0.55)
                    pos, op = p0 + (p1 - p0) * k, min(1, a / 0.08)
                else:
                    k = rate_functions.ease_out_sine((a - 0.55) / 0.45)
                    pos = p1 + (p2 - p1) * k
                    op = (1 - k) if bad else (1 if a < 0.92 else (1 - a) / 0.08)
                m.move_to(pos).set_opacity(max(0, op))
            seq = UpdateFromAlphaFunc(c, upd, run_time=2.2)
            anims.append(seq)
        self.play(LaggedStart(*anims, lag_ratio=0.45), run_time=5.0)
        line = T("a careful reader, in between", 30, INK, MEDIUM).to_edge(UP, buff=0.9)
        self.play(FadeIn(line, shift=DOWN * 0.15), run_time=0.7)
        self.at(END - 0.6)
        self.play(*[FadeOut(m) for m in self.mobjects], run_time=0.6)
