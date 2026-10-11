#!/usr/bin/env bash
# Render all Manim scenes. Usage: bash tools/render_manim.sh [draft|final] [scene-file ...]
# draft = 480p15 preview, final = 1080p30 into build/scenes/<file>.mp4
set -euo pipefail
cd "$(dirname "$0")/.."
Q="${1:-final}"; shift || true
FILES=("$@"); [ ${#FILES[@]} -eq 0 ] && FILES=(problem pipeline closing)
for f in "${FILES[@]}"; do
  cls=$(grep -oE '^class [A-Za-z]+Scene' "motion/manim/$f.py" | head -1 | awk '{print $2}')
  if [ "$Q" = draft ]; then
    .venv/bin/manim -ql --fps 15 --media_dir build/manim "motion/manim/$f.py" "$cls" 2>&1 | grep -E "Error|Traceback|File ready" || true
  else
    .venv/bin/manim -qh --fps 30 -r 1920,1080 --media_dir build/manim "motion/manim/$f.py" "$cls" 2>&1 | grep -E "Error|Traceback|File ready" || true
    mkdir -p build/scenes
    cp "build/manim/videos/$f/1080p30/$cls.mp4" "build/scenes/$f.mp4"
    echo "-> build/scenes/$f.mp4"
  fi
done
