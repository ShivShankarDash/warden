#!/usr/bin/env bash
# Render HyperFrames compositions from motion/hf.
# Usage: bash tools/render_hf.sh <draft|final> <comp> [comp ...]     e.g. bash tools/render_hf.sh final intro demo
# draft -> build/test/<comp>_draft.mp4 (+ contact sheet), final -> build/scenes/<comp>.mp4 (or .mov for *overlay*)
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.nvm/versions/node/v22.23.3/bin:$PATH" HYPERFRAMES_SKIP_SKILLS=1
HF="$PWD/hf/node_modules/.bin/hyperframes"
Q="$1"; shift
mkdir -p build/test build/scenes
for c in "$@"; do
  if [ "$Q" = draft ]; then
    out="$PWD/build/test/${c}_draft.mp4"
    (cd motion/hf && "$HF" render . -c "$c.html" -q draft -o "$out" --quiet) 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -iE "error|warn|fail" | head -10 || true
    bash tools/contact.sh "$out" "build/test/${c}_contact.png" 4 3 640
  else
    if [[ "$c" == *overlay* ]]; then out="$PWD/build/scenes/$c.webm"; fmt=webm; W="-w 1"; else out="$PWD/build/scenes/$c.mp4"; fmt=mp4; W=""; fi
    (cd motion/hf && "$HF" render . -c "$c.html" -q delivery --format "$fmt" --video-frame-format png $W -o "$out" --quiet) 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -iE "error|warn|fail" | head -10 || true
    echo "-> $out"
  fi
done
