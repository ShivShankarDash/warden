#!/usr/bin/env bash
# Grab frames at given timestamps and tile them, labelled. Usage: bash tools/frames_at.sh <video> <out.png> <cols> t1 t2 ...
set -euo pipefail
V="$1"; OUT="$2"; C="$3"; shift 3
TMP=$(mktemp -d)
i=0
for t in "$@"; do
  ffmpeg -y -loglevel error -ss "$t" -i "$V" -frames:v 1 -vf scale=800:-1 "$TMP/$(printf %03d $i).png"
  i=$((i+1))
done
R=$(( (i + C - 1) / C ))
ffmpeg -y -loglevel error -pattern_type glob -i "$TMP/*.png" -vf "tile=${C}x${R}" -frames:v 1 "$OUT"
rm -rf "$TMP"; echo "$OUT"
