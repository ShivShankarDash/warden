#!/usr/bin/env bash
# Contact sheet: N evenly spaced frames tiled into one PNG.
# Usage: bash tools/contact.sh <video> <out.png> [cols=4] [rows=2] [width=640]
set -euo pipefail
V="$1"; OUT="$2"; C="${3:-4}"; R="${4:-2}"; W="${5:-640}"
D=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$V")
N=$((C * R))
FPS=$(python3 -c "print($N/$D)")
ffmpeg -y -loglevel error -i "$V" -vf "fps=$FPS,scale=$W:-1,tile=${C}x${R}" -frames:v 1 "$OUT"
echo "$OUT ($D s)"
