#!/usr/bin/env bash
# Wait until the user has been idle (no keyboard/mouse) for IDLE_SECS, then run the terminal take.
# Usage: bash scripts/record_when_idle.sh [IDLE_SECS=90] [MAX_WAIT_SECS=7200]
set -u
cd "$(dirname "$0")/.."
NEED="${1:-90}"; MAX="${2:-7200}"; waited=0
idle() { ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print int($NF/1000000000); exit}'; }
while :; do
  i=$(idle)
  if [ "${i:-0}" -ge "$NEED" ]; then break; fi
  sleep 10; waited=$((waited + 10))
  if [ "$waited" -ge "$MAX" ]; then echo "gave up after ${MAX}s"; exit 3; fi
done
echo "idle ${i}s -> recording at $(date +%T)"
REC_SECS=95 bash scripts/term_reel.sh "$PWD/build/footage/terminal_v2.mov" "$PWD/build/footage/terminal_v2_marks.tsv"
# was the user idle the whole time? (idle counter must exceed the take length)
i2=$(idle); echo "idle after take: ${i2}s"
if [ "${i2:-0}" -ge 90 ]; then echo CLEAN; else echo "INTERRUPTED"; fi
