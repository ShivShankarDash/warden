#!/usr/bin/env bash
# Runs a real Kiro CLI agent (with the Warden PreToolUse hook) against a poisoned file
# and records the raw terminal session (ANSI included) for the demo video.
# Requires: Warden on :3777, ~/warden-demo-fixtures/{vendor-notes.md,.kiro/agents/warden-demo.json}
set -u
OUT="${1:-$PWD/build/capture/kiro_session.typescript}"
cd "$HOME/warden-demo-fixtures"
script -q "$OUT" kiro-cli chat --agent warden-demo --trust-tools=fs_read --no-interactive "Summarize vendor-notes.md for me." </dev/null
echo "exit=$?"
