#!/usr/bin/env bash
# Screen-records a real Terminal.app window running the Warden CLI demo.
# Left tmux pane: the Warden server (published npm package). Right pane: typed commands.
# Every command shown on screen is the command actually executed.
#
# Usage: bash scripts/term_reel.sh <out.mov> <marks.tsv>
# Needs: macOS Screen Recording permission for the terminal running this script.
set -u
set -m
OUT="${1:-$PWD/build/footage/terminal.mov}"
MARKS="${2:-$PWD/build/footage/terminal_marks.tsv}"
DB="${DEMO_DB:-$PWD/build/db/demo.db}"
FIX="$HOME/warden-demo-fixtures"
S=wdemo
X=36; Y=70; W=1440; H=810      # window in screen points (16:9)

DRY="${DRY:-0}"
tm() { tmux -L wdemo -f /dev/null "$@"; }
tm kill-server 2>/dev/null
ZD="$PWD/build/footage/zdot"; mkdir -p "$ZD"
cat > "$ZD/.zshrc" <<RC
export PATH="$HOME/.local/bin:$HOME/.bun/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export DB_PATH="$DB" WARDEN_NO_LAYA_INSTALL=1
PS1='%F{75}warden-demo%f %F{244}❯%f '
cd "$FIX"
RC
SH="env ZDOTDIR=$ZD zsh -i"
tm new-session -d -s $S -x 160 -y 44 "$SH"
tm set -g status off
tm set -g pane-border-style 'fg=#2a3340'
tm set -g pane-active-border-style 'fg=#2a3340'
L=$(tm display -p -t $S '#{pane_id}')
R=$(tm split-window -h -l 52% -t "$L" -P -F '#{pane_id}' "$SH")
[ -n "$R" ] || { echo "split failed"; exit 1; }
sleep 1

# Open a clean Terminal window attached to the tmux session.
if [ "$DRY" = 1 ]; then OSA_SKIP=1; fi
[ "${OSA_SKIP:-0}" = 1 ] || osascript <<OSA
tell application "Terminal"
  activate
  repeat with ow in (every window whose name contains "tmux")
    close ow saving no
  end repeat
  do script "tmux -L wdemo attach -t $S"
  delay 1
  set w to front window
  set current settings of w to settings set "Pro"
  set font size of current settings of w to 16
  set background color of current settings of w to {2570, 3598, 5140}
  set normal text color of current settings of w to {59000, 60900, 62965}
  set bounds of w to {$X, $Y, $((X+W)), $((Y+H))}
end tell
OSA
sleep 2

if [ "$DRY" = 1 ]; then sleep 9999 & else screencapture -v -x -V ${REC_SECS:-100} -R$X,$Y,$W,$H "$OUT" & fi
REC=$!
T0=$(date +%s)
: > "$MARKS"
mark() { printf '%s\t%s\n' "$1" "$(( $(date +%s) - T0 ))" >> "$MARKS"; }
type_in() { # pane, text
  local p=$1 t=$2 i
  for ((i=0; i<${#t}; i++)); do tm send-keys -t "$p" -l "${t:$i:1}"; sleep 0.028; done
  sleep 0.35; tm send-keys -t "$p" Enter
}
wait_for() { # pane, pattern, timeout
  local i; for ((i=0; i<${3:-90}; i++)); do tm capture-pane -p -t "$1" -S -200 | grep -q "$2" && return 0; sleep 1; done; return 1
}

sleep 2; mark install
type_in $R "bun --version"
sleep 1.5
mark start
type_in $L "bunx @shivdev/agent-warden --api-only --port 3000"
wait_for $L "Ctrl-C" 120; sleep 2.5
mark setup
type_in $R "bunx @shivdev/agent-warden setup --kiro"
wait_for $R "Restart\|No IDEs" 60; sleep 4
type_in $R "clear"
mark attack
type_in $R "cat invoice-email.json"
sleep 3
type_in $R "curl -s localhost:3000/scan -d @invoice-email.json | jq '{action, riskScore, attacks: [.findings[].attackType]}'"
wait_for $R '"action"' 30; sleep 4.5
mark benign
type_in $R "curl -s localhost:3000/scan -d @benign.json | jq '{action, riskScore}'"
sleep 1; wait_for $R 'ALLOW' 30; sleep 4
type_in $R "clear"
mark kiro
type_in $R "grep -n 'AI agent' -A1 vendor-notes.md"
sleep 3
type_in $R "kiro-cli chat --agent warden-demo --trust-tools=fs_read --no-interactive \"Summarize vendor-notes.md\""
wait_for $R "won't\|blocked\|Blocked" 120; sleep 6
mark summary
tm send-keys -t $L C-c
sleep 5
mark end
[ "$DRY" = 1 ] && kill $REC 2>/dev/null; wait $REC 2>/dev/null
[ "$DRY" = 1 ] && { tm capture-pane -p -t "$L" -S -80 > "${OUT%.*}_left.txt"; tm capture-pane -p -t "$R" -S -200 > "${OUT%.*}_right.txt"; }
tm kill-server 2>/dev/null
[ "$DRY" = 1 ] || osascript -e 'tell application "Terminal" to close front window' 2>/dev/null
echo "recorded $OUT"; cat "$MARKS"
