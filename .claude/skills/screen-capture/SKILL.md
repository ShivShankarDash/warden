---
name: screen-capture
description: Records real product footage for demo videos, covering a scripted Terminal/tmux take of CLI commands (including Kiro CLI with Warden hooks) via macOS screencapture, and crisp Playwright CDP-screencast tours of the web dashboard, then conforms the takes to the narration. Use when a video needs genuine CLI, IDE-agent or dashboard footage, or when re-shooting a take.
---

# Screen capture

## Terminal take (real commands, real output)

`video/scripts/term_reel.sh` opens one Terminal window (opaque navy profile, 16 pt) attached to a private tmux socket. The left pane runs the published package (`bunx @shivdev/agent-warden --api-only --port 3000`) and the right pane types and runs each command. `screencapture -v -V <secs> -R x,y,w,h` records just that window at Retina resolution, and beat markers go to `build/footage/terminal_marks.tsv`.

```bash
DRY=1 bash scripts/term_reel.sh build/footage/dry.mov build/footage/dry_marks.tsv   # no window, no recording: validates every step
bash scripts/record_when_idle.sh 90                                                  # waits for 90 s of user idleness, then records; prints CLEAN / INTERRUPTED
```

Requirements and lessons learned:
- The terminal app needs **Screen Recording** permission (System Settings › Privacy & Security). Without it, `screencapture` fails with "could not create image from display".
- Region capture records whatever is on top. Never record while the user is working: use `record_when_idle.sh`, and check the contact sheet afterwards.
- Use an **opaque** profile background. Terminal's "Pro" profile is translucent, and other windows ghost through.
- `screencapture` discards the file if interrupted. Give it a fixed `-V` duration and let it finish.
- tmux 3.4 dropped `split-window -p`; use `-l 52%`. Use `-L <socket> -f /dev/null` so the user's tmux config can't renumber panes.
- Start panes with a private `ZDOTDIR` rc (clean PATH, prompt, env) so no setup line appears on screen.
- Commands that write config (`setup`) run in a throwaway project (`~/warden-demo-fixtures`). Back up `~/.warden/hooks/scanner.py` first.
- The user's global IDE hooks may post to port 3000 while you record. Keep the camera off that pane in the edit, or record on another port.

### Kiro CLI with Warden protection

`~/warden-demo-fixtures/.kiro/agents/warden-demo.json` defines an agent whose `preToolUse` hook runs `scripts/warden-prefetch.py`. Kiro CLI sends `tool_name: "read"` with `tool_input.operations[].path`. The hook handles that shape (fixed in this branch), so a poisoned file is blocked before the model reads it:

```bash
kiro-cli chat --agent warden-demo --trust-tools=fs_read --no-interactive "Summarize vendor-notes.md"
```

## Dashboard takes (Playwright, no screen takeover)

```bash
DB_PATH=$PWD/build/db/demo.db WARDEN_NO_LAYA_INSTALL=1 bun ../src/cli.ts --api-only --port 3777 &   # demo copy of the DB, from the repo root
node scripts/record_dashboard.mjs http://localhost:3777 build/footage/dashboard.mp4
node scripts/record_review.mjs   http://localhost:3777 build/footage/review.mp4
```
- Uses the CDP screencast (JPEG q92) rather than `recordVideo` (≈1 Mbps, blurry text), and rebuilds constant 30 fps from frame timestamps.
- Injects a visible cursor with click ripples and eases every mouse move and scroll.
- Fires real `/scan` requests during the take so the live feed animates with genuine verdicts.
- Record against a **copy** of `~/.warden/warden.db`; demo traffic and review decisions must not pollute the user's data.
- The "Detection rate" tile reads the newest `eval/results/*.json` alphabetically, and `benchmark-public.json` sorts last and has no summary. Move it aside during the take and restore it afterwards (tracked file).

## Conform to the narration

`python tools/cut_demo.py` retimes each terminal beat (speed 0.9–2.6×, holds instead of slow motion) so its action lands under its narration line. It picks dashboard sub-clips, punches the dashboard in to its content column (`crop=1280:720:320:0`), and writes `build/footage/demo_base.mp4` (2880×1620) plus the edit list `cuts.json`.
