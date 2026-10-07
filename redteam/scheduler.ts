/**
 * Red team scheduler — runs periodic red team cycles targeting weak attack types.
 *
 * On each cycle the scheduler queries coverageGaps() for the attack types the
 * similarity stage is weakest on, passes them to runRedTeam so mutated probes
 * focus on those gaps first, then runs a lifecycle pass to promote/retire
 * memories that the cycle affected.
 *
 * Requires the Warden API server running (`bun run dev`).
 *
 * Usage:
 *   bun redteam/scheduler.ts
 *
 * Configure via env:
 *   REDTEAM_INTERVAL_MS — cycle interval in ms (default: 7200000 = 2 hours)
 *   WARDEN_API_URL      — API base URL (default: http://localhost:3000)
 */

import { coverageGaps } from "../src/store/coverage.ts";
import { runLifecyclePass } from "../src/store/lifecycle.ts";
import { runRedTeam } from "./runner.ts";

const DEFAULT_INTERVAL_MS = 7_200_000; // 2 hours

let cycleCount = 0;
let timer: ReturnType<typeof setInterval> | null = null;

async function runCycle(): Promise<void> {
  cycleCount++;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`[scheduler] Cycle #${cycleCount} starting at ${new Date().toISOString()}`);
  console.log(`${"=".repeat(60)}`);

  // Get weak attack types from coverage data
  const gaps = coverageGaps();
  const weakTypes = gaps.map((g) => g.attackType);

  if (weakTypes.length > 0) {
    console.log(`[scheduler] Weak types (${weakTypes.length}): ${weakTypes.join(", ")}`);
  } else {
    console.log("[scheduler] No coverage data yet — running full sweep");
  }

  // Run red team cycle focused on weak types
  const stats = await runRedTeam({ weakTypes });

  // Run lifecycle pass to promote/retire memories
  const lifecycle = runLifecyclePass();
  console.log(`[scheduler] Lifecycle pass: promoted=${lifecycle.promoted}, retired=${lifecycle.retired}, loadBearing=${lifecycle.loadBearing}`);

  const nextRun = new Date(Date.now() + intervalMs);
  console.log(`[scheduler] Cycle #${cycleCount} complete. Next run at ${nextRun.toISOString()}`);
}

const intervalMs = parseInt(process.env.REDTEAM_INTERVAL_MS ?? "", 10) || DEFAULT_INTERVAL_MS;

function formatMs(ms: number): string {
  const minutes = Math.floor(ms / 60_000);
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

if (import.meta.main) {
  const nextRun = new Date(Date.now() + intervalMs);
  console.log(`[scheduler] Red team scheduler started`);
  console.log(`[scheduler] Interval: ${formatMs(intervalMs)} (${intervalMs}ms)`);
  console.log(`[scheduler] Next run at ${nextRun.toISOString()}`);

  // Run immediately on start, then on interval
  runCycle().catch((e) => console.error("[scheduler] Cycle error:", e));

  timer = setInterval(() => {
    runCycle().catch((e) => console.error("[scheduler] Cycle error:", e));
  }, intervalMs);

  // Graceful shutdown
  process.on("SIGINT", () => {
    console.log(`\n[scheduler] Shutting down after ${cycleCount} cycle(s).`);
    if (timer) clearInterval(timer);
    process.exit(0);
  });
}
