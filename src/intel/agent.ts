/**
 * Threat intelligence agent — orchestrates the fetch → process → seed cycle.
 *
 * Runs as a one-shot script or in watch mode on a configurable interval.
 * Fetches new prompt-injection examples from public HuggingFace datasets and
 * GitHub repos, checks each against the live Warden API, and seeds misses
 * into the similarity memory so they are caught next time.
 *
 * Usage:
 *   bun src/intel/agent.ts              # one-shot cycle
 *   bun src/intel/agent.ts --watch      # periodic cycles
 *   bun src/intel/agent.ts --interval 4 # custom interval (hours)
 *
 * Configure via env:
 *   INTEL_SOURCES       — comma-separated source names to enable (default: all)
 *   INTEL_INTERVAL_HOURS — cycle interval in hours (default: 6)
 *   WARDEN_API_URL      — API base URL (default: http://localhost:3000)
 */

import { getEnabledSources } from "./sources.ts";
import { fetchSource } from "./fetcher.ts";
import { processItems, printStats } from "./processor.ts";
import type { IntelItem } from "./sources.ts";

const DEFAULT_INTERVAL_HOURS = 6;

/**
 * Runs a single intel cycle: fetch from all enabled sources, then process
 * and seed the collected items.
 */
export async function runIntelCycle(): Promise<void> {
  const enabledIds = process.env.INTEL_SOURCES
    ? process.env.INTEL_SOURCES.split(",").map((s) => s.trim()).filter(Boolean)
    : undefined;

  const sources = getEnabledSources(enabledIds);
  console.log(`[intel] Starting cycle with ${sources.length} source(s)`);

  const allItems: IntelItem[] = [];

  for (const source of sources) {
    try {
      console.log(`[intel] Fetching: ${source.name}`);
      const items = await fetchSource(source);
      console.log(`[intel]   → ${items.length} new item(s)`);
      allItems.push(...items);
    } catch (e) {
      console.error(`[intel] Error fetching ${source.name}: ${e instanceof Error ? e.message : e}`);
    }
  }

  console.log(`[intel] Total items to process: ${allItems.length}`);
  const stats = await processItems(allItems);
  printStats(stats);
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

if (import.meta.main) {
  const argv = process.argv.slice(2);

  let watch = false;
  let intervalHours = parseInt(process.env.INTEL_INTERVAL_HOURS ?? "", 10) || DEFAULT_INTERVAL_HOURS;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--watch") {
      watch = true;
    } else if (arg === "--interval" && argv[i + 1]) {
      intervalHours = parseFloat(argv[++i]);
      if (isNaN(intervalHours) || intervalHours <= 0) {
        intervalHours = DEFAULT_INTERVAL_HOURS;
      }
    }
  }

  if (watch) {
    const intervalMs = intervalHours * 3_600_000;
    console.log(`[intel] Watch mode — interval: ${intervalHours}h (${intervalMs}ms)`);

    // Run immediately then on interval
    runIntelCycle().catch((e) => console.error("[intel] Cycle error:", e));

    const timer = setInterval(() => {
      runIntelCycle().catch((e) => console.error("[intel] Cycle error:", e));
    }, intervalMs);

    // Graceful shutdown
    process.on("SIGINT", () => {
      console.log("\n[intel] Shutting down.");
      clearInterval(timer);
      process.exit(0);
    });
  } else {
    // One-shot
    runIntelCycle()
      .then(() => process.exit(0))
      .catch((e) => {
        console.error("[intel] Fatal:", e);
        process.exit(1);
      });
  }
}
