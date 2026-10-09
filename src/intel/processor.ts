/**
 * Threat intelligence processor — evaluates fetched items against Warden and
 * seeds missed attacks into memory.
 *
 * For each attack item, the processor scans it via the live API to see if
 * Warden already catches it. Misses are seeded via addReference() so the
 * similarity stage picks them up next time. Benign items from trusted
 * sources are seeded via addSafeReference() to suppress false positives.
 */

import { addReference, addSafeReference } from "../detect/similarity.ts";
import type { AttackType } from "../types.ts";
import type { IntelItem } from "./sources.ts";

const WARDEN_API_URL = process.env.WARDEN_API_URL ?? "http://localhost:3000";
const SCAN_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ProcessStats {
  fetched: number;
  alreadyKnown: number;
  seeded: number;
  seedFailed: number;
  safe: number;
  errors: number;
}

// ---------------------------------------------------------------------------
// API scanner
// ---------------------------------------------------------------------------

/**
 * Scans text through the live Warden API to check whether it is already detected.
 */
export async function scanViaApi(
  text: string
): Promise<{ action: string; riskScore: number }> {
  try {
    const res = await fetch(`${WARDEN_API_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: text, source: "user_message", agentId: "intel" }),
      signal: AbortSignal.timeout(SCAN_TIMEOUT_MS),
    });
    if (!res.ok) {
      console.error(`[intel] scan API error: ${res.status} ${res.statusText}`);
      return { action: "ERROR", riskScore: 0 };
    }
    return (await res.json()) as { action: string; riskScore: number };
  } catch (e) {
    console.error(`[intel] scan API error: ${e instanceof Error ? e.message : e}`);
    return { action: "ERROR", riskScore: 0 };
  }
}

// ---------------------------------------------------------------------------
// Processor
// ---------------------------------------------------------------------------

/** Actions that indicate Warden already detects this content. */
const CAUGHT_ACTIONS = new Set(["BLOCK", "QUARANTINE", "HUMAN_REVIEW"]);

/**
 * Processes fetched intel items: scans attacks to check coverage, seeds misses
 * via addReference, and seeds benign examples via addSafeReference.
 */
export async function processItems(items: IntelItem[]): Promise<ProcessStats> {
  const stats: ProcessStats = {
    fetched: items.length,
    alreadyKnown: 0,
    seeded: 0,
    seedFailed: 0,
    safe: 0,
    errors: 0,
  };

  for (const item of items) {
    try {
      // Skip items explicitly marked as not seedable (e.g. commit messages,
      // release notes that aren't representative prompts).
      if (item.seedable === false) continue;

      if (item.isAttack) {
        // Check if Warden already catches this
        const result = await scanViaApi(item.text);

        if (result.action === "ERROR") {
          stats.errors++;
          continue;
        }

        if (CAUGHT_ACTIONS.has(result.action)) {
          stats.alreadyKnown++;
          continue;
        }

        // Missed — seed into memory
        const attackType = (item.attackType ?? "instruction_override") as AttackType;
        const added = await addReference(item.text, attackType, item.source, {
          origin: "seed",
        });
        if (added) {
          stats.seeded++;
        } else {
          stats.seedFailed++;
        }
      } else {
        // Benign item from trusted source — seed as safe example
        const added = await addSafeReference(item.text, item.source, {
          origin: "seed",
        });
        if (added) {
          stats.safe++;
        }
      }
    } catch (e) {
      stats.errors++;
      console.error(`[intel] processItem error: ${e instanceof Error ? e.message : e}`);
    }
  }

  return stats;
}

/**
 * Prints a formatted summary of processing stats.
 */
export function printStats(stats: ProcessStats): void {
  console.log(`\n[intel] Processing complete:`);
  console.log(`  Fetched:       ${stats.fetched}`);
  console.log(`  Already known: ${stats.alreadyKnown}`);
  console.log(`  Seeded:        ${stats.seeded}`);
  console.log(`  Seed failed:   ${stats.seedFailed}`);
  console.log(`  Safe added:    ${stats.safe}`);
  console.log(`  Errors:        ${stats.errors}`);
}
