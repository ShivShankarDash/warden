/**
 * Red team runner — exercises Warden's detection pipeline with mutated attacks.
 *
 * Loads seed attacks from eval/cases/*.json, applies deterministic mutations from
 * mutations.ts, and sends each mutated variant to POST /scan. Bypasses (mutations
 * that get ALLOWed despite being malicious) trigger a re-scan of the original seed
 * to engage the learning loop, strengthening future detection.
 *
 * Requires `bun run dev` (the Warden API server) running on port 3000 (or the
 * URL in WARDEN_API_URL).
 *
 * Usage:
 *   bun redteam/runner.ts [--limit N] [--mutations name1,name2] [--dry-run]
 */

import { Glob } from "bun";
import { mutationOrder, type Mutation, type MutationResult } from "./mutations.ts";
import type { SourceType, Action } from "../src/types.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EvalCase {
  id: string;
  source: SourceType;
  content: string;
  label: string;
  expected_attacks?: string[];
  expected_action?: string;
  notes?: string;
}

export interface RunStats {
  totalSeeds: number;
  totalMutations: number;
  bypasses: number;
  memoriesLearned: number;
  errors: number;
  byMutation: Record<string, { tried: number; bypassed: number }>;
}

export interface RunRedTeamOpts {
  /** Max seed payloads to process. Default: all. */
  limit?: number;
  /** Filter to specific mutation names. Default: all. */
  mutations?: string[];
  /** Only print what would happen, skip network calls. */
  dryRun?: boolean;
  /** Focus on seeds matching these attack types first (from coverageGaps). */
  weakTypes?: string[];
  /** API base URL. Default: WARDEN_API_URL env or http://localhost:3000. */
  apiUrl?: string;
}

// ---------------------------------------------------------------------------
// Seed loading
// ---------------------------------------------------------------------------

/**
 * Loads all malicious eval cases from eval/cases/*.json.
 * Returns an array of EvalCase objects with label === 'malicious'.
 */
export async function loadSeedAttacks(): Promise<EvalCase[]> {
  const casesDir = new URL("../eval/cases/", import.meta.url).pathname;
  const glob = new Glob("*.json");
  const seeds: EvalCase[] = [];

  for await (const path of glob.scan(casesDir)) {
    const full = `${casesDir}${path}`;
    const raw = await Bun.file(full).text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      console.warn(`  [redteam] skipping unparseable file: ${path}`);
      continue;
    }
    if (!Array.isArray(parsed)) continue;
    for (const c of parsed) {
      if (c && typeof c === "object" && c.label === "malicious" && typeof c.content === "string") {
        seeds.push(c as EvalCase);
      }
    }
  }

  return seeds;
}

// ---------------------------------------------------------------------------
// Mutation application (pure, testable)
// ---------------------------------------------------------------------------

export interface AppliedMutation {
  seed: EvalCase;
  mutation: string;
  content: string;
  source: SourceType;
}

/**
 * Applies mutations to a seed payload. Pure function — no network calls.
 * Returns an array of successfully-applied mutation results.
 */
export function applyMutations(
  seed: EvalCase,
  mutations: Mutation[],
): AppliedMutation[] {
  const results: AppliedMutation[] = [];
  for (const m of mutations) {
    const result = m.apply(seed.content, seed.source);
    if (result) {
      results.push({
        seed,
        mutation: m.name,
        content: result.content,
        source: (result.source as SourceType) ?? seed.source,
      });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Stats tracking (pure, testable)
// ---------------------------------------------------------------------------

/** Creates a fresh stats object. */
export function createStats(): RunStats {
  return {
    totalSeeds: 0,
    totalMutations: 0,
    bypasses: 0,
    memoriesLearned: 0,
    errors: 0,
    byMutation: {},
  };
}

/** Records a mutation attempt in the stats. */
export function recordAttempt(
  stats: RunStats,
  mutationName: string,
  bypassed: boolean,
): void {
  stats.totalMutations++;
  if (bypassed) stats.bypasses++;
  if (!stats.byMutation[mutationName]) {
    stats.byMutation[mutationName] = { tried: 0, bypassed: 0 };
  }
  stats.byMutation[mutationName].tried++;
  if (bypassed) stats.byMutation[mutationName].bypassed++;
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

async function scanPayload(
  apiUrl: string,
  content: string,
  source: SourceType,
): Promise<{ action: Action } | null> {
  try {
    const res = await fetch(`${apiUrl}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, source, agentId: "redteam" }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) {
      console.error(`  [redteam] scan failed: ${res.status} ${res.statusText}`);
      return null;
    }
    return (await res.json()) as { action: Action };
  } catch (e) {
    console.error(`  [redteam] scan error: ${e instanceof Error ? e.message : e}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/**
 * Runs a red team cycle. Loads seeds, applies mutations, probes the API,
 * and re-scans originals on bypass to trigger learning.
 */
export async function runRedTeam(opts?: RunRedTeamOpts): Promise<RunStats> {
  const apiUrl = opts?.apiUrl ?? process.env.WARDEN_API_URL ?? "http://localhost:3000";
  const dryRun = opts?.dryRun ?? false;
  const limit = opts?.limit;
  const mutationFilter = opts?.mutations;
  const weakTypes = opts?.weakTypes;

  const stats = createStats();

  // Load seeds
  let seeds = await loadSeedAttacks();

  // Prioritise seeds matching weak attack types
  if (weakTypes && weakTypes.length > 0) {
    const weakSet = new Set(weakTypes.map((t) => t.toLowerCase()));
    seeds.sort((a, b) => {
      const aWeak = a.expected_attacks?.some((t) => weakSet.has(t.toLowerCase())) ? 0 : 1;
      const bWeak = b.expected_attacks?.some((t) => weakSet.has(t.toLowerCase())) ? 0 : 1;
      return aWeak - bWeak;
    });
  }

  if (limit && limit > 0) seeds = seeds.slice(0, limit);
  stats.totalSeeds = seeds.length;

  // Select mutations
  let mutations = mutationOrder();
  if (mutationFilter && mutationFilter.length > 0) {
    const filterSet = new Set(mutationFilter.map((n) => n.toLowerCase()));
    mutations = mutations.filter((m) => filterSet.has(m.name.toLowerCase()));
  }

  console.log(`[redteam] Starting run: ${seeds.length} seeds × ${mutations.length} mutations${dryRun ? " (dry run)" : ""}`);

  for (const seed of seeds) {
    const applied = applyMutations(seed, mutations);

    for (const variant of applied) {
      if (dryRun) {
        recordAttempt(stats, variant.mutation, false);
        continue;
      }

      const result = await scanPayload(apiUrl, variant.content, variant.source);
      if (!result) {
        stats.errors++;
        recordAttempt(stats, variant.mutation, false);
        continue;
      }

      const bypassed = result.action === "ALLOW";
      recordAttempt(stats, variant.mutation, bypassed);

      if (bypassed) {
        console.log(`  [bypass] seed=${seed.id} mutation=${variant.mutation}`);

        // Re-scan original to trigger learning loop
        const learnResult = await scanPayload(apiUrl, seed.content, seed.source);
        if (learnResult) {
          stats.memoriesLearned++;
        }
      }
    }
  }

  // Print summary
  console.log(`\n[redteam] Run complete:`);
  console.log(`  Seeds:     ${stats.totalSeeds}`);
  console.log(`  Mutations: ${stats.totalMutations}`);
  console.log(`  Bypasses:  ${stats.bypasses}`);
  console.log(`  Learned:   ${stats.memoriesLearned}`);
  console.log(`  Errors:    ${stats.errors}`);

  if (Object.keys(stats.byMutation).length > 0) {
    console.log(`  By mutation:`);
    for (const [name, m] of Object.entries(stats.byMutation)) {
      console.log(`    ${name}: ${m.tried} tried, ${m.bypassed} bypassed`);
    }
  }

  return stats;
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

function parseArgs(argv: string[]): RunRedTeamOpts {
  const opts: RunRedTeamOpts = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--limit" && argv[i + 1]) {
      opts.limit = parseInt(argv[++i], 10);
    } else if (arg === "--mutations" && argv[i + 1]) {
      opts.mutations = argv[++i].split(",");
    } else if (arg === "--dry-run") {
      opts.dryRun = true;
    }
  }
  return opts;
}

if (import.meta.main) {
  const opts = parseArgs(process.argv.slice(2));
  runRedTeam(opts).catch((e) => {
    console.error("[redteam] Fatal:", e);
    process.exit(1);
  });
}
