/**
 * Self-play orchestrator — runs adversarial rounds where the attacker agent
 * generates novel prompt injections and the defender agent strengthens Warden's
 * defenses by seeding memory, suggesting rules, and creating training examples.
 *
 * Usage:
 *   bun redteam/selfplay.ts [--rounds N] [--attacks N] [--budget N]
 */

import { runAttackerRound } from "./attacker.ts";
import type { AttackerRoundStats, BypassRecord } from "./attacker.ts";
import { runDefenderRound } from "./defender.ts";
import type { DefenderRoundStats } from "./defender.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SelfPlayConfig {
  wardenUrl: string;
  rounds: number;
  attacksPerRound: number;
  llmBudget: number;
}

export interface RoundReport {
  round: number;
  attacker: AttackerRoundStats;
  defender: DefenderRoundStats;
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

/**
 * Runs the full self-play loop: for each round the attacker generates attacks,
 * scans them against Warden, and any bypasses are handed to the defender for
 * analysis, memory seeding, and training example generation.
 */
export async function runSelfPlay(config: SelfPlayConfig): Promise<RoundReport[]> {
  // 1. Reachability check
  try {
    await fetch(`${config.wardenUrl}/metrics`, {
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    console.error(
      `ERROR: Warden server not reachable at ${config.wardenUrl}. Start it with: bun run dev`,
    );
    process.exit(1);
  }

  // 2. Banner
  console.log(
    `[selfplay] Starting adversarial self-play: ${config.rounds} rounds × ${config.attacksPerRound} attacks per round`,
  );

  const reports: RoundReport[] = [];
  const allBypasses: BypassRecord[] = [];
  let totalBypasses = 0;
  let totalMemories = 0;

  // 3. Round loop
  for (let n = 1; n <= config.rounds; n++) {
    console.log(`[selfplay] === Round ${n}/${config.rounds} ===`);

    // Collect prior bypass content strings for attacker adaptation
    const priorBypassContents = allBypasses.map((b) => b.content);

    // Run attacker round
    const { stats: attackerStats, bypasses } = await runAttackerRound(
      {
        wardenUrl: config.wardenUrl,
        attacksPerRound: config.attacksPerRound,
        llmBudget: config.llmBudget,
      },
      n,
      priorBypassContents,
    );

    // Track all bypasses across rounds
    allBypasses.push(...bypasses);

    // Run defender round if there were bypasses
    let defenderStats: DefenderRoundStats = {
      bypasses: 0,
      memoriesSeeded: 0,
      rulesSuggested: 0,
      trainingExamplesGenerated: 0,
    };

    if (bypasses.length > 0) {
      defenderStats = await runDefenderRound(bypasses, n);
    }

    totalBypasses += attackerStats.bypasses;
    totalMemories += defenderStats.memoriesSeeded;

    // Print per-round stats
    console.log(`  Attacks generated: ${attackerStats.generated}`);
    console.log(`  Attacks scanned:   ${attackerStats.scanned}`);
    console.log(`  Bypasses found:    ${attackerStats.bypasses}`);
    console.log(`  Memories seeded:   ${defenderStats.memoriesSeeded}`);
    console.log(`  Rules suggested:   ${defenderStats.rulesSuggested}`);
    console.log(`  Training examples: ${defenderStats.trainingExamplesGenerated}`);

    reports.push({ round: n, attacker: attackerStats, defender: defenderStats });
  }

  // 4. Final summary
  console.log(
    `[selfplay] Complete. ${config.rounds} rounds, ${totalBypasses} total bypasses, ${totalMemories} memories seeded.`,
  );

  return reports;
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

function parseArgs(argv: string[]): Partial<SelfPlayConfig> {
  const opts: Partial<SelfPlayConfig> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--rounds" && argv[i + 1]) {
      opts.rounds = parseInt(argv[++i], 10);
    } else if (arg === "--attacks" && argv[i + 1]) {
      opts.attacksPerRound = parseInt(argv[++i], 10);
    } else if (arg === "--budget" && argv[i + 1]) {
      opts.llmBudget = parseInt(argv[++i], 10);
    }
  }
  return opts;
}

if (import.meta.main) {
  const parsed = parseArgs(process.argv.slice(2));

  const config: SelfPlayConfig = {
    wardenUrl:
      process.env.WARDEN_URL ?? process.env.WARDEN_API_URL ?? "http://localhost:3000",
    rounds: parsed.rounds ?? Number(process.env.SELFPLAY_ROUNDS ?? 5),
    attacksPerRound: parsed.attacksPerRound ?? Number(process.env.SELFPLAY_ATTACKS ?? 20),
    llmBudget: parsed.llmBudget ?? Number(process.env.SELFPLAY_LLM_BUDGET ?? 50),
  };

  runSelfPlay(config).catch((e) => {
    console.error("[selfplay] Fatal:", e);
    process.exit(1);
  });
}
