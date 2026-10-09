/**
 * Red team defender agent — analyzes bypasses and strengthens Warden's defenses.
 *
 * For each bypass the attacker produces, the defender:
 *  - Generates regex rule suggestions via LLM analysis
 *  - Seeds the bypass text into similarity memory so the same attack is caught next time
 *  - Creates training examples for future Laya fine-tuning
 *
 * Uses the existing getProvider/BudgetedClient/parseJsonArray pattern from
 * redteam/provider.ts and addReference from src/detect/similarity.ts.
 */

import { getProvider, BudgetedClient, parseJsonArray } from "./provider.ts";
import type { AttackType } from "../src/types.ts";
import { addReference } from "../src/detect/similarity.ts";
import type { BypassRecord } from "./attacker.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RuleSuggestion {
  round: number;
  timestamp: number;
  bypassContent: string;
  pattern: string;
  attackType: string;
  confidence: number;
  reason: string;
}

export interface TrainingExample {
  round: number;
  timestamp: number;
  text: string;
  label: "INJECT";
  attackType: string;
  source: string;
}

export interface DefenderRoundStats {
  bypasses: number;
  memoriesSeeded: number;
  rulesSuggested: number;
  trainingExamplesGenerated: number;
}

// ---------------------------------------------------------------------------
// Valid attack types for validation
// ---------------------------------------------------------------------------

const VALID_ATTACK_TYPES: Set<string> = new Set([
  "instruction_override", "role_change", "secret_extraction", "tool_abuse",
  "credential_theft", "context_poisoning", "multi_step_jailbreak",
  "encoded_instructions", "indirect_injection",
]);

// ---------------------------------------------------------------------------
// LLM prompts
// ---------------------------------------------------------------------------

const DEFENDER_SYSTEM_PROMPT = `You are a security analyst defending Warden, a prompt-injection firewall. You analyze attacks that bypassed detection and generate regex rule fixes.

Warden's detection stages:
1. Rules — JavaScript regex patterns (case-insensitive). Each rule has: pattern, attackType, confidence (0-1), reason.
2. Similarity — kNN cosine search against known attack embeddings (threshold 0.70).
3. Laya — fine-tuned DistilBERT injection classifier.
4. Judge — LLM adjudicator for uncertain cases.

When analyzing a bypass:
- Identify which stage SHOULD have caught it and why it didn't
- Focus on what makes this attack DIFFERENT from patterns the rules already cover
- Generate regex patterns that catch this attack and plausible variants without matching benign business text
- Keep patterns specific enough to avoid false positives — Warden's false-positive rate is currently zero and must stay there
- Use JavaScript regex syntax with case-insensitive flag where appropriate`;

// ---------------------------------------------------------------------------
// Pure functions
// ---------------------------------------------------------------------------

/**
 * Assembles a RuleSuggestion record from a bypass and LLM analysis output.
 */
export function formatRuleSuggestion(
  bypass: BypassRecord,
  pattern: string,
  attackType: string,
  confidence: number,
  reason: string,
): RuleSuggestion {
  return {
    round: bypass.round,
    timestamp: Date.now(),
    bypassContent: bypass.content,
    pattern,
    attackType,
    confidence,
    reason,
  };
}

/**
 * Assembles a TrainingExample from a bypass. Label is always 'INJECT' since
 * bypasses are confirmed malicious content that the pipeline missed.
 */
export function formatTrainingExample(bypass: BypassRecord): TrainingExample {
  return {
    round: bypass.round,
    timestamp: Date.now(),
    text: bypass.content,
    label: "INJECT",
    attackType: bypass.generationContext.targetWeakness,
    source: "selfplay_defender",
  };
}

// ---------------------------------------------------------------------------
// Impure functions (network / LLM / file I/O)
// ---------------------------------------------------------------------------

/**
 * Analyzes a bypass using an LLM and returns regex rule suggestions.
 */
export async function analyzeBypass(
  client: BudgetedClient,
  bypass: BypassRecord,
): Promise<{ rules: Array<{ pattern: string; attackType: string; confidence: number; reason: string }> }> {
  const userPrompt = `This attack bypassed Warden's detection:

Content: ${bypass.content}

Scan result: action=${bypass.scanResult.action}, riskScore=${bypass.scanResult.riskScore}
Findings: ${JSON.stringify(bypass.scanResult.findings)}
Trace: ${JSON.stringify(bypass.scanResult.trace)}
Target weakness: ${bypass.generationContext.targetWeakness}
Evasion strategy: ${bypass.generationContext.strategy}

Generate regex rule suggestions as a JSON array. Each element:
{"pattern": "/regex/flags", "attackType": "one of the 9 types", "confidence": 0.0-1.0, "reason": "why this catches the bypass without false positives"}`;

  const raw = await client.complete(DEFENDER_SYSTEM_PROMPT, userPrompt);
  const rules = parseJsonArray<{ pattern: string; attackType: string; confidence: number; reason: string }>(raw);
  return { rules };
}

/**
 * Seeds a bypass into Warden's similarity memory so the same attack pattern
 * is caught by kNN search next time.
 */
export async function seedMemory(bypass: BypassRecord): Promise<boolean> {
  const attackType = VALID_ATTACK_TYPES.has(bypass.generationContext.targetWeakness)
    ? (bypass.generationContext.targetWeakness as AttackType)
    : ("instruction_override" as AttackType);

  return addReference(bypass.content, attackType, bypass.source, {
    origin: "seed",
    agentId: "default",
  });
}

/**
 * Appends a rule suggestion as a JSON line to the rule suggestions log.
 */
export async function appendRuleSuggestion(suggestion: RuleSuggestion): Promise<void> {
  const path = new URL("./logs/rule_suggestions.jsonl", import.meta.url).pathname;
  const line = JSON.stringify(suggestion) + "\n";
  const file = Bun.file(path);
  const existing = (await file.exists()) ? await file.text() : "";
  await Bun.write(path, existing + line);
}

/**
 * Appends a training example as a JSON line to the training examples log.
 */
export async function appendTrainingExample(example: TrainingExample): Promise<void> {
  const path = new URL("./logs/training_examples.jsonl", import.meta.url).pathname;
  const line = JSON.stringify(example) + "\n";
  const file = Bun.file(path);
  const existing = (await file.exists()) ? await file.text() : "";
  await Bun.write(path, existing + line);
}

/**
 * Reads all bypass records from the JSONL log. Returns [] if the file doesn't exist.
 */
export async function readBypasses(path?: string): Promise<BypassRecord[]> {
  const filePath = path ?? new URL("./logs/bypasses.jsonl", import.meta.url).pathname;
  const file = Bun.file(filePath);
  if (!(await file.exists())) return [];

  const text = await file.text();
  const records: BypassRecord[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      records.push(JSON.parse(trimmed) as BypassRecord);
    } catch {
      // Skip malformed lines
    }
  }
  return records;
}

/**
 * Orchestrates one defender round: analyze bypasses, seed memory, generate
 * rule suggestions and training examples.
 */
export async function runDefenderRound(
  bypasses: BypassRecord[],
  round: number,
): Promise<DefenderRoundStats> {
  const stats: DefenderRoundStats = {
    bypasses: bypasses.length,
    memoriesSeeded: 0,
    rulesSuggested: 0,
    trainingExamplesGenerated: 0,
  };

  if (bypasses.length === 0) {
    console.log("[defender] No bypasses to process");
    return stats;
  }

  const provider = getProvider();
  if (!provider) {
    console.error("[defender] No LLM provider configured (set ANTHROPIC_API_KEY or OPENAI_API_KEY)");
    return stats;
  }

  const client = new BudgetedClient(provider, bypasses.length * 2);

  console.log(`[defender] Processing ${bypasses.length} bypasses...`);

  for (const bypass of bypasses) {
    // Analyze bypass and get rule suggestions
    const { rules } = await analyzeBypass(client, bypass);
    for (const rule of rules) {
      const suggestion = formatRuleSuggestion(
        bypass,
        rule.pattern,
        rule.attackType,
        rule.confidence,
        rule.reason,
      );
      await appendRuleSuggestion(suggestion);
      stats.rulesSuggested++;
    }

    // Seed the bypass text into similarity memory
    const seeded = await seedMemory(bypass);
    if (seeded) {
      stats.memoriesSeeded++;
      console.log(`  [defender] Seeded memory: ${bypass.generationContext.targetWeakness}`);
    }

    // Create and log a training example
    const example = formatTrainingExample(bypass);
    await appendTrainingExample(example);
    stats.trainingExamplesGenerated++;
  }

  console.log(
    `[defender] Round ${round} complete: ${stats.memoriesSeeded} memories seeded, ` +
    `${stats.rulesSuggested} rules suggested, ${stats.trainingExamplesGenerated} training examples`,
  );

  return stats;
}
