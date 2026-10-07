import type { Finding, AttackType, SourceType } from "../types.ts";
import { embed, cosine, embeddingsAvailable } from "./embeddings.ts";
import { getDb } from "../store/db.ts";
import {
  addMemory,
  confirmMemory,
  activeMemories,
  allMemories,
  type MemoryOrigin,
  type MemoryRecord,
} from "../store/memory.ts";

/**
 * kNN against Warden's memory.
 *
 * This is where the system gets better with use. Every attack the judge confirms is
 * embedded and stored, so the next variant is caught in ~2ms rather than costing
 * another ~1500ms judge call, and the judge referral rate falls as the set fills.
 *
 * Memory holds safe examples too. Those are exculpatory: content resembling a
 * human-confirmed benign example should be *less* suspicious, not more. Over-blocking
 * is what gets a firewall switched off, so suppressing it is as valuable as detection.
 */

/** Cosine above which two texts are treated as the same thing. Measured separation on
 *  reworded attacks vs benign text is wide (attacks 0.76-0.87, benign max 0.39), so
 *  0.70 sits in the gap. Safe to sit lower than instinct suggests because the finding's
 *  confidence *is* the cosine: a 0.70 match lands in the judge's band and gets
 *  adjudicated rather than acted on. */
const MATCH_THRESHOLD = Number(process.env.SIMILARITY_THRESHOLD ?? 0.7);

/** Near-duplicate of an existing memory: confirm that one instead of adding another. */
const DUPLICATE_THRESHOLD = 0.95;

/** Short inputs embed noisily — cosine between two 3-word strings is unstable. */
const MIN_LENGTH = 20;

let cache: MemoryRecord[] | null = null;

function memories(agentId: string): MemoryRecord[] {
  if (!cache) cache = activeMemories({ agentId });
  return cache;
}

export function invalidateReferenceCache(): void {
  cache = null;
}

export function referenceCount(agentId = "default"): number {
  return memories(agentId).filter((m) => m.label === "attack").length;
}

function nearest(vector: Float32Array, pool: MemoryRecord[]) {
  let best: MemoryRecord | null = null;
  let bestScore = 0;
  for (const m of pool) {
    const score = cosine(vector, m.vector);
    if (score > bestScore) {
      bestScore = score;
      best = m;
    }
  }
  return { best, bestScore };
}

/**
 * Records a confirmed attack. New entries start on probation and are invisible to
 * scanning until confirmed, so a single wrong verdict cannot permanently skew results.
 * Seeing the same payload again confirms the existing memory rather than duplicating it.
 */
export async function addReference(
  text: string,
  attackType: AttackType,
  source: SourceType | string,
  opts: { origin?: MemoryOrigin; agentId?: string; sourceId?: string } = {}
): Promise<boolean> {
  if (!embeddingsAvailable() || text.trim().length < MIN_LENGTH) return false;

  const vector = await embed(text);
  if (!vector) return false;

  const agentId = opts.agentId ?? "default";
  // Dedup against *all* memories, not just active ones. Probationary entries are
  // hidden from scanning by design, but they must still be visible here — otherwise
  // re-seeing a payload creates a second probationary row instead of confirming the
  // first, and nothing is ever promoted.
  const pool = allMemories({ agentId }).filter((m) => m.label === "attack");
  const { best, bestScore } = nearest(vector, pool);
  if (best && bestScore >= DUPLICATE_THRESHOLD) {
    confirmMemory(best.id);
    invalidateReferenceCache();
    return false;
  }

  addMemory({
    label: "attack",
    attackType,
    vector,
    text,
    source: String(source),
    sourceId: opts.sourceId ?? null,
    origin: opts.origin ?? "judge",
    agentId,
  });
  invalidateReferenceCache();
  return true;
}

/**
 * Records content confirmed benign. Only human and seed origins are accepted: learning
 * "this is safe" from unreviewed traffic is exactly the poisoning path, because the
 * traffic is what the attacker controls.
 */
export async function addSafeReference(
  text: string,
  source: SourceType | string,
  opts: { origin?: MemoryOrigin; agentId?: string; sourceId?: string } = {}
): Promise<boolean> {
  const origin = opts.origin ?? "human";
  if (origin !== "human" && origin !== "seed") return false;
  if (!embeddingsAvailable() || text.trim().length < MIN_LENGTH) return false;

  const vector = await embed(text);
  if (!vector) return false;

  const agentId = opts.agentId ?? "default";
  // Same reasoning as the attack path: dedup must see probationary entries too.
  const safePool = allMemories({ agentId }).filter((m) => m.label === "safe");
  const { best, bestScore } = nearest(vector, safePool);
  if (best && bestScore >= DUPLICATE_THRESHOLD) {
    confirmMemory(best.id);
    invalidateReferenceCache();
    return false;
  }

  addMemory({
    label: "safe",
    vector,
    text,
    source: String(source),
    sourceId: opts.sourceId ?? null,
    origin,
    agentId,
  });
  invalidateReferenceCache();
  return true;
}

/**
 * Bumps the match_count and last_matched_at timestamp on a memory that was just used
 * in a similarity finding. Called fire-and-forget so it never blocks scanning.
 */
export function incrementMatchCount(memoryId: string): void {
  try {
    getDb()
      .prepare("UPDATE memory SET match_count = match_count + 1, last_matched_at = ? WHERE id = ?")
      .run(Date.now(), memoryId);
  } catch {}
}

export interface SimilarityResult {
  findings: Finding[];
  /** Cosine to the nearest human-confirmed benign example, when one is closer than
   *  any known attack. The orchestrator treats this as exculpatory. */
  safeMatch: number;
  safeText?: string;
}

export async function similarityCheck(
  text: string,
  threshold = MATCH_THRESHOLD,
  agentId = "default"
): Promise<SimilarityResult> {
  if (!embeddingsAvailable() || text.trim().length < MIN_LENGTH) {
    return { findings: [], safeMatch: 0 };
  }

  const pool = memories(agentId);
  if (!pool.length) return { findings: [], safeMatch: 0 };

  const vector = await embed(text);
  if (!vector) return { findings: [], safeMatch: 0 };

  const attacks = nearest(vector, pool.filter((m) => m.label === "attack"));
  const safe = nearest(vector, pool.filter((m) => m.label === "safe"));

  // A closer benign neighbour than any attack means this looks like something a
  // human already cleared. Report it so the caller can weigh it, and suppress the
  // attack finding — otherwise known-good content keeps getting re-flagged.
  const safeWins = safe.bestScore >= threshold && safe.bestScore > attacks.bestScore;
  if (safeWins) {
    return { findings: [], safeMatch: safe.bestScore, safeText: safe.best?.text };
  }

  if (!attacks.best || attacks.bestScore < threshold) {
    return { findings: [], safeMatch: safe.bestScore };
  }

  // Fire-and-forget: track that this memory was useful so lifecycle management can
  // promote frequently-matched entries and retire stale ones.
  void Promise.resolve().then(() => incrementMatchCount(attacks.best!.id)).catch(() => {});

  return {
    safeMatch: safe.bestScore,
    findings: [
      {
        attackType: attacks.best.attackType ?? "instruction_override",
        confidence: Math.min(0.95, attacks.bestScore),
        stage: "similarity",
        spans: [],
        reason: `Matches a known ${attacks.best.attackType} attack (cosine ${attacks.bestScore.toFixed(3)}): "${attacks.best.text.slice(0, 80)}..."`,
      },
    ],
  };
}
