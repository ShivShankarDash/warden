import { getDb } from "./db.ts";

/**
 * Source reputation.
 *
 * `source` is a *type* (email, html, mcp_tool_description); `sourceId` is an
 * *identity* — a sender address, a domain, an MCP server name. An identity that has
 * sent attacks before deserves more scrutiny than one that has not, which is a cheap
 * signal with a large effect on the cases that matter.
 *
 * Two deliberate limits:
 *
 *  - The adjustment is **bounded and symmetric-ish but asymmetric in trust**: a bad
 *    history tightens more than a clean history relaxes. Being wrong about a bad
 *    sender costs a false positive; being wrong about a good one costs a breach.
 *  - Reputation **cannot by itself cause a block**. It nudges the score of content
 *    that already looks borderline. Otherwise an attacker who poisons one identity's
 *    record could get unrelated content blocked, and a long-clean identity could be
 *    used to smuggle anything.
 */

export interface Reputation {
  sourceId: string;
  attacks: number;
  clean: number;
  total: number;
  lastAttackAt: number | null;
}

/** Observations needed before reputation influences anything. Below this the sample
 *  is too small to distinguish a bad sender from an unlucky one. */
const MIN_OBSERVATIONS = Number(process.env.REPUTATION_MIN_OBSERVATIONS ?? 3);

/** Most reputation may tighten a score. */
const MAX_PENALTY = Number(process.env.REPUTATION_MAX_PENALTY ?? 0.25);

/** Most reputation may relax a score — deliberately smaller than the penalty. */
const MAX_BONUS = Number(process.env.REPUTATION_MAX_BONUS ?? 0.1);

export function recordObservation(
  sourceId: string,
  wasAttack: boolean,
  agentId = "default"
): void {
  if (!sourceId) return;
  const now = Date.now();
  getDb()
    .prepare(
      `INSERT INTO source_reputation (source_id, agent_id, attacks, clean, last_attack_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(source_id, agent_id) DO UPDATE SET
         attacks = attacks + ?,
         clean = clean + ?,
         last_attack_at = CASE WHEN ? = 1 THEN ? ELSE last_attack_at END,
         updated_at = ?`
    )
    .run(
      sourceId, agentId, wasAttack ? 1 : 0, wasAttack ? 0 : 1, wasAttack ? now : null, now,
      wasAttack ? 1 : 0, wasAttack ? 0 : 1, wasAttack ? 1 : 0, now, now
    );
}

export function getReputation(sourceId: string, agentId = "default"): Reputation | null {
  if (!sourceId) return null;
  const row = getDb()
    .query(
      "SELECT source_id, attacks, clean, last_attack_at FROM source_reputation WHERE source_id = ? AND agent_id = ?"
    )
    .get(sourceId, agentId) as
    | { source_id: string; attacks: number; clean: number; last_attack_at: number | null }
    | null;
  if (!row) return null;
  return {
    sourceId: row.source_id,
    attacks: row.attacks,
    clean: row.clean,
    total: row.attacks + row.clean,
    lastAttackAt: row.last_attack_at,
  };
}

export interface ReputationAdjustment {
  /** Added to the risk score. Positive tightens, negative relaxes, zero means no opinion. */
  delta: number;
  reason: string | null;
}

/**
 * How much this identity's history should move a score.
 *
 * Returns zero for unknown or thinly-observed identities rather than guessing, so a
 * first-time sender is treated on the content alone.
 */
export function reputationAdjustment(
  sourceId: string | undefined | null,
  agentId = "default"
): ReputationAdjustment {
  if (!sourceId) return { delta: 0, reason: null };

  const rep = getReputation(sourceId, agentId);
  if (!rep || rep.total < MIN_OBSERVATIONS) return { delta: 0, reason: null };

  const attackRate = rep.attacks / rep.total;

  if (rep.attacks > 0) {
    const delta = MAX_PENALTY * attackRate;
    return {
      delta,
      reason: `${sourceId} has sent ${rep.attacks} attack(s) in ${rep.total} observations (+${delta.toFixed(2)})`,
    };
  }

  // Clean history. Scaled by how much evidence there is, capped low — a long clean
  // record is weak evidence that the next message is safe, since compromise is
  // exactly what turns a good sender bad.
  const confidence = Math.min(1, rep.total / 20);
  const delta = -MAX_BONUS * confidence;
  return {
    delta,
    reason: `${sourceId} has ${rep.clean} clean observations and no attacks (${delta.toFixed(2)})`,
  };
}

export function topOffenders(agentId = "default", limit = 20) {
  return getDb()
    .query(
      `SELECT source_id, attacks, clean, last_attack_at FROM source_reputation
       WHERE agent_id = ? AND attacks > 0
       ORDER BY attacks DESC LIMIT ?`
    )
    .all(agentId, limit) as {
    source_id: string; attacks: number; clean: number; last_attack_at: number | null;
  }[];
}
