import { getDb } from "./db.ts";

/**
 * Coverage tracking — per-attack-type detection statistics.
 *
 * Records how often each attack type is scanned, detected, or missed so that
 * downstream consumers (the red team scheduler in FEAT-004, the dashboard) can
 * identify the types the similarity stage is weakest on and focus effort there.
 */

export interface CoverageRow {
  attackType: string;
  agentId: string;
  scans: number;
  detected: number;
  missed: number;
  lastMissedAt: number | null;
  updatedAt: number;
}

export interface CoverageGap {
  attackType: string;
  scans: number;
  detected: number;
  missed: number;
  detectionRate: number;
  memoryCount: number;
  lastMissedAt: number | null;
}

/**
 * Upsert a coverage outcome for a single attack type.
 *
 * `detected` is true when the scan action was BLOCK/QUARANTINE/HUMAN_REVIEW;
 * false when it was ALLOW (a miss). Uses the same INSERT … ON CONFLICT DO UPDATE
 * pattern as `recordObservation` in reputation.ts.
 */
export function recordCoverageOutcome(
  attackType: string,
  detected: boolean,
  agentId = "default",
): void {
  if (!attackType) return;
  const now = Date.now();
  getDb()
    .prepare(
      `INSERT INTO coverage_stats (attack_type, agent_id, scans, detected, missed, last_missed_at, updated_at)
       VALUES (?, ?, 1, ?, ?, ?, ?)
       ON CONFLICT(attack_type, agent_id) DO UPDATE SET
         scans = scans + 1,
         detected = detected + ?,
         missed = missed + ?,
         last_missed_at = CASE WHEN ? = 1 THEN ? ELSE last_missed_at END,
         updated_at = ?`,
    )
    .run(
      attackType,
      agentId,
      detected ? 1 : 0,
      detected ? 0 : 1,
      detected ? null : now,
      now,
      // ON CONFLICT increments
      detected ? 1 : 0,
      detected ? 0 : 1,
      detected ? 0 : 1,
      now,
      now,
    );
}

/**
 * Returns attack types sorted by weakness: lowest detection rate first, then
 * fewest active memories as a tiebreak. Joins against the memory table to include
 * a count of active memories per attack type.
 */
export function coverageGaps(agentId?: string): CoverageGap[] {
  const db = getDb();
  const aid = agentId ?? "default";
  const rows = db
    .query(
      `SELECT
         c.attack_type,
         c.scans,
         c.detected,
         c.missed,
         c.last_missed_at,
         COALESCE(m.cnt, 0) AS memory_count
       FROM coverage_stats c
       LEFT JOIN (
         SELECT attack_type, COUNT(*) AS cnt
         FROM memory
         WHERE status = 'active' AND agent_id = ? AND valid_to IS NULL
         GROUP BY attack_type
       ) m ON m.attack_type = c.attack_type
       WHERE c.agent_id = ?
       ORDER BY
         CASE WHEN c.scans = 0 THEN 1.0 ELSE CAST(c.detected AS REAL) / c.scans END ASC,
         COALESCE(m.cnt, 0) ASC`,
    )
    .all(aid, aid) as {
    attack_type: string;
    scans: number;
    detected: number;
    missed: number;
    last_missed_at: number | null;
    memory_count: number;
  }[];

  return rows.map((r) => ({
    attackType: r.attack_type,
    scans: r.scans,
    detected: r.detected,
    missed: r.missed,
    detectionRate: r.scans > 0 ? r.detected / r.scans : 0,
    memoryCount: r.memory_count,
    lastMissedAt: r.last_missed_at,
  }));
}

/**
 * Returns the full coverage_stats rows as-is for the API.
 */
export function coverageSummary(agentId?: string): CoverageRow[] {
  const db = getDb();
  const aid = agentId ?? "default";
  const rows = db
    .query(
      `SELECT attack_type, agent_id, scans, detected, missed, last_missed_at, updated_at
       FROM coverage_stats
       WHERE agent_id = ?
       ORDER BY attack_type`,
    )
    .all(aid) as {
    attack_type: string;
    agent_id: string;
    scans: number;
    detected: number;
    missed: number;
    last_missed_at: number | null;
    updated_at: number;
  }[];

  return rows.map((r) => ({
    attackType: r.attack_type,
    agentId: r.agent_id,
    scans: r.scans,
    detected: r.detected,
    missed: r.missed,
    lastMissedAt: r.last_missed_at,
    updatedAt: r.updated_at,
  }));
}
