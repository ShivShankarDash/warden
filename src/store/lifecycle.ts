import { getDb } from "./db.ts";

/**
 * Memory lifecycle management.
 *
 * Memories that prove their value (matched frequently) are promoted off probation
 * automatically. Memories that sit unused for a month are retired so the kNN pool
 * stays lean and relevant. Load-bearing entries — ones that match ≥20 times — are
 * protected from retirement because removing them would open real detection gaps.
 */

/** Match count at which a probationary entry auto-promotes to active. */
export const ESCALATION_THRESHOLD = 5;

/** Match count at which an entry is considered load-bearing and shielded from retirement. */
export const LOAD_BEARING_THRESHOLD = 20;

/** Days without a match before an entry is retired. */
export const STALE_DAYS = 30;

const STALE_MS = STALE_DAYS * 86_400_000;

export interface LifecycleStats {
  promoted: number;
  retired: number;
  loadBearing: number;
}

/**
 * Runs escalation and retirement in a single pass.
 *
 * - Promotes probationary entries that have been matched ≥ ESCALATION_THRESHOLD times.
 * - Retires active entries that haven't been matched in STALE_DAYS, unless they are
 *   load-bearing (match_count ≥ LOAD_BEARING_THRESHOLD).
 * - Retires entries that have never been matched and are older than STALE_DAYS.
 */
export function runLifecyclePass(agentId?: string): LifecycleStats {
  const db = getDb();
  const now = Date.now();
  const staleTs = now - STALE_MS;

  // --- Promote ---
  const promoteWhere = agentId
    ? "status = 'probation' AND match_count >= ? AND valid_to IS NULL AND agent_id = ?"
    : "status = 'probation' AND match_count >= ? AND valid_to IS NULL";
  const promoteParams: unknown[] = agentId
    ? [ESCALATION_THRESHOLD, agentId]
    : [ESCALATION_THRESHOLD];

  const toPromote = db
    .query(`SELECT id FROM memory WHERE ${promoteWhere}`)
    .all(...promoteParams) as { id: string }[];

  const promoteStmt = db.prepare(
    "UPDATE memory SET status = 'active', valid_from = ? WHERE id = ?"
  );
  for (const row of toPromote) {
    promoteStmt.run(now, row.id);
  }

  // --- Retire stale (previously matched but not recently) ---
  const retireMatchedWhere = agentId
    ? `status = 'active' AND match_count < ? AND last_matched_at IS NOT NULL
       AND last_matched_at < ? AND valid_to IS NULL AND agent_id = ?`
    : `status = 'active' AND match_count < ? AND last_matched_at IS NOT NULL
       AND last_matched_at < ? AND valid_to IS NULL`;
  const retireMatchedParams: unknown[] = agentId
    ? [LOAD_BEARING_THRESHOLD, staleTs, agentId]
    : [LOAD_BEARING_THRESHOLD, staleTs];

  const toRetireMatched = db
    .query(`SELECT id FROM memory WHERE ${retireMatchedWhere}`)
    .all(...retireMatchedParams) as { id: string }[];

  // --- Retire never-matched and older than STALE_DAYS ---
  const retireNeverWhere = agentId
    ? `last_matched_at IS NULL AND created_at < ? AND status IN ('probation','active')
       AND valid_to IS NULL AND agent_id = ?`
    : `last_matched_at IS NULL AND created_at < ? AND status IN ('probation','active')
       AND valid_to IS NULL`;
  const retireNeverParams: unknown[] = agentId
    ? [staleTs, agentId]
    : [staleTs];

  const toRetireNever = db
    .query(`SELECT id FROM memory WHERE ${retireNeverWhere}`)
    .all(...retireNeverParams) as { id: string }[];

  const retireStmt = db.prepare(
    "UPDATE memory SET status = 'retired', valid_to = ? WHERE id = ?"
  );
  for (const row of [...toRetireMatched, ...toRetireNever]) {
    retireStmt.run(now, row.id);
  }

  // --- Load-bearing count ---
  const lbWhere = agentId
    ? "match_count >= ? AND status = 'active' AND valid_to IS NULL AND agent_id = ?"
    : "match_count >= ? AND status = 'active' AND valid_to IS NULL";
  const lbParams: unknown[] = agentId
    ? [LOAD_BEARING_THRESHOLD, agentId]
    : [LOAD_BEARING_THRESHOLD];

  const { n: loadBearing } = db
    .query(`SELECT COUNT(*) AS n FROM memory WHERE ${lbWhere}`)
    .get(...lbParams) as { n: number };

  return {
    promoted: toPromote.length,
    retired: toRetireMatched.length + toRetireNever.length,
    loadBearing,
  };
}

export interface MemoryHealthStats {
  total: number;
  active: number;
  probation: number;
  retired: number;
  loadBearing: number;
  stale: number;
}

/**
 * Snapshot of memory health: counts by status plus load-bearing and stale indicators.
 */
export function memoryHealth(agentId?: string): MemoryHealthStats {
  const db = getDb();
  const agentFilter = agentId ? " AND agent_id = ?" : "";
  const params: unknown[] = agentId ? [agentId] : [];
  const staleTs = Date.now() - STALE_MS;

  const { n: total } = db
    .query(`SELECT COUNT(*) AS n FROM memory WHERE 1=1${agentFilter}`)
    .get(...params) as { n: number };

  const { n: active } = db
    .query(`SELECT COUNT(*) AS n FROM memory WHERE status = 'active' AND valid_to IS NULL${agentFilter}`)
    .get(...params) as { n: number };

  const { n: probation } = db
    .query(`SELECT COUNT(*) AS n FROM memory WHERE status = 'probation' AND valid_to IS NULL${agentFilter}`)
    .get(...params) as { n: number };

  const { n: retired } = db
    .query(`SELECT COUNT(*) AS n FROM memory WHERE status = 'retired'${agentFilter}`)
    .get(...params) as { n: number };

  const { n: loadBearing } = db
    .query(`SELECT COUNT(*) AS n FROM memory WHERE status = 'active' AND valid_to IS NULL AND match_count >= ?${agentFilter}`)
    .get(LOAD_BEARING_THRESHOLD, ...params) as { n: number };

  // Stale: active entries where last_matched_at is older than STALE_DAYS, or null
  // and created_at is older than STALE_DAYS.
  const { n: stale } = db
    .query(
      `SELECT COUNT(*) AS n FROM memory
       WHERE status = 'active' AND valid_to IS NULL
         AND (
           (last_matched_at IS NOT NULL AND last_matched_at < ?)
           OR (last_matched_at IS NULL AND created_at < ?)
         )${agentFilter}`
    )
    .get(staleTs, staleTs, ...params) as { n: number };

  return { total, active, probation, retired, loadBearing, stale };
}

/**
 * Returns true when a memory's match_count is high enough that removing it would
 * likely open a detection gap. Used as a guard before retirement.
 */
export function isLoadBearing(id: string): boolean {
  const row = getDb()
    .query("SELECT match_count FROM memory WHERE id = ?")
    .get(id) as { match_count: number } | null;
  return (row?.match_count ?? 0) >= LOAD_BEARING_THRESHOLD;
}
