import { getDb } from "./db.ts";
import type { AttackType } from "../types.ts";
import { toBlob, fromBlob } from "../detect/embeddings.ts";

/**
 * Warden's memory: the attacks and safe examples it has learned.
 *
 * Two properties keep a learning firewall from being taught wrong:
 *
 *  - **Probation.** A new memory is written but does not influence scans until it is
 *    confirmed. One mistaken verdict should not permanently alter every future
 *    decision, and an attacker who gets a single payload accepted should not thereby
 *    own the classifier.
 *  - **Temporal validity.** Retiring a memory closes its window instead of deleting
 *    the row, so a bad batch can be rolled back and "what did Warden believe on
 *    Tuesday" stays answerable.
 */

export type MemoryLabel = "attack" | "safe";
export type MemoryStatus = "probation" | "active" | "retired";
/** What vouched for this memory. Only human and seed are trusted enough to create
 *  safe entries — learning "this is safe" from unreviewed traffic is the poisoning
 *  path, since an attacker controls the traffic. */
export type MemoryOrigin = "human" | "judge" | "rules" | "redteam" | "seed";

export interface MemoryRecord {
  id: string;
  label: MemoryLabel;
  attackType: AttackType | null;
  vector: Float32Array;
  text: string;
  source: string | null;
  sourceId: string | null;
  status: MemoryStatus;
  origin: MemoryOrigin;
  confirmations: number;
  agentId: string;
  matchCount: number;
  lastMatchedAt: number | null;
}

/** Confirmations required to promote a probationary memory to active. */
const PROMOTION_THRESHOLD = Number(process.env.MEMORY_PROMOTION_THRESHOLD ?? 2);

interface Row {
  id: string;
  label: MemoryLabel;
  attack_type: string | null;
  embedding: Uint8Array;
  text: string;
  source: string | null;
  source_id: string | null;
  status: MemoryStatus;
  origin: MemoryOrigin;
  confirmations: number;
  agent_id: string;
  match_count: number;
  last_matched_at: number | null;
}

function toRecord(r: Row): MemoryRecord {
  return {
    id: r.id,
    label: r.label,
    attackType: (r.attack_type as AttackType) ?? null,
    vector: fromBlob(r.embedding),
    text: r.text,
    source: r.source,
    sourceId: r.source_id,
    status: r.status,
    origin: r.origin,
    confirmations: r.confirmations,
    agentId: r.agent_id,
    matchCount: r.match_count ?? 0,
    lastMatchedAt: r.last_matched_at ?? null,
  };
}

export interface AddMemoryInput {
  label: MemoryLabel;
  attackType?: AttackType | null;
  vector: Float32Array;
  text: string;
  source?: string | null;
  sourceId?: string | null;
  origin: MemoryOrigin;
  agentId?: string;
}

/**
 * Writes a memory. Human and seed entries are trusted immediately; anything learned
 * automatically starts on probation.
 */
export function addMemory(input: AddMemoryInput): MemoryRecord {
  const trusted = input.origin === "human" || input.origin === "seed";
  const now = Date.now();
  const id = crypto.randomUUID();

  getDb()
    .prepare(
      `INSERT INTO memory
        (id, label, attack_type, embedding, text, source, source_id, status, origin,
         confirmations, agent_id, valid_from, valid_to, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`
    )
    .run(
      id,
      input.label,
      input.attackType ?? null,
      toBlob(input.vector),
      input.text.slice(0, 4000),
      input.source ?? null,
      input.sourceId ?? null,
      trusted ? "active" : "probation",
      input.origin,
      // Creating the memory is itself the first sighting, so the count starts at 1.
      // With PROMOTION_THRESHOLD = 2 that means "seen twice independently" promotes.
      trusted ? PROMOTION_THRESHOLD : 1,
      input.agentId ?? "default",
      now,
      now
    );

  return {
    id,
    label: input.label,
    attackType: input.attackType ?? null,
    vector: input.vector,
    text: input.text,
    source: input.source ?? null,
    sourceId: input.sourceId ?? null,
    status: trusted ? "active" : "probation",
    origin: input.origin,
    confirmations: trusted ? PROMOTION_THRESHOLD : 1,
    agentId: input.agentId ?? "default",
    matchCount: 0,
    lastMatchedAt: null,
  };
}

/**
 * Records that an existing memory was seen again. Independent sightings are what
 * promote it off probation — a payload seen once might be a misfire, the same
 * payload seen repeatedly is a pattern.
 */
export function confirmMemory(id: string): MemoryStatus | null {
  const db = getDb();
  const row = db
    .query("SELECT confirmations, status FROM memory WHERE id = ? AND valid_to IS NULL")
    .get(id) as { confirmations: number; status: MemoryStatus } | null;
  if (!row || row.status === "retired") return null;

  const confirmations = row.confirmations + 1;
  const promoting = row.status === "probation" && confirmations >= PROMOTION_THRESHOLD;
  const status: MemoryStatus = promoting || row.status === "active" ? "active" : "probation";

  if (promoting) {
    db.prepare(
      "UPDATE memory SET confirmations = ?, status = 'active', valid_from = ? WHERE id = ?"
    ).run(confirmations, Date.now(), id);
  } else {
    db.prepare("UPDATE memory SET confirmations = ?, status = ? WHERE id = ?").run(
      confirmations, status, id
    );
  }
  return status;
}

/** Promotes immediately, bypassing the confirmation count. For human approval. */
export function approveMemory(id: string): void {
  getDb()
    .prepare(
      `UPDATE memory SET status = 'active', origin = 'human',
         confirmations = MAX(confirmations, ?),
         valid_from = CASE WHEN status = 'probation' THEN ? ELSE valid_from END
       WHERE id = ?`
    )
    .run(PROMOTION_THRESHOLD, Date.now(), id);
}

/** Closes a memory's validity window rather than deleting it, so history survives. */
export function retireMemory(id: string, at = Date.now()): void {
  getDb()
    .prepare("UPDATE memory SET status = 'retired', valid_to = ? WHERE id = ? AND valid_to IS NULL")
    .run(at, id);
}

/**
 * Memories in effect, optionally as of a past instant.
 *
 * Only `active` entries are returned: probationary ones are deliberately invisible to
 * scanning, which is what makes probation meaningful rather than cosmetic.
 */
export function activeMemories(opts: { agentId?: string; asOf?: number } = {}): MemoryRecord[] {
  const asOf = opts.asOf ?? Date.now();
  const agentId = opts.agentId ?? "default";

  // Status and validity are different axes. `status` is the current label; the window
  // is what was true at a given instant. Filtering on status = 'active' would hide a
  // memory that has since been retired even when asOf falls inside its window, which
  // makes point-in-time queries useless. Probationary entries never became effective,
  // so they are excluded by status; everything else is decided by the window, with
  // valid_from set at the moment the memory started counting.
  const rows = getDb()
    .query(
      `SELECT * FROM memory
       WHERE status <> 'probation'
         AND agent_id = ?
         AND valid_from <= ?
         AND (valid_to IS NULL OR valid_to > ?)`
    )
    .all(agentId, asOf, asOf) as Row[];

  return rows.map(toRecord);
}

export function allMemories(opts: { agentId?: string } = {}): MemoryRecord[] {
  const rows = getDb()
    .query("SELECT * FROM memory WHERE agent_id = ? AND valid_to IS NULL")
    .all(opts.agentId ?? "default") as Row[];
  return rows.map(toRecord);
}

export function memoryStats(agentId = "default") {
  const rows = getDb()
    .query(
      `SELECT label, status, COUNT(*) AS n FROM memory
       WHERE agent_id = ? AND valid_to IS NULL GROUP BY label, status`
    )
    .all(agentId) as { label: MemoryLabel; status: MemoryStatus; n: number }[];

  const stats = { attack: { active: 0, probation: 0 }, safe: { active: 0, probation: 0 } };
  for (const r of rows) {
    if (r.status === "retired") continue;
    stats[r.label][r.status as "active" | "probation"] = r.n;
  }
  return stats;
}

export interface MemorySummary {
  id: string;
  label: MemoryLabel;
  attackType: string | null;
  text: string;
  source: string | null;
  status: MemoryStatus;
  origin: MemoryOrigin;
  confirmations: number;
  validFrom: number;
  createdAt: number;
}

const SUMMARY_COLUMNS =
  "id, label, attack_type, text, source, status, origin, confirmations, valid_from, created_at";

function toSummary(r: {
  id: string; label: MemoryLabel; attack_type: string | null; text: string;
  source: string | null; status: MemoryStatus; origin: MemoryOrigin;
  confirmations: number; valid_from: number; created_at: number;
}): MemorySummary {
  return {
    id: r.id, label: r.label, attackType: r.attack_type, text: r.text,
    source: r.source, status: r.status, origin: r.origin,
    confirmations: r.confirmations, validFrom: r.valid_from, createdAt: r.created_at,
  };
}

/** Most recently written memories, newest first. Read-only; for display. */
export function recentMemories(limit = 20, agentId = "default"): MemorySummary[] {
  const rows = getDb()
    .query(
      `SELECT ${SUMMARY_COLUMNS} FROM memory
       WHERE agent_id = ? AND valid_to IS NULL
       ORDER BY created_at DESC LIMIT ?`
    )
    .all(agentId, limit) as Parameters<typeof toSummary>[0][];
  return rows.map(toSummary);
}

/**
 * Memories that were promoted off probation, newest first.
 *
 * Judge- and redteam-origin entries always start on probation, so an active one
 * necessarily earned its way there — valid_from is stamped at the moment of
 * promotion, which makes it the ordering key.
 */
export function recentPromotions(limit = 10, agentId = "default"): MemorySummary[] {
  const rows = getDb()
    .query(
      `SELECT ${SUMMARY_COLUMNS} FROM memory
       WHERE agent_id = ? AND valid_to IS NULL
         AND status = 'active' AND origin IN ('judge','redteam')
       ORDER BY valid_from DESC LIMIT ?`
    )
    .all(agentId, limit) as Parameters<typeof toSummary>[0][];
  return rows.map(toSummary);
}

/**
 * Rebuilds the memory table when its CHECK constraint predates an origin value.
 *
 * SQLite bakes CHECK constraints into the table definition and cannot ALTER them, so
 * a database created before 'rules' existed would reject those inserts at runtime —
 * silently losing every rule-caught attack. Detect the stale definition and rebuild,
 * preserving rows.
 */
export function migrateMemoryConstraints(): boolean {
  const db = getDb();
  const row = db
    .query("SELECT sql FROM sqlite_master WHERE type='table' AND name='memory'")
    .get() as { sql: string } | null;
  if (!row || row.sql.includes("'rules'")) return false;

  db.transaction(() => {
    db.run(`
      CREATE TABLE memory_migrated (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL CHECK (label IN ('attack','safe')),
        attack_type TEXT,
        embedding BLOB NOT NULL,
        text TEXT NOT NULL,
        source TEXT,
        source_id TEXT,
        status TEXT NOT NULL DEFAULT 'probation'
          CHECK (status IN ('probation','active','retired')),
        origin TEXT NOT NULL CHECK (origin IN ('human','judge','rules','redteam','seed')),
        confirmations INTEGER NOT NULL DEFAULT 0,
        agent_id TEXT NOT NULL DEFAULT 'default',
        valid_from INTEGER NOT NULL,
        valid_to INTEGER,
        created_at INTEGER NOT NULL
      )`);
    db.run("INSERT INTO memory_migrated SELECT * FROM memory");
    db.run("DROP TABLE memory");
    db.run("ALTER TABLE memory_migrated RENAME TO memory");
    db.run("CREATE INDEX IF NOT EXISTS idx_memory_active ON memory(status, label) WHERE valid_to IS NULL");
    db.run("CREATE INDEX IF NOT EXISTS idx_memory_agent ON memory(agent_id)");
  })();
  return true;
}

/** Migrates rows from the pre-probation attack_reference table, once. */
export function migrateLegacyReferences(): number {
  const db = getDb();
  const legacy = db
    .query("SELECT id, attack_type, embedding, text, source, created_at FROM attack_reference")
    .all() as {
    id: string;
    attack_type: string;
    embedding: Uint8Array;
    text: string;
    source: string | null;
    created_at: number;
  }[];
  if (!legacy.length) return 0;

  const existing = db.query("SELECT COUNT(*) AS n FROM memory").get() as { n: number };
  if (existing.n > 0) return 0;

  const insert = db.prepare(
    `INSERT INTO memory
      (id, label, attack_type, embedding, text, source, source_id, status, origin,
       confirmations, agent_id, valid_from, valid_to, created_at)
     VALUES (?, 'attack', ?, ?, ?, ?, NULL, 'active', 'judge', ?, 'default', ?, NULL, ?)`
  );
  const tx = db.transaction((rows: typeof legacy) => {
    for (const r of rows) {
      insert.run(r.id, r.attack_type, r.embedding, r.text, r.source, PROMOTION_THRESHOLD, r.created_at, r.created_at);
    }
  });
  tx(legacy);
  return legacy.length;
}
