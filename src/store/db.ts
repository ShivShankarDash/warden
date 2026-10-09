import { Database } from "bun:sqlite";
import type { Finding, ScanResult } from "../types.ts";

/**
 * Where the database lives.
 *
 * Defaults to ~/.warden/warden.db rather than ./warden.db because an MCP host
 * spawns this process with a working directory of its own choosing. A relative
 * path means the database is created wherever the host happened to start —
 * littering the user's project folders, and silently losing learned memory and
 * review history the moment they open a different project. A fixed location in the
 * home directory keeps one database per user, which is what a CLI tool should do.
 *
 * DB_PATH still overrides, which is how the tests and eval keep their own files.
 */
function defaultDbPath(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE;
  if (!home) return "./warden.db"; // no home directory — fall back to cwd
  const dir = `${home}/.warden`;
  try {
    require("node:fs").mkdirSync(dir, { recursive: true });
    return `${dir}/warden.db`;
  } catch {
    return "./warden.db"; // unwritable home — better than failing to start
  }
}

const DB_PATH = process.env.DB_PATH ?? defaultDbPath();

let _db: Database | null = null;

export function getDb(): Database {
  if (_db) return _db;
  _db = new Database(DB_PATH, { create: true });
  _db.exec(`
    CREATE TABLE IF NOT EXISTS scan_results (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      session_id TEXT,
      source TEXT NOT NULL,
      action TEXT NOT NULL,
      risk_score REAL NOT NULL,
      findings TEXT NOT NULL,
      trace TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS review_queue (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      content TEXT NOT NULL,
      findings TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'unknown',
      source_id TEXT,
      agent_id TEXT NOT NULL DEFAULT 'default',
      action TEXT NOT NULL DEFAULT 'HUMAN_REVIEW',
      risk_score REAL NOT NULL DEFAULT 0,
      decision TEXT,
      reviewer_note TEXT,
      created_at INTEGER NOT NULL,
      resolved_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS attack_reference (
      id TEXT PRIMARY KEY,
      attack_type TEXT NOT NULL,
      embedding BLOB,
      text TEXT NOT NULL,
      source TEXT,
      created_at INTEGER NOT NULL
    );

    -- Unified memory: what Warden has learned, and how much it trusts each entry.
    --
    -- label    attack | safe. Safe entries are exculpatory — they exist to suppress
    --          false positives, which is the failure mode that gets firewalls
    --          switched off.
    -- status   probation | active | retired. A new memory is stored but does NOT
    --          influence scans until confirmed. Without this, one wrong verdict
    --          permanently poisons every future lookup with no way to retract it.
    -- origin   human | judge | redteam | seed. Records what vouched for the entry,
    --          so trust can be reasoned about after the fact.
    -- valid_from / valid_to  temporal versioning: retiring a memory closes its
    --          window rather than deleting it, so "memory as of <date>" stays
    --          answerable and a bad batch can be rolled back.
    CREATE TABLE IF NOT EXISTS memory (
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
      created_at INTEGER NOT NULL,
      match_count INTEGER NOT NULL DEFAULT 0,
      last_matched_at INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_memory_active
      ON memory(status, label) WHERE valid_to IS NULL;
    CREATE INDEX IF NOT EXISTS idx_memory_agent ON memory(agent_id);

    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      turn_count INTEGER NOT NULL DEFAULT 0,
      suspicious_turns INTEGER NOT NULL DEFAULT 0,
      consecutive_suspicious INTEGER NOT NULL DEFAULT 0,
      cumulative_risk REAL NOT NULL DEFAULT 0,
      attack_types TEXT NOT NULL DEFAULT '{}',
      first_seen INTEGER NOT NULL,
      last_seen INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS session_taint (
      session_id TEXT NOT NULL,
      shingle TEXT NOT NULL,
      source TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (session_id, shingle)
    );

    -- Per-identity history. source_id is a sender address, domain or server name;
    -- distinct from the source column, which holds a content type.
    CREATE TABLE IF NOT EXISTS source_reputation (
      source_id TEXT NOT NULL,
      agent_id TEXT NOT NULL DEFAULT 'default',
      attacks INTEGER NOT NULL DEFAULT 0,
      clean INTEGER NOT NULL DEFAULT 0,
      last_attack_at INTEGER,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (source_id, agent_id)
    );

    -- Per-attack-type detection coverage: how often each type is seen, caught, or missed.
    CREATE TABLE IF NOT EXISTS coverage_stats (
      attack_type TEXT NOT NULL,
      agent_id TEXT NOT NULL DEFAULT 'default',
      scans INTEGER NOT NULL DEFAULT 0,
      detected INTEGER NOT NULL DEFAULT 0,
      missed INTEGER NOT NULL DEFAULT 0,
      last_missed_at INTEGER,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (attack_type, agent_id)
    );

    CREATE INDEX IF NOT EXISTS idx_coverage_agent ON coverage_stats(agent_id);

    CREATE TABLE IF NOT EXISTS intel_sources (
      source_id TEXT PRIMARY KEY,
      last_fetched_at INTEGER,
      last_row_count INTEGER,
      items_fetched INTEGER NOT NULL DEFAULT 0,
      errors INTEGER NOT NULL DEFAULT 0,
      updated_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_scan_agent ON scan_results(agent_id);
    CREATE INDEX IF NOT EXISTS idx_taint_session ON session_taint(session_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
    CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_results(created_at);
    CREATE INDEX IF NOT EXISTS idx_review_status ON review_queue(status);
  `);

  // Migrate existing DBs that predate the match_count / last_matched_at columns.
  try { _db.exec("ALTER TABLE memory ADD COLUMN match_count INTEGER NOT NULL DEFAULT 0"); } catch {}
  try { _db.exec("ALTER TABLE memory ADD COLUMN last_matched_at INTEGER"); } catch {}

  return _db;
}

export function insertScanResult(result: {
  id: string;
  agentId: string;
  sessionId?: string;
  source: string;
  action: string;
  riskScore: number;
  findings: unknown[];
  trace: unknown[];
  createdAt: number;
}) {
  const db = getDb();
  db.prepare(`
    INSERT INTO scan_results (id, agent_id, session_id, source, action, risk_score, findings, trace, created_at)
    VALUES ($id, $agentId, $sessionId, $source, $action, $riskScore, $findings, $trace, $createdAt)
  `).run({
    $id: result.id,
    $agentId: result.agentId,
    $sessionId: result.sessionId ?? null,
    $source: result.source,
    $action: result.action,
    $riskScore: result.riskScore,
    $findings: JSON.stringify(result.findings),
    $trace: JSON.stringify(result.trace),
    $createdAt: result.createdAt,
  });
}

/** Look up a stored scan result by primary key. Returns null for unknown IDs. */
export function getScanResult(id: string): {
  id: string;
  agentId: string;
  sessionId: string | null;
  source: string;
  action: string;
  riskScore: number;
  findings: Finding[];
  trace: ScanResult["trace"];
  createdAt: number;
} | null {
  const row = getDb()
    .query("SELECT * FROM scan_results WHERE id = ?")
    .get(id) as {
      id: string;
      agent_id: string;
      session_id: string | null;
      source: string;
      action: string;
      risk_score: number;
      findings: string;
      trace: string;
      created_at: number;
    } | null;
  if (!row) return null;
  return {
    id: row.id,
    agentId: row.agent_id,
    sessionId: row.session_id,
    source: row.source,
    action: row.action,
    riskScore: row.risk_score,
    findings: JSON.parse(row.findings) as Finding[],
    trace: JSON.parse(row.trace) as ScanResult["trace"],
    createdAt: row.created_at,
  };
}
