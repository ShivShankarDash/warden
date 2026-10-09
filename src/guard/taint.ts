import { getDb } from "../store/db.ts";

/**
 * Taint tracking.
 *
 * Full data-flow tracking through a model is not possible — once untrusted text is
 * in the context, the model may paraphrase or summarise it. What *is* tractable is
 * recognising untrusted text being carried back out verbatim, which is what
 * exfiltration actually looks like: the agent copies a secret, a document body, or
 * an attacker-supplied URL into a tool call.
 *
 * Content that fails a scan is reduced to overlapping word-shingles and stored
 * against the session. A later tool call whose arguments share shingles with that
 * content is carrying it.
 */

/** Words per shingle. Long enough that ordinary phrases don't collide, short enough
 *  to survive light editing by the model. */
const SHINGLE_WORDS = 8;

/** Cap per session so a large document can't bloat the table unboundedly. */
const MAX_SHINGLES_PER_SESSION = 2000;

function normalise(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s@._:/-]/gu, " ")
    .split(/\s+/)
    .filter(Boolean);
}

function hash(s: string): string {
  return Bun.hash(s).toString(36);
}

export function shingles(text: string): string[] {
  const words = normalise(text);
  if (words.length < SHINGLE_WORDS) {
    return words.length ? [hash(words.join(" "))] : [];
  }
  const out: string[] = [];
  for (let i = 0; i + SHINGLE_WORDS <= words.length; i++) {
    out.push(hash(words.slice(i, i + SHINGLE_WORDS).join(" ")));
  }
  return out;
}

/** Records untrusted content so later tool calls can be checked against it. */
export function recordTaint(sessionId: string, content: string, source: string): number {
  const db = getDb();
  const hashes = [...new Set(shingles(content))].slice(0, MAX_SHINGLES_PER_SESSION);
  if (!hashes.length) return 0;

  const insert = db.prepare(
    "INSERT OR IGNORE INTO session_taint (session_id, shingle, source, created_at) VALUES (?, ?, ?, ?)"
  );
  const now = Date.now();
  const tx = db.transaction((rows: string[]) => {
    for (const h of rows) insert.run(sessionId, h, source, now);
  });
  tx(hashes);
  return hashes.length;
}

export interface TaintMatch {
  matched: number;
  total: number;
  ratio: number;
  sources: string[];
}

/** How much of `text` came from content previously marked untrusted in this session. */
export function checkTaint(sessionId: string, text: string): TaintMatch {
  const hashes = [...new Set(shingles(text))];
  if (!hashes.length) return { matched: 0, total: 0, ratio: 0, sources: [] };

  const db = getDb();
  const placeholders = hashes.map(() => "?").join(",");
  const rows = db
    .query(
      `SELECT shingle, source FROM session_taint WHERE session_id = ? AND shingle IN (${placeholders})`
    )
    .all(sessionId, ...hashes) as { shingle: string; source: string }[];

  const sources = [...new Set(rows.map((r) => r.source))];
  return {
    matched: rows.length,
    total: hashes.length,
    ratio: hashes.length ? rows.length / hashes.length : 0,
    sources,
  };
}

export function clearTaint(sessionId: string): void {
  getDb().prepare("DELETE FROM session_taint WHERE session_id = ?").run(sessionId);
}
