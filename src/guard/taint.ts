import { getDb } from "../store/db.ts";
import { decode } from "../decode/index.ts";

/**
 * Taint tracking.
 *
 * Full data-flow tracking through a model is not possible — once untrusted text is
 * in the context, the model may paraphrase or summarise it. What *is* tractable is
 * recognising untrusted content being carried back out, which is what exfiltration
 * actually looks like: the agent copies a secret, a document body, or an
 * attacker-supplied URL into a tool call.
 *
 * Two signals, because one was not enough:
 *
 *  - *Shingles*. Content that fails a scan is reduced to overlapping word-shingles
 *    and stored against the session. Arguments sharing shingles are carrying it.
 *    This only recognises text carried near-verbatim.
 *
 *  - *Entities*. Shingle matching inverted the real threat model. An agent acting on
 *    a poisoned document normally restates it before sending — it summarises,
 *    bullets, wraps in JSON, translates — and an 8-word shingle survives none of
 *    that. Measured against 11 realistic restatements of one document, 7 walked
 *    straight through while only the verbatim cases blocked. What does survive is
 *    the distinctive literals: a passphrase, an account number, a person's name.
 *    Those are stored too, and matched independently of word order.
 */

/** Words per shingle. Long enough that ordinary phrases don't collide, short enough
 *  to survive light editing by the model. */
const SHINGLE_WORDS = 8;

/** Cap per session so a large document can't bloat the table unboundedly. */
const MAX_SHINGLES_PER_SESSION = 2000;

/** Same cap for entities. Far fewer of them, so a lower ceiling is plenty. */
const MAX_ENTITIES_PER_SESSION = 300;

/**
 * Entity fingerprints share the `session_taint` table with shingles, separated by
 * these prefixes rather than by a new column: the table's primary key is
 * (session_id, shingle), so a prefix keeps both kinds unique without a migration
 * that every deployed database would have to run. `s:` is implicit — shingles keep
 * their bare hash so existing rows still match.
 */
const STRONG_ENTITY_PREFIX = "e1:";
const WEAK_ENTITY_PREFIX = "e2:";

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

/**
 * Both sides of the comparison go through the input pipeline's decoder first.
 *
 * Base64 was a free evasion: the same bytes, re-encoded, share no words with the
 * original and so shared no shingles and no entities. `src/decode` already undoes
 * base64, URL-encoding, hex, rot13, homoglyphs and invisible characters on the way
 * in, so an outbound argument that has been encoded is compared on its decoded form
 * instead. Normalising both sides is what matters — decoding only the outbound side
 * would miss a document that arrived encoded.
 */
function decoded(text: string): string {
  try {
    return decode(text).text;
  } catch {
    // A decoder failure must not silently disable taint tracking; fall back to raw.
    return text;
  }
}

export function shingles(text: string): string[] {
  const words = normalise(decoded(text));
  if (words.length < SHINGLE_WORDS) {
    return words.length ? [hash(words.join(" "))] : [];
  }
  const out: string[] = [];
  for (let i = 0; i + SHINGLE_WORDS <= words.length; i++) {
    out.push(hash(words.slice(i, i + SHINGLE_WORDS).join(" ")));
  }
  return out;
}

/** An identifier-shaped literal: letters and digits together, or separated by a
 *  hyphen or underscore. "maple-harbour-29", "AKIAIOSFODNN7EXAMPLE", "INV-2219". */
const IDENTIFIER = /\b(?=[\w-]*\d)(?=[\w-]*[A-Za-z])[\w-]{6,40}\b/g;

/** A bare run of digits: account, invoice, card, case number. */
const DIGIT_RUN = /\b\d{4,}\b/g;

const EMAIL = /\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/g;

/** A URL with a path. Bare hosts are deliberately excluded — a poisoned document
 *  mentioning "https://github.com" should not taint every later mention of GitHub. */
const URL_WITH_PATH = /\bhttps?:\/\/[^\s<>"')\]]+\/[^\s<>"')\]]+/g;

/** A capitalised word that is not the first word of its sentence, so it is a name
 *  rather than ordinary sentence case. "…held under the name Priya Raghunathan at
 *  the Brighton branch" yields Priya, Raghunathan, Brighton; "Account 88142 is…"
 *  yields nothing from "Account", which is only capitalised because it starts one. */
const MID_SENTENCE_PROPER = /(?<=[a-z,;]\s+)\b[A-Z][a-z]{3,}\b/g;

/**
 * Literals distinctive enough that finding them in a later tool call means the
 * content came from here, not from coincidence.
 *
 * `strong` ones stand alone: a passphrase or an account number does not turn up by
 * chance. `weak` ones — ordinary capitalised names — need a second match before
 * they count, because one shared surname between a document and an unrelated
 * message is not evidence of anything.
 */
export function entities(text: string): { strong: string[]; weak: string[] } {
  const src = decoded(text);
  const strong = new Set<string>();
  const weak = new Set<string>();

  for (const m of src.match(EMAIL) ?? []) strong.add(m.toLowerCase());
  for (const m of src.match(URL_WITH_PATH) ?? []) strong.add(m.toLowerCase());
  for (const m of src.match(IDENTIFIER) ?? []) strong.add(m.toLowerCase());
  for (const m of src.match(DIGIT_RUN) ?? []) {
    // A four-digit number is usually a year, and a year is not an identifier.
    const n = Number(m);
    if (m.length === 4 && n >= 1900 && n <= 2100) continue;
    (m.length >= 5 ? strong : weak).add(m);
  }
  for (const m of src.match(MID_SENTENCE_PROPER) ?? []) weak.add(m.toLowerCase());

  // An identifier is also matched by DIGIT_RUN's siblings; keep the sets disjoint so
  // counts mean what they say.
  for (const s of strong) weak.delete(s);

  return { strong: [...strong], weak: [...weak] };
}

/** Entity fingerprints are hashed like shingles, and for the same reason: the taint
 *  table would otherwise hold the plaintext of every passphrase and account number
 *  that ever failed a scan. A blocked call can report how many matched, not what. */
function entityKeys(text: string): string[] {
  const { strong, weak } = entities(text);
  return [
    ...strong.map((e) => STRONG_ENTITY_PREFIX + hash(e)),
    ...weak.map((e) => WEAK_ENTITY_PREFIX + hash(e)),
  ];
}

/** Records untrusted content so later tool calls can be checked against it. */
export function recordTaint(sessionId: string, content: string, source: string): number {
  const db = getDb();
  const hashes = [...new Set(shingles(content))].slice(0, MAX_SHINGLES_PER_SESSION);
  const entityHashes = [...new Set(entityKeys(content))].slice(0, MAX_ENTITIES_PER_SESSION);
  if (!hashes.length && !entityHashes.length) return 0;

  const insert = db.prepare(
    "INSERT OR IGNORE INTO session_taint (session_id, shingle, source, created_at) VALUES (?, ?, ?, ?)"
  );
  const now = Date.now();
  const tx = db.transaction((rows: string[]) => {
    for (const h of rows) insert.run(sessionId, h, source, now);
  });
  tx([...hashes, ...entityHashes]);
  // Still the shingle count: callers log this as "how much of the document is
  // fingerprinted", and entities are a different unit.
  return hashes.length;
}

export interface TaintMatch {
  matched: number;
  total: number;
  ratio: number;
  sources: string[];
  /** Distinctive literals from tainted content found in this text. Independent of
   *  `ratio`, which only sees text carried near-verbatim. */
  strongEntities: number;
  weakEntities: number;
}

/** How much of `text` came from content previously marked untrusted in this session. */
export function checkTaint(sessionId: string, text: string): TaintMatch {
  const hashes = [...new Set(shingles(text))];
  const entityHashes = [...new Set(entityKeys(text))];
  const empty = { matched: 0, total: 0, ratio: 0, sources: [], strongEntities: 0, weakEntities: 0 };
  if (!hashes.length && !entityHashes.length) return empty;

  const db = getDb();
  const all = [...hashes, ...entityHashes];
  const placeholders = all.map(() => "?").join(",");
  const rows = db
    .query(
      `SELECT shingle, source FROM session_taint WHERE session_id = ? AND shingle IN (${placeholders})`
    )
    .all(sessionId, ...all) as { shingle: string; source: string }[];

  // `ratio` stays strictly shingle-over-shingle. Folding entity hits into it would
  // make the percentage in a block message mean two different things at once.
  const shingleHits = rows.filter(
    (r) => !r.shingle.startsWith(STRONG_ENTITY_PREFIX) && !r.shingle.startsWith(WEAK_ENTITY_PREFIX)
  );
  const sources = [...new Set(rows.map((r) => r.source))];
  return {
    matched: shingleHits.length,
    total: hashes.length,
    ratio: hashes.length ? shingleHits.length / hashes.length : 0,
    sources,
    strongEntities: rows.filter((r) => r.shingle.startsWith(STRONG_ENTITY_PREFIX)).length,
    weakEntities: rows.filter((r) => r.shingle.startsWith(WEAK_ENTITY_PREFIX)).length,
  };
}

export function clearTaint(sessionId: string): void {
  getDb().prepare("DELETE FROM session_taint WHERE session_id = ?").run(sessionId);
}
