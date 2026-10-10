import { getDb } from "./db.ts";
import type { Action, Finding, SourceType } from "../types.ts";

/**
 * The human review loop.
 *
 * Until now `review_queue` was read and resolved but never written to, so the queue
 * was permanently empty and no human decision ever reached the system. This closes
 * that: uncertain verdicts are queued, and resolving one feeds the outcome back into
 * memory as a human-origin entry — the highest-trust signal Warden has, and the only
 * one allowed to create safe memories.
 */

export interface ReviewItem {
  id: string;
  scanId: string;
  status: "pending" | "resolved";
  content: string;
  findings: Finding[];
  source: SourceType;
  sourceId: string | null;
  agentId: string;
  action: Action;
  riskScore: number;
  decision: string | null;
  reviewerNote: string | null;
  createdAt: number;
  resolvedAt: number | null;
}

/** Verdicts uncertain enough that a human should look. A BLOCK is already decided;
 *  an ALLOW raises nothing to review. The middle is where review earns its keep. */
const REVIEWABLE: Action[] = ["HUMAN_REVIEW", "QUARANTINE"];

export function shouldQueueForReview(action: Action): boolean {
  return REVIEWABLE.includes(action);
}

export function enqueueReview(item: {
  scanId: string;
  content: string;
  findings: Finding[];
  source: SourceType;
  sourceId?: string | null;
  agentId?: string;
  action: Action;
  riskScore: number;
}): string | null {
  if (!shouldQueueForReview(item.action)) return null;

  const id = crypto.randomUUID();
  getDb()
    .prepare(
      `INSERT INTO review_queue
        (id, scan_id, status, content, findings, source, source_id, agent_id, action,
         risk_score, decision, reviewer_note, created_at, resolved_at)
       VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, NULL)`
    )
    .run(
      id,
      item.scanId,
      item.content.slice(0, 8000),
      JSON.stringify(item.findings),
      item.source,
      item.sourceId ?? null,
      item.agentId ?? "default",
      item.action,
      item.riskScore,
      Date.now()
    );
  return id;
}

interface Row {
  id: string; scan_id: string; status: "pending" | "resolved"; content: string;
  findings: string; source: string; source_id: string | null; agent_id: string;
  action: string; risk_score: number; decision: string | null;
  reviewer_note: string | null; created_at: number; resolved_at: number | null;
}

function toItem(r: Row): ReviewItem {
  return {
    id: r.id, scanId: r.scan_id, status: r.status, content: r.content,
    findings: JSON.parse(r.findings) as Finding[],
    source: r.source as SourceType, sourceId: r.source_id, agentId: r.agent_id,
    action: r.action as Action, riskScore: r.risk_score, decision: r.decision,
    reviewerNote: r.reviewer_note, createdAt: r.created_at, resolvedAt: r.resolved_at,
  };
}

export function pendingReviews(agentId?: string, limit = 50, offset = 0): ReviewItem[] {
  const db = getDb();
  const rows = agentId
    ? db.query("SELECT * FROM review_queue WHERE status='pending' AND agent_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?").all(agentId, limit, offset)
    : db.query("SELECT * FROM review_queue WHERE status='pending' ORDER BY created_at DESC LIMIT ? OFFSET ?").all(limit, offset);
  return (rows as Row[]).map(toItem);
}

/**
 * How many items are actually waiting.
 *
 * The queue is served one page at a time, so the length of a page is not the size
 * of the backlog. Reporting the page length as the count made a 880-item queue read
 * as 50 — the reviewer had no way to tell that most of it was out of reach.
 */
export function pendingReviewCount(agentId?: string): number {
  const db = getDb();
  const row = agentId
    ? db.query("SELECT COUNT(*) AS n FROM review_queue WHERE status='pending' AND agent_id=?").get(agentId)
    : db.query("SELECT COUNT(*) AS n FROM review_queue WHERE status='pending'").get();
  return (row as { n: number }).n;
}

export function getReview(id: string): ReviewItem | null {
  const row = getDb().query("SELECT * FROM review_queue WHERE id = ?").get(id) as Row | null;
  return row ? toItem(row) : null;
}

/** Valid decisions a human reviewer can make on a queued item. */
export type ReviewDecision = "attack" | "safe" | "dismiss";

export function markResolved(id: string, decision: ReviewDecision, note?: string): void {
  getDb()
    .prepare(
      "UPDATE review_queue SET status='resolved', decision=?, reviewer_note=?, resolved_at=? WHERE id=?"
    )
    .run(decision, note ?? null, Date.now(), id);
}

/** Counts of how reviewers have ruled per source, used by source reputation. */
export function reviewOutcomesBySource(agentId = "default") {
  return getDb()
    .query(
      `SELECT source, decision, COUNT(*) AS n FROM review_queue
       WHERE status='resolved' AND agent_id=? GROUP BY source, decision`
    )
    .all(agentId) as { source: string; decision: string; n: number }[];
}
