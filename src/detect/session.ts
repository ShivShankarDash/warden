import type { Finding, AttackType } from "../types.ts";
import { getDb } from "../store/db.ts";

export interface SessionAssessment {
  sessionRisk: number;
  escalate: boolean;
  reason: string;
  turnCount: number;
  consecutiveSuspicious: number;
}

/** Below this a turn is treated as clean and contributes nothing, so ordinary
 *  long conversations don't drift upward on noise alone. */
const SUSPICION_FLOOR = 0.25;

/** How much of a suspicious turn's risk carries into the session total. Tuned so
 *  three consecutive sub-threshold probes (~0.3/0.35/0.45 — the confidences the
 *  multi-step rules emit) cross 0.8, while two do not. */
const GAIN = 0.75;

/** Accumulated risk halves after this long idle, so a session isn't condemned by
 *  something that happened hours ago. */
const HALF_LIFE_MS = 30 * 60 * 1000;

/** Consecutive suspicious turns that trip escalation on their own. A steady climb
 *  is the Crescendo signature even when no single turn is damning. */
const CONSECUTIVE_LIMIT = 3;

interface SessionRow {
  turn_count: number;
  suspicious_turns: number;
  consecutive_suspicious: number;
  cumulative_risk: number;
  attack_types: string;
  last_seen: number;
}

function readSession(sessionId: string): SessionRow | null {
  return getDb()
    .query("SELECT turn_count, suspicious_turns, consecutive_suspicious, cumulative_risk, attack_types, last_seen FROM sessions WHERE session_id = ?")
    .get(sessionId) as SessionRow | null;
}

export function updateSession(
  sessionId: string,
  agentId: string,
  turnRisk: number,
  findings: Finding[],
  threshold: number
): SessionAssessment {
  const db = getDb();
  const now = Date.now();
  const prev = readSession(sessionId);

  // Decay whatever was carried over before adding this turn
  const elapsed = prev ? now - prev.last_seen : 0;
  const decayed = prev ? prev.cumulative_risk * Math.pow(0.5, elapsed / HALF_LIFE_MS) : 0;

  const isSuspicious = turnRisk >= SUSPICION_FLOOR;
  const sessionRisk = Math.min(1, decayed + (isSuspicious ? turnRisk * GAIN : 0));

  const turnCount = (prev?.turn_count ?? 0) + 1;
  const suspiciousTurns = (prev?.suspicious_turns ?? 0) + (isSuspicious ? 1 : 0);
  const consecutive = isSuspicious ? (prev?.consecutive_suspicious ?? 0) + 1 : 0;

  const attackTypes: Record<string, number> = prev ? JSON.parse(prev.attack_types) : {};
  for (const f of findings) {
    attackTypes[f.attackType] = (attackTypes[f.attackType] ?? 0) + 1;
  }

  db.prepare(`
    INSERT INTO sessions (session_id, agent_id, turn_count, suspicious_turns, consecutive_suspicious,
                          cumulative_risk, attack_types, first_seen, last_seen)
    VALUES ($sid, $aid, $turns, $susp, $consec, $risk, $types, $now, $now)
    ON CONFLICT(session_id) DO UPDATE SET
      turn_count = $turns, suspicious_turns = $susp, consecutive_suspicious = $consec,
      cumulative_risk = $risk, attack_types = $types, last_seen = $now
  `).run({
    $sid: sessionId,
    $aid: agentId,
    $turns: turnCount,
    $susp: suspiciousTurns,
    $consec: consecutive,
    $risk: sessionRisk,
    $types: JSON.stringify(attackTypes),
    $now: now,
  });

  const repeated = Object.entries(attackTypes)
    .filter(([, n]) => n >= CONSECUTIVE_LIMIT)
    .map(([t]) => t as AttackType);

  let escalate = false;
  let reason = "";
  if (sessionRisk >= threshold) {
    escalate = true;
    reason = `Session risk ${sessionRisk.toFixed(2)} over ${turnCount} turns exceeds threshold ${threshold} — ${suspiciousTurns} suspicious turns accumulated`;
  } else if (consecutive >= CONSECUTIVE_LIMIT) {
    escalate = true;
    reason = `${consecutive} consecutive suspicious turns — gradual escalation pattern (Crescendo)`;
  } else if (repeated.length) {
    escalate = true;
    reason = `Repeated ${repeated.join(", ")} across ${turnCount} turns`;
  }

  return { sessionRisk, escalate, reason, turnCount, consecutiveSuspicious: consecutive };
}

export function getSession(sessionId: string) {
  const row = readSession(sessionId);
  if (!row) return null;
  return {
    turnCount: row.turn_count,
    suspiciousTurns: row.suspicious_turns,
    consecutiveSuspicious: row.consecutive_suspicious,
    sessionRisk: row.cumulative_risk,
    attackTypes: JSON.parse(row.attack_types) as Record<string, number>,
    lastSeen: row.last_seen,
  };
}

export function resetSession(sessionId: string): void {
  getDb().prepare("DELETE FROM sessions WHERE session_id = ?").run(sessionId);
}
