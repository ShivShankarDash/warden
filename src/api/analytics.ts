/**
 * Aggregations behind the dashboard's charts.
 *
 * These read the stored scan rows directly rather than keeping counters in memory,
 * so a restart never loses history and every figure on screen can be traced back to
 * a row in `scan_results`.
 */

import { getDb } from "../store/db.ts";
import type { Finding, ScanResult, Stage } from "../types.ts";

/** The shape stored in `scan_results.trace`; declared inline on ScanResult. */
type TraceEntry = ScanResult["trace"][number];

/** A judge call costs roughly this; a memory match costs about a millisecond. The
 *  gap is the whole point of the learning loop, so it is measured, not asserted. */
export const JUDGE_COST_MS = 1400;

/** Severity tiers. Six actions are too many to read at a glance, and they fall
 *  naturally into three ordered bands — which is also why the chart uses an ordinal
 *  ramp rather than three unrelated hues. */
export type Tier = "allowed" | "flagged" | "blocked";

export function tierOf(action: string): Tier {
  if (action === "ALLOW") return "allowed";
  if (action === "BLOCK" || action === "QUARANTINE") return "blocked";
  return "flagged";
}

const RANGES = {
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
} as const;

export type RangeKey = keyof typeof RANGES | "all";

/** Window bounds plus a bucket width that keeps the column chart readable.
 *  `all` stretches from the first stored scan to now. */
function window(range: RangeKey): { from: number; to: number; bucketMs: number } {
  const to = Date.now();
  if (range === "all") {
    const row = getDb()
      .query("SELECT MIN(created_at) AS t FROM scan_results")
      .get() as { t: number | null } | null;
    const from = row?.t ?? to - RANGES["24h"];
    const span = Math.max(to - from, 60 * 60 * 1000);
    return { from, to, bucketMs: Math.ceil(span / 36 / 60000) * 60000 };
  }
  const span = RANGES[range];
  // 36 columns is dense enough to show shape without turning into hairlines.
  return { from: to - span, to, bucketMs: Math.ceil(span / 36 / 60000) * 60000 };
}

interface Row {
  action: string;
  source: string;
  risk_score: number;
  findings: string;
  trace: string;
  created_at: number;
}

function rowsIn(from: number, to: number): Row[] {
  return getDb()
    .query(
      `SELECT action, source, risk_score, findings, trace, created_at
         FROM scan_results
        WHERE created_at >= ? AND created_at <= ?
        ORDER BY created_at ASC`
    )
    .all(from, to) as Row[];
}

function parse<T>(json: string, fallback: T): T {
  try {
    return JSON.parse(json) as T;
  } catch {
    // A single malformed row should not blank the whole dashboard.
    return fallback;
  }
}

/**
 * Which stage actually settled a scan, and the judge time that saved.
 *
 * Exported so the live websocket event and the historical aggregate agree — two
 * copies of this rule would eventually disagree and the saved-time figure would
 * stop being trustworthy.
 */
export function decidedBy(
  findings: Finding[],
  trace: TraceEntry[]
): { stage: Stage | "none"; savedMs: number } {
  const top = [...findings].sort((a, b) => b.confidence - a.confidence)[0];
  const judgeTrace = trace.find((t) => t.stage === "judge");
  const judgeRan = !!judgeTrace && !judgeTrace.skipped;

  if (top?.stage === "similarity") return { stage: "similarity", savedMs: JUDGE_COST_MS };
  if (top?.stage === "rules" && !judgeRan) return { stage: "rules", savedMs: JUDGE_COST_MS };
  if (judgeRan) return { stage: "judge", savedMs: 0 };
  return { stage: top?.stage ?? "none", savedMs: 0 };
}

export interface Analytics {
  range: RangeKey;
  from: number;
  to: number;
  bucketMs: number;
  /** One entry per time bucket, already zero-filled so the chart never has gaps. */
  series: { t: number; allowed: number; flagged: number; blocked: number }[];
  heatmap: {
    sources: string[];
    attackTypes: string[];
    /** cells[sourceIndex][attackTypeIndex] — scans from that source carrying that type. */
    cells: number[][];
    /** Total scans per source, for the volume column beside the grid. */
    rowTotals: number[];
    max: number;
  };
  /** How scans were settled, and the judge time the fast paths avoided. */
  decisions: { stage: string; n: number }[];
  savedMs: number;
  totals: { scans: number; allowed: number; flagged: number; blocked: number; threats: number };
}

export function analytics(range: RangeKey): Analytics {
  const { from, to, bucketMs } = window(range);
  const rows = rowsIn(from, to);

  // ---- time series (zero-filled buckets) ----
  const bucketCount = Math.max(1, Math.ceil((to - from) / bucketMs));
  const start = Math.floor(from / bucketMs) * bucketMs;
  const series = Array.from({ length: bucketCount }, (_, i) => ({
    t: start + i * bucketMs,
    allowed: 0,
    flagged: 0,
    blocked: 0,
  }));

  // ---- heatmap accumulator (sparse until we know which labels appear) ----
  const sourceTotals = new Map<string, number>();
  const pairs = new Map<string, number>();
  const attackSeen = new Map<string, number>();

  const stages = new Map<string, number>();
  let savedMs = 0;
  const totals = { scans: rows.length, allowed: 0, flagged: 0, blocked: 0, threats: 0 };

  for (const r of rows) {
    const tier = tierOf(r.action);
    totals[tier]++;
    if (tier !== "allowed") totals.threats++;

    const idx = Math.min(series.length - 1, Math.floor((r.created_at - start) / bucketMs));
    if (idx >= 0) series[idx]![tier]++;

    sourceTotals.set(r.source, (sourceTotals.get(r.source) ?? 0) + 1);

    const findings = parse<Finding[]>(r.findings, []);
    // One scan counts once per attack type, however many findings carried it.
    for (const type of new Set(findings.map((f) => f.attackType))) {
      const key = `${r.source}\u0000${type}`;
      pairs.set(key, (pairs.get(key) ?? 0) + 1);
      attackSeen.set(type, (attackSeen.get(type) ?? 0) + 1);
    }

    const d = decidedBy(findings, parse<TraceEntry[]>(r.trace, []));
    stages.set(d.stage, (stages.get(d.stage) ?? 0) + 1);
    savedMs += d.savedMs;
  }

  // Rows are every source that sent traffic, ordered by volume — so the grid shows
  // quiet-but-clean sources too, not just the ones that happened to be attacked.
  const sources = [...sourceTotals.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([s]) => s);
  const attackTypes = [...attackSeen.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([t]) => t);

  const cells = sources.map((s) => attackTypes.map((t) => pairs.get(`${s}\u0000${t}`) ?? 0));
  const max = cells.flat().reduce((m, n) => Math.max(m, n), 0);

  return {
    range,
    from,
    to,
    bucketMs,
    series,
    heatmap: {
      sources,
      attackTypes,
      cells,
      rowTotals: sources.map((s) => sourceTotals.get(s) ?? 0),
      max,
    },
    decisions: [...stages.entries()]
      .map(([stage, n]) => ({ stage, n }))
      .sort((a, b) => b.n - a.n),
    savedMs,
    totals,
  };
}

export function isRange(v: string | null): v is RangeKey {
  return v === "all" || (!!v && v in RANGES);
}

/**
 * The last few scans, for the dashboard's feed on first paint.
 *
 * `scan_results` deliberately stores no content, so there is no preview to show for
 * a historical row — the feed falls back to the findings. Live rows arriving over
 * the websocket carry a preview because the request body is still in hand.
 */
export function recentScans(limit = 40) {
  const rows = getDb()
    .query(
      `SELECT id, source, action, risk_score, findings, trace, created_at
         FROM scan_results ORDER BY created_at DESC LIMIT ?`
    )
    .all(Math.min(limit, 200)) as (Row & { id: string })[];

  return rows.map((r) => {
    const findings = parse<Finding[]>(r.findings, []);
    const trace = parse<TraceEntry[]>(r.trace, []);
    const d = decidedBy(findings, trace);
    return {
      id: r.id,
      source: r.source,
      action: r.action,
      riskScore: r.risk_score,
      attackTypes: [...new Set(findings.map((f) => f.attackType))],
      decidedBy: d.stage,
      savedMs: d.savedMs,
      latencyMs: trace.find((t) => t.stage === "total")?.ms ?? 0,
      at: r.created_at,
    };
  });
}
