import { scan } from "../detect/orchestrator.ts";
import { getDb, insertScanResult, getScanResult } from "../store/db.ts";
import { initWarden } from "../init.ts";
import { getSession, resetSession } from "../detect/session.ts";
import { scanOutput, generateCanary } from "../guard/output.ts";
import { checkToolCall } from "../guard/tools.ts";
import { recordTaint } from "../guard/taint.ts";
import { enqueueReview, pendingReviews, getReview, markResolved } from "../store/review.ts";
import { addReference, addSafeReference } from "../detect/similarity.ts";
import { memoryStats, recentMemories, recentPromotions } from "../store/memory.ts";
import type { ToolCallCheck, Action, ScanResult } from "../types.ts";
import { analytics, decidedBy, isRange, recentScans } from "./analytics.ts";
import { coverageSummary, coverageGaps } from "../store/coverage.ts";
import { memoryHealth } from "../store/lifecycle.ts";
import { explainVerdict } from "../explain/verdict.ts";
import { getReputation } from "../store/reputation.ts";
import dashboard from "../../dashboard/index.html";

const PORT = Number(process.env.PORT ?? 3000);

await initWarden();

/** Latest saved eval run, for the headline accuracy figures the dashboard shows. */
async function latestEvalSummary() {
  try {
    const dir = "./eval/results";
    const files = [...new Bun.Glob("*.json").scanSync(dir)].sort();
    const newest = files[files.length - 1];
    if (!newest) return null;
    const data = (await Bun.file(`${dir}/${newest}`).json()) as {
      summary: Record<string, number | boolean>;
    };
    return { date: newest.replace(".json", ""), ...data.summary };
  } catch {
    return null;
  }
}

/** p50 of total scan time, read out of the stored traces. */
function latencyPercentiles(limit = 500) {
  const rows = getDb()
    .query("SELECT trace FROM scan_results ORDER BY created_at DESC LIMIT ?")
    .all(limit) as { trace: string }[];

  const totals: number[] = [];
  for (const r of rows) {
    try {
      const trace = JSON.parse(r.trace) as { stage: string; ms: number }[];
      const total = trace.find((t) => t.stage === "total");
      if (total) totals.push(total.ms);
    } catch {
      // A malformed trace should not take the metrics endpoint down.
    }
  }
  if (!totals.length) return { p50: 0, p95: 0, samples: 0 };
  totals.sort((a, b) => a - b);
  const at = (p: number) => totals[Math.min(totals.length - 1, Math.floor(totals.length * p))];
  return { p50: at(0.5), p95: at(0.95), samples: totals.length };
}

// Bun's routes map a path to an object of method handlers. "POST /scan" as a single
// key is not valid and throws at startup.
const server = Bun.serve({
  port: PORT,
  routes: {
    "/scan": {
      POST: async (req) => {
        const body = await req.json();
        const result = await scan(body);
        insertScanResult({
          id: result.id,
          agentId: body.agentId ?? "default",
          sessionId: body.sessionId,
          source: body.source,
          action: result.action,
          riskScore: result.riskScore,
          findings: result.findings,
          trace: result.trace,
          createdAt: result.createdAt,
        });

        // Remember untrusted content so a later tool call carrying it outward can be
        // recognised. Without this the outbound guard has nothing to compare against.
        if (result.action !== "ALLOW" && body.sessionId && typeof body.content === "string") {
          recordTaint(body.sessionId, body.content, body.source ?? "unknown");
        }

        // Uncertain verdicts go to a human. Previously nothing wrote here, so the
        // queue was always empty and no human decision could reach the system.
        if (typeof body.content === "string") {
          enqueueReview({
            scanId: result.id,
            content: body.content,
            findings: result.findings,
            source: body.source,
            sourceId: body.sourceId,
            agentId: body.agentId ?? "default",
            action: result.action,
            riskScore: result.riskScore,
          });
        }

        // Push to the dashboard. broadcastEvent existed but nothing ever called it,
        // so the /events socket had no traffic.
        const decision = decidedBy(result.findings, result.trace);
        server.publish(
          "events",
          JSON.stringify({
            type: "scan",
            id: result.id,
            source: body.source,
            sourceId: body.sourceId ?? null,
            action: result.action,
            riskScore: result.riskScore,
            attackTypes: [...new Set(result.findings.map((f) => f.attackType))],
            decidedBy: decision.stage,
            savedMs: decision.savedMs,
            latencyMs: result.trace.find((t) => t.stage === "total")?.ms ?? 0,
            preview: typeof body.content === "string" ? body.content.slice(0, 160) : "[binary]",
            at: result.createdAt,
          })
        );

        // Optional inline explanation when the caller requests it.
        const wantExplain =
          new URL(req.url).searchParams.get("explain") === "true" ||
          body.explain === true;
        if (wantExplain && typeof body.content === "string") {
          const explanation = await explainVerdict(result, body.content, {
            mode: "fast",
            includeContent: false,
          });
          return Response.json({ ...result, explanation });
        }

        return Response.json(result);
      },
    },

    "/": dashboard,

    "/recent": {
      GET: () => Response.json(recentScans(40)),
    },

    "/analytics": {
      GET: (req) => {
        const r = new URL(req.url).searchParams.get("range");
        return Response.json(analytics(isRange(r) ? r : "24h"));
      },
    },

    "/memory": {
      GET: (req) => {
        const agentId = new URL(req.url).searchParams.get("agentId") ?? "default";
        return Response.json({
          stats: memoryStats(agentId),
          recent: recentMemories(20, agentId),
          promotions: recentPromotions(10, agentId),
        });
      },
    },

    "/scan-output": {
      POST: async (req) => {
        const body = (await req.json()) as {
          content: string;
          canaries?: string[];
          allowedHosts?: string[];
        };
        return Response.json(scanOutput(body));
      },
    },

    "/check-tool": {
      POST: async (req) => {
        const body = (await req.json()) as ToolCallCheck & { allowedTools?: string[] };
        return Response.json(checkToolCall(body));
      },
    },

    "/canary": {
      POST: () => Response.json({ canary: generateCanary() }),
    },

    "/ingest": {
      POST: async (req) => {
        // [ME] Day 5: scan + trust-label document entering RAG/memory
        const body = await req.json();
        const result = await scan({ ...body, agentId: body.agentId ?? "rag" });
        return Response.json({
          trustLabel: result.action === "ALLOW" ? "trusted" : "untrusted",
          result,
        });
      },
    },

    "/session/:id": {
      GET: (req) => {
        const { id } = req.params as { id: string };
        const state = getSession(id);
        if (!state) return Response.json({ error: "unknown session" }, { status: 404 });
        return Response.json({ sessionId: id, ...state });
      },
      DELETE: (req) => {
        const { id } = req.params as { id: string };
        resetSession(id);
        return Response.json({ ok: true });
      },
    },

    "/explain/:scanId": {
      GET: async (req) => {
        const { scanId } = req.params as { scanId: string };
        const row = getScanResult(scanId);
        if (!row) return Response.json({ error: "unknown scan" }, { status: 404 });

        // Content lives only in review_queue, not in scan_results.
        const contentRow = getDb()
          .query("SELECT content FROM review_queue WHERE scan_id = ?")
          .get(scanId) as { content: string } | null;
        const content = contentRow?.content ?? "";

        // Build a ScanResult shape from the DB row.
        const scanResult: ScanResult = {
          id: row.id,
          action: row.action as Action,
          findings: row.findings,
          riskScore: row.riskScore,
          trace: row.trace,
          createdAt: row.createdAt,
        };

        // Look up reputation for richer context.
        const reviewRow = getDb()
          .query("SELECT source_id FROM review_queue WHERE scan_id = ?")
          .get(scanId) as { source_id: string | null } | null;
        const sourceId = reviewRow?.source_id ?? null;
        const reputation = sourceId
          ? getReputation(sourceId, row.agentId)
          : null;

        const explanation = await explainVerdict(scanResult, content, {
          mode: "rich",
          includeContent: !!contentRow,
          reputation,
        });

        return Response.json({ scanId, explanation });
      },
    },

    "/review": {
      GET: async (req) => {
        const agentId = new URL(req.url).searchParams.get("agentId") ?? undefined;
        const items = pendingReviews(agentId);

        // Enrich each review item with a fast-mode explanation.
        const enriched = await Promise.all(
          items.map(async (item) => {
            // Reconstruct a ScanResult from the review item; optionally pull trace
            // from the parent scan_results row.
            const parent = getScanResult(item.scanId);
            const scanResult: ScanResult = {
              id: item.scanId,
              action: item.action,
              findings: item.findings,
              riskScore: item.riskScore,
              trace: parent?.trace ?? [],
              createdAt: item.createdAt,
            };
            const explanation = await explainVerdict(scanResult, item.content, {
              mode: "fast",
              includeContent: false,
            });
            return { ...item, explanation };
          }),
        );

        return Response.json(enriched);
      },
    },

    "/review/:id": {
      POST: async (req) => {
        const { id } = req.params as { id: string };
        const body = (await req.json()) as { decision: "attack" | "safe" | "dismiss"; note?: string };

        const item = getReview(id);
        if (!item) return Response.json({ error: "unknown review item" }, { status: 404 });
        if (item.status === "resolved") {
          return Response.json({ error: "already resolved" }, { status: 409 });
        }

        markResolved(id, body.decision, body.note);

        // A human decision is the highest-trust signal Warden has, so it goes
        // straight into memory as active rather than onto probation. "safe" is only
        // ever reachable from here — learning that something is benign from
        // unreviewed traffic is the poisoning path.
        let learned = false;
        if (body.decision === "attack") {
          const attackType = item.findings[0]?.attackType ?? "instruction_override";
          learned = await addReference(item.content, attackType, item.source, {
            origin: "human",
            agentId: item.agentId,
            sourceId: item.sourceId ?? undefined,
          });
        } else if (body.decision === "safe") {
          learned = await addSafeReference(item.content, item.source, {
            origin: "human",
            agentId: item.agentId,
            sourceId: item.sourceId ?? undefined,
          });
        } else if (body.decision === "dismiss") {
          /* no-op: dismissed without learning */
        }

        return Response.json({ ok: true, decision: body.decision, learned });
      },
    },

    "/metrics": {
      GET: async () => {
        const db = getDb();
        const total = (db.query("SELECT COUNT(*) as n FROM scan_results").get() as { n: number }).n;
        const blocked = (
          db.query("SELECT COUNT(*) as n FROM scan_results WHERE action IN ('BLOCK','QUARANTINE')").get() as { n: number }
        ).n;
        const pending = (
          db.query("SELECT COUNT(*) as n FROM review_queue WHERE status='pending'").get() as { n: number }
        ).n;
        const byAction = db
          .query("SELECT action, COUNT(*) AS n FROM scan_results GROUP BY action")
          .all() as { action: string; n: number }[];
        const bySource = db
          .query("SELECT source, COUNT(*) AS n FROM scan_results GROUP BY source ORDER BY n DESC")
          .all() as { source: string; n: number }[];

        return Response.json({
          total,
          blocked,
          blocked_rate: total ? blocked / total : 0,
          pending_review: pending,
          latency: latencyPercentiles(),
          byAction,
          bySource,
          evaluation: await latestEvalSummary(),
          memory: memoryStats(),
        });
      },
    },

    "/metrics/coverage": {
      GET: (req) => {
        const agentId = new URL(req.url).searchParams.get("agentId") ?? undefined;
        return Response.json({
          gaps: coverageGaps(agentId),
          stats: coverageSummary(agentId),
        });
      },
    },

    "/metrics/intel": {
      GET: () => {
        const db = getDb();
        const sources = db
          .query("SELECT source_id, last_fetched_at, items_fetched, errors, updated_at FROM intel_sources ORDER BY updated_at DESC")
          .all() as { source_id: string; last_fetched_at: number | null; items_fetched: number; errors: number; updated_at: number }[];
        const seeded = (
          db.query("SELECT COUNT(*) as n FROM memory WHERE origin = 'seed' AND valid_to IS NULL").get() as { n: number }
        ).n;
        return Response.json({
          sources,
          totalSeeded: seeded,
          coverageStats: coverageSummary(),
        });
      },
    },

    "/metrics/memory-health": {
      GET: (req) => {
        const agentId = new URL(req.url).searchParams.get("agentId") ?? undefined;
        return Response.json(memoryHealth(agentId));
      },
    },

    "/alerts/export": {
      GET: () => {
        const db = getDb();
        const rows = db
          .query("SELECT * FROM scan_results WHERE action IN ('BLOCK','QUARANTINE','HUMAN_REVIEW') ORDER BY created_at DESC LIMIT 500")
          .all();
        const siem = rows.map((r: any) => ({
          event_type: "warden_alert",
          timestamp: new Date(r.created_at).toISOString(),
          source: r.source,
          action: r.action,
          risk_score: r.risk_score,
          findings: JSON.parse(r.findings),
          agent_id: r.agent_id,
          session_id: r.session_id,
        }));
        return new Response(JSON.stringify(siem, null, 2), {
          headers: { "Content-Type": "application/json" },
        });
      },
    },
  },

  websocket: {
    open(ws) {
      ws.subscribe("events");
    },
    message() {},
    close() {},
  },

  fetch(req, server) {
    if (req.url.endsWith("/events")) {
      const upgraded = server.upgrade(req);
      if (upgraded) return;
    }
    return new Response("Not found", { status: 404 });
  },
});

console.log(`Warden listening on http://localhost:${PORT}`);

export function broadcastEvent(event: unknown) {
  server.publish("events", JSON.stringify(event));
}
