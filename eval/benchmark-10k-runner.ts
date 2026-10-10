/**
 * 10K Benchmark Runner
 *
 * Reads the 10K corpus, starts the Warden API server with the judge-enabled
 * benchmark-10k policy, scans every case via HTTP, and produces detailed
 * results (JSON + markdown summary).
 *
 * Usage:  bun eval/benchmark-10k-runner.ts
 */
import { spawn, type Subprocess } from "bun";
import { unlinkSync, existsSync, mkdirSync } from "node:fs";

// ── Configuration ────────────────────────────────────────────────────────────
const PORT = 3001;
const DB_PATH = `${import.meta.dir}/benchmark-10k.db`;
const CORPUS_PATH = `${import.meta.dir}/cases/benchmark-10k-corpus.jsonl`;
const RESULTS_DIR = `${import.meta.dir}/results`;
const RESULTS_JSON = `${RESULTS_DIR}/benchmark-10k.json`;
const RESULTS_MD = `${RESULTS_DIR}/benchmark-10k-summary.md`;
const SERVER_URL = `http://localhost:${PORT}`;
const AGENT_ID = "benchmark-10k";
const HEALTH_TIMEOUT_MS = 30_000;
const REQUEST_TIMEOUT_MS = 30_000;
const BASE_DELAY_MS = 50;
const JUDGE_EXTRA_DELAY_MS = 200;
const PROGRESS_INTERVAL = 100;

// ── Types ────────────────────────────────────────────────────────────────────
interface CorpusCase {
  id: string;
  content: string;
  contentBase64?: string;
  source: string;
  label: "malicious" | "benign";
  formatCategory: string;
  dataset: string;
  attackTypes?: string[];
  notes?: string;
}

interface CaseResult {
  id: string;
  label: "malicious" | "benign";
  action: string;
  riskScore: number;
  latencyMs: number;
  formatCategory: string;
  dataset: string;
  judgeInvoked: boolean;
  judgeRan: boolean;
  error?: string;
}

interface MetricsBucket {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  total: number;
  totalLatency: number;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function newBucket(): MetricsBucket {
  return { tp: 0, fp: 0, tn: 0, fn: 0, total: 0, totalLatency: 0 };
}

function isDetected(action: string): boolean {
  return ["BLOCK", "QUARANTINE", "HUMAN_REVIEW", "SANITIZE"].includes(action);
}

function classify(label: "malicious" | "benign", action: string, bucket: MetricsBucket) {
  const detected = isDetected(action);
  if (label === "malicious" && detected) bucket.tp++;
  else if (label === "malicious" && !detected) bucket.fn++;
  else if (label === "benign" && detected) bucket.fp++;
  else bucket.tn++;
  bucket.total++;
}

function computeMetrics(b: MetricsBucket) {
  const total = b.tp + b.fp + b.tn + b.fn;
  const accuracy = total > 0 ? (b.tp + b.tn) / total : 0;
  const precision = b.tp + b.fp > 0 ? b.tp / (b.tp + b.fp) : 0;
  const recall = b.tp + b.fn > 0 ? b.tp / (b.tp + b.fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const fp_rate = b.fp + b.tn > 0 ? b.fp / (b.fp + b.tn) : 0;
  const avg_latency_ms = b.total > 0 ? Math.round(b.totalLatency / b.total) : 0;
  return { accuracy: round4(accuracy), precision: round4(precision), recall: round4(recall), f1: round4(f1), fp_rate: round4(fp_rate), avg_latency_ms, total, tp: b.tp, fp: b.fp, tn: b.tn, fn: b.fn };
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(n: number): string {
  return (n * 100).toFixed(1) + "%";
}

// ── API Key check ────────────────────────────────────────────────────────────

function checkApiKey(): void {
  if (!process.env.ANTHROPIC_API_KEY && !process.env.OPENROUTER_API_KEY) {
    console.error("❌ No LLM judge API key found. Set ANTHROPIC_API_KEY or OPENROUTER_API_KEY.");
    process.exit(1);
  }
  const provider = process.env.ANTHROPIC_API_KEY ? "Anthropic" : "OpenRouter";
  console.log(`✅ Using ${provider} API key for judge`);
}

// ── Server lifecycle ─────────────────────────────────────────────────────────

let serverProc: Subprocess | null = null;

function startServer(): Subprocess {
  // Clean DB for a fresh run
  if (existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    console.log(`🗑  Deleted existing benchmark DB: ${DB_PATH}`);
  }

  console.log(`🚀 Starting Warden server on port ${PORT}...`);
  const proc = spawn({
    cmd: ["bun", "src/api/index.ts"],
    cwd: `${import.meta.dir}/..`,
    env: {
      ...process.env,
      PORT: String(PORT),
      DB_PATH,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  serverProc = proc;
  return proc;
}

async function waitForHealth(): Promise<void> {
  const deadline = Date.now() + HEALTH_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${SERVER_URL}/metrics`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        console.log(`✅ Server healthy at ${SERVER_URL}`);
        return;
      }
    } catch {
      // Not ready yet
    }
    await Bun.sleep(500);
  }
  throw new Error(`Server did not become healthy within ${HEALTH_TIMEOUT_MS / 1000}s`);
}

async function checkLaya(): Promise<boolean> {
  try {
    const res = await fetch("http://localhost:8111/health", { signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      console.log("✅ Laya sidecar available at localhost:8111");
      return true;
    }
  } catch {
    // Not available
  }
  console.log("ℹ️  Laya sidecar not available — proceeding without it");
  return false;
}

function killServer() {
  if (serverProc) {
    try {
      serverProc.kill();
    } catch {
      // Already dead
    }
    serverProc = null;
    console.log("🛑 Server stopped");
  }
}

// ── Corpus loading ───────────────────────────────────────────────────────────

async function loadCorpus(): Promise<CorpusCase[]> {
  const text = await Bun.file(CORPUS_PATH).text();
  const lines = text.trim().split("\n");
  const cases: CorpusCase[] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      cases.push(JSON.parse(line));
    } catch (e) {
      console.warn(`⚠️  Skipping malformed line: ${(e as Error).message}`);
    }
  }
  return cases;
}

// ── Scanning ─────────────────────────────────────────────────────────────────

async function scanCase(c: CorpusCase): Promise<{ result: any; latencyMs: number }> {
  const body: Record<string, unknown> = {
    source: c.source,
    agentId: AGENT_ID,
  };

  // PDF cases have contentBase64 and empty content
  if (c.contentBase64) {
    body.contentBase64 = c.contentBase64;
  } else {
    body.content = c.content;
  }

  const t0 = performance.now();
  const res = await fetch(`${SERVER_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const latencyMs = performance.now() - t0;
  const result = await res.json();
  return { result, latencyMs };
}

function extractJudgeInfo(trace: any[]): { invoked: boolean; ran: boolean } {
  if (!Array.isArray(trace)) return { invoked: false, ran: false };
  const judgeEntry = trace.find((t: any) => t.stage === "judge");
  if (!judgeEntry) return { invoked: false, ran: false };
  const invoked = !judgeEntry.skipped;
  const ran = invoked && judgeEntry.error !== "judge_unavailable" && judgeEntry.error !== "judge_deferred";
  return { invoked, ran };
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("=" .repeat(70));
  console.log("🛡  WARDEN 10K BENCHMARK");
  console.log("=" .repeat(70));
  console.log(`Timestamp: ${new Date().toISOString()}`);
  console.log();

  // 1. Check API key
  checkApiKey();

  // 2. Start server
  const proc = startServer();
  try {
    await waitForHealth();
    await checkLaya();

    // 3. Load corpus
    console.log(`\n📂 Loading corpus from ${CORPUS_PATH}...`);
    const cases = await loadCorpus();
    console.log(`   Loaded ${cases.length} cases`);

    const attackCount = cases.filter(c => c.label === "malicious").length;
    const benignCount = cases.filter(c => c.label === "benign").length;
    console.log(`   Attack: ${attackCount} | Benign: ${benignCount}`);
    console.log();

    // 4. Scan all cases
    const results: CaseResult[] = [];
    const overall = newBucket();
    const perFormat: Record<string, MetricsBucket> = {};
    const perDataset: Record<string, MetricsBucket> = {};
    let judgeInvokedCount = 0;
    let judgeRanCount = 0;
    let judgeUnavailableCount = 0;
    let errorCount = 0;
    let prevJudgeInvoked = false;

    // Judge accuracy tracking
    const judgeRanResults: { label: string; detected: boolean }[] = [];
    const judgeSkippedResults: { label: string; detected: boolean }[] = [];

    const startTime = performance.now();

    for (let i = 0; i < cases.length; i++) {
      const c = cases[i];

      // Rate limiting
      const delay = BASE_DELAY_MS + (prevJudgeInvoked ? JUDGE_EXTRA_DELAY_MS : 0);
      if (i > 0) await Bun.sleep(delay);

      let caseResult: CaseResult;
      try {
        const { result, latencyMs } = await scanCase(c);
        const action = result.action ?? "ERROR";
        const riskScore = result.riskScore ?? 0;
        const { invoked, ran } = extractJudgeInfo(result.trace);

        caseResult = {
          id: c.id,
          label: c.label,
          action,
          riskScore,
          latencyMs: Math.round(latencyMs),
          formatCategory: c.formatCategory,
          dataset: c.dataset,
          judgeInvoked: invoked,
          judgeRan: ran,
        };

        if (invoked) {
          judgeInvokedCount++;
          if (ran) judgeRanCount++;
          else judgeUnavailableCount++;
        }

        // Classify into buckets
        const detected = isDetected(action);
        classify(c.label, action, overall);
        overall.totalLatency += latencyMs;

        if (!perFormat[c.formatCategory]) perFormat[c.formatCategory] = newBucket();
        classify(c.label, action, perFormat[c.formatCategory]);
        perFormat[c.formatCategory].totalLatency += latencyMs;

        if (!perDataset[c.dataset]) perDataset[c.dataset] = newBucket();
        classify(c.label, action, perDataset[c.dataset]);
        perDataset[c.dataset].totalLatency += latencyMs;

        // Track judge accuracy
        if (invoked && ran) {
          judgeRanResults.push({ label: c.label, detected });
        } else {
          judgeSkippedResults.push({ label: c.label, detected });
        }

        prevJudgeInvoked = invoked;
      } catch (e) {
        errorCount++;
        caseResult = {
          id: c.id,
          label: c.label,
          action: "ERROR",
          riskScore: 0,
          latencyMs: 0,
          formatCategory: c.formatCategory,
          dataset: c.dataset,
          judgeInvoked: false,
          judgeRan: false,
          error: (e as Error).message,
        };
        prevJudgeInvoked = false;
      }

      results.push(caseResult);

      // Progress
      if ((i + 1) % PROGRESS_INTERVAL === 0 || i === cases.length - 1) {
        const elapsed = (performance.now() - startTime) / 1000;
        const rate = (i + 1) / elapsed;
        const eta = (cases.length - i - 1) / rate;
        const currentAcc = overall.total > 0 ? (overall.tp + overall.tn) / overall.total : 0;
        console.log(
          `[${i + 1}/${cases.length}] ` +
          `acc=${pct(currentAcc)} TP=${overall.tp} FP=${overall.fp} TN=${overall.tn} FN=${overall.fn} ` +
          `judge=${judgeInvokedCount}/${i + 1} errs=${errorCount} ` +
          `${rate.toFixed(1)}/s ETA=${Math.round(eta)}s`
        );
      }
    }

    const totalElapsed = (performance.now() - startTime) / 1000;
    console.log(`\n✅ Scanning complete in ${Math.round(totalElapsed)}s (${(totalElapsed / 60).toFixed(1)} min)`);

    // 5. Compute final metrics
    const overallMetrics = {
      ...computeMetrics(overall),
      errors: errorCount,
      attack_count: attackCount,
      benign_count: benignCount,
    };

    const perFormatMetrics: Record<string, ReturnType<typeof computeMetrics>> = {};
    for (const [fmt, bucket] of Object.entries(perFormat)) {
      perFormatMetrics[fmt] = computeMetrics(bucket);
    }

    const perDatasetMetrics: Record<string, ReturnType<typeof computeMetrics>> = {};
    for (const [ds, bucket] of Object.entries(perDataset)) {
      perDatasetMetrics[ds] = computeMetrics(bucket);
    }

    // Judge impact
    const judgeRanCorrect = judgeRanResults.filter(r =>
      (r.label === "malicious" && r.detected) || (r.label === "benign" && !r.detected)
    ).length;
    const judgeSkippedCorrect = judgeSkippedResults.filter(r =>
      (r.label === "malicious" && r.detected) || (r.label === "benign" && !r.detected)
    ).length;

    const judgeStats = {
      invoked: judgeInvokedCount,
      ran: judgeRanCount,
      unavailable: judgeUnavailableCount,
      invocation_rate: round4(cases.length > 0 ? judgeInvokedCount / cases.length : 0),
      accuracy_with_judge: round4(judgeRanResults.length > 0 ? judgeRanCorrect / judgeRanResults.length : 0),
      accuracy_without_judge: round4(judgeSkippedResults.length > 0 ? judgeSkippedCorrect / judgeSkippedResults.length : 0),
    };

    // 6. Write results JSON
    if (!existsSync(RESULTS_DIR)) mkdirSync(RESULTS_DIR, { recursive: true });

    const resultsJson = {
      timestamp: new Date().toISOString(),
      overall: overallMetrics,
      perFormat: perFormatMetrics,
      perDataset: perDatasetMetrics,
      judge: judgeStats,
      cases: results,
    };

    await Bun.write(RESULTS_JSON, JSON.stringify(resultsJson, null, 2));
    console.log(`📊 Results JSON written to ${RESULTS_JSON}`);

    // 7. Write summary markdown
    const summary = generateSummary(resultsJson, totalElapsed, results);
    await Bun.write(RESULTS_MD, summary);
    console.log(`📝 Summary written to ${RESULTS_MD}`);

    // 8. Print headline
    console.log("\n" + "=".repeat(70));
    console.log("HEADLINE RESULTS");
    console.log("=".repeat(70));
    console.log(`Overall Accuracy:  ${pct(overallMetrics.accuracy)}`);
    console.log(`Precision:         ${pct(overallMetrics.precision)}`);
    console.log(`Recall:            ${pct(overallMetrics.recall)}`);
    console.log(`F1:                ${pct(overallMetrics.f1)}`);
    console.log(`FP Rate:           ${pct(overallMetrics.fp_rate)}`);
    console.log(`Avg Latency:       ${overallMetrics.avg_latency_ms}ms`);
    console.log(`Total Cases:       ${overallMetrics.total}`);
    console.log(`Errors:            ${errorCount}`);
    console.log(`Judge Invoked:     ${judgeStats.invoked} (${pct(judgeStats.invocation_rate)})`);
    console.log(`Judge Ran:         ${judgeStats.ran}`);
    console.log(`Judge Unavailable: ${judgeStats.unavailable}`);
    console.log(`Acc with Judge:    ${pct(judgeStats.accuracy_with_judge)}`);
    console.log(`Acc without Judge: ${pct(judgeStats.accuracy_without_judge)}`);
    console.log("=".repeat(70));

  } finally {
    killServer();
  }
}

// ── Summary generation ───────────────────────────────────────────────────────

function generateSummary(data: any, elapsedSec: number, results: CaseResult[]): string {
  const { overall, perFormat, perDataset, judge } = data;
  const ts = data.timestamp;

  let md = `# Warden 10K Benchmark Results\n\n`;
  md += `**Run:** ${ts}  \n`;
  md += `**Duration:** ${Math.round(elapsedSec)}s (${(elapsedSec / 60).toFixed(1)} min)  \n`;
  md += `**Corpus:** ${overall.total} cases (${overall.attack_count} attack, ${overall.benign_count} benign)  \n`;
  md += `**Agent policy:** benchmark-10k (judge enabled, threshold 0.5)  \n\n`;

  // Overall stats
  md += `## Overall Results\n\n`;
  md += `| Metric | Value |\n`;
  md += `|--------|-------|\n`;
  md += `| Accuracy | ${pct(overall.accuracy)} |\n`;
  md += `| Precision | ${pct(overall.precision)} |\n`;
  md += `| Recall | ${pct(overall.recall)} |\n`;
  md += `| F1 Score | ${pct(overall.f1)} |\n`;
  md += `| FP Rate | ${pct(overall.fp_rate)} |\n`;
  md += `| Avg Latency | ${overall.avg_latency_ms}ms |\n`;
  md += `| Total Cases | ${overall.total} |\n`;
  md += `| TP / FP / TN / FN | ${overall.tp} / ${overall.fp} / ${overall.tn} / ${overall.fn} |\n`;
  md += `| Errors | ${overall.errors} |\n\n`;

  // Per-format breakdown
  md += `## Per-Format Breakdown\n\n`;
  md += `| Format | Accuracy | Precision | Recall | F1 | FP Rate | Avg ms | N |\n`;
  md += `|--------|----------|-----------|--------|-----|---------|--------|---|\n`;
  const formats = Object.keys(perFormat).sort();
  for (const fmt of formats) {
    const m = perFormat[fmt];
    md += `| ${fmt} | ${pct(m.accuracy)} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.f1)} | ${pct(m.fp_rate)} | ${m.avg_latency_ms}ms | ${m.total} |\n`;
  }
  md += `\n`;

  // Per-dataset breakdown
  md += `## Per-Dataset Breakdown\n\n`;
  md += `| Dataset | Accuracy | Precision | Recall | F1 | FP Rate | Avg ms | N |\n`;
  md += `|---------|----------|-----------|--------|-----|---------|--------|---|\n`;
  const datasets = Object.entries(perDataset as Record<string, any>)
    .sort((a, b) => b[1].total - a[1].total);
  for (const [ds, m] of datasets) {
    md += `| ${ds} | ${pct(m.accuracy)} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.f1)} | ${pct(m.fp_rate)} | ${m.avg_latency_ms}ms | ${m.total} |\n`;
  }
  md += `\n`;

  // Judge impact
  md += `## Judge Impact Analysis\n\n`;
  md += `| Metric | Value |\n`;
  md += `|--------|-------|\n`;
  md += `| Judge Invocations | ${judge.invoked} |\n`;
  md += `| Judge Successful | ${judge.ran} |\n`;
  md += `| Judge Unavailable | ${judge.unavailable} |\n`;
  md += `| Invocation Rate | ${pct(judge.invocation_rate)} |\n`;
  md += `| Accuracy (judge ran) | ${pct(judge.accuracy_with_judge)} |\n`;
  md += `| Accuracy (judge skipped) | ${pct(judge.accuracy_without_judge)} |\n\n`;

  if (judge.unavailable > 0) {
    md += `> ⚠️ **Degraded Results:** ${judge.unavailable} judge calls were unavailable. `;
    md += `Detection may be understated where the judge could not run.\n\n`;
  }

  // Notable findings
  md += `## Notable Findings\n\n`;

  // Highest-confidence FPs
  const fps = results
    .filter(r => r.label === "benign" && isDetected(r.action))
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 10);
  if (fps.length > 0) {
    md += `### Highest-Confidence False Positives\n\n`;
    md += `| Case ID | Action | Risk Score | Format | Dataset |\n`;
    md += `|---------|--------|------------|--------|----------|\n`;
    for (const fp of fps) {
      md += `| ${fp.id} | ${fp.action} | ${fp.riskScore.toFixed(2)} | ${fp.formatCategory} | ${fp.dataset} |\n`;
    }
    md += `\n`;
  }

  // Missed attacks (high-confidence FNs — malicious cases that were allowed)
  const fns = results
    .filter(r => r.label === "malicious" && !isDetected(r.action))
    .sort((a, b) => a.riskScore - b.riskScore)
    .slice(0, 10);
  if (fns.length > 0) {
    md += `### Missed Attacks (False Negatives)\n\n`;
    md += `| Case ID | Action | Risk Score | Format | Dataset |\n`;
    md += `|---------|--------|------------|--------|----------|\n`;
    for (const fn of fns) {
      md += `| ${fn.id} | ${fn.action} | ${fn.riskScore.toFixed(2)} | ${fn.formatCategory} | ${fn.dataset} |\n`;
    }
    md += `\n`;
  }

  // Error cases
  const errors = results.filter(r => r.error);
  if (errors.length > 0) {
    md += `### Errors (${errors.length} total)\n\n`;
    const shown = errors.slice(0, 5);
    for (const e of shown) {
      md += `- **${e.id}** (${e.formatCategory}): ${e.error}\n`;
    }
    if (errors.length > 5) {
      md += `- ... and ${errors.length - 5} more\n`;
    }
    md += `\n`;
  }

  return md;
}

// ── Run ──────────────────────────────────────────────────────────────────────
main().catch((e) => {
  console.error("❌ Benchmark failed:", e);
  killServer();
  process.exit(1);
});
