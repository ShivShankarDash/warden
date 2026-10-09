import { readdir } from "node:fs/promises";
import { scan } from "../src/detect/orchestrator.ts";
import { initWarden } from "../src/init.ts";
import { referenceCount, invalidateReferenceCache } from "../src/detect/similarity.ts";
import { memoryStats } from "../src/store/memory.ts";
import { getDb } from "../src/store/db.ts";
import type { SourceType, AttackType, Action, ScanResult } from "../src/types.ts";

interface EvalCase {
  id: string;
  source: SourceType;
  /** Inline text content. Mutually exclusive with contentFile. */
  content?: string;
  /**
   * Path to a real binary fixture (PDF, DOCX), relative to the repo root. Document
   * sources need this: a plain-text description of a PDF attack never exercises the
   * extractor — extraction throws, the orchestrator falls back to raw text, and the
   * result measures the rules engine instead.
   */
  contentFile?: string;
  label: "malicious" | "benign";
  expected_attacks: AttackType[];
  expected_action: Action;
  notes?: string;
}

interface CaseResult {
  case: EvalCase;
  result: ScanResult;
  correct: boolean;
  latencyMs: number;
}

const ALL_ATTACKS: AttackType[] = [
  "instruction_override", "role_change", "secret_extraction", "tool_abuse",
  "credential_theft", "context_poisoning", "multi_step_jailbreak",
  "encoded_instructions", "indirect_injection",
];

const ALL_SOURCES: SourceType[] = [
  "user_message", "html", "email", "pdf", "docx", "markdown",
  "api_json", "code", "ocr_text", "image", "mcp_tool_description", "a2a_message",
];

function percentile(sorted: number[], p: number): number {
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)] ?? 0;
}

async function loadCases(): Promise<EvalCase[]> {
  const files = (await readdir("eval/cases")).filter((f) => f.endsWith(".json"));
  const cases: EvalCase[] = [];
  for (const file of files) {
    const text = await Bun.file(`eval/cases/${file}`).text();
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) cases.push(...parsed);
  }
  return cases;
}

async function main() {
  console.log("\nWARDEN EVAL — " + new Date().toISOString());
  await initWarden();

  // The learning loop writes confirmed attacks into attack_reference during the run,
  // so without clearing it each eval starts from whatever the last one left behind
  // and the numbers drift. Measure from a known state unless explicitly asked not to.
  const keepReferences = process.env.EVAL_KEEP_REFERENCES === "1";
  const startingReferences = referenceCount();
  if (!keepReferences && startingReferences > 0) {
    getDb().run("DELETE FROM attack_reference");
    getDb().run("DELETE FROM memory");
    invalidateReferenceCache();
    console.log(`Cleared ${startingReferences} learned references for a reproducible run.`);
    console.log(`(set EVAL_KEEP_REFERENCES=1 to measure with a warm reference set instead)`);
  } else if (keepReferences) {
    console.log(`Starting with a warm reference set: ${startingReferences} entries.`);
  }
  const cases = await loadCases();
  if (!cases.length) {
    console.log("No eval cases found in eval/cases/. Add .json files with case arrays.");
    process.exit(0);
  }

  const attackCases = cases.filter((c) => c.label === "malicious");
  const benignCases = cases.filter((c) => c.label === "benign");
  console.log(`Cases: ${cases.length} | Attack: ${attackCases.length} | Benign: ${benignCases.length}`);
  console.log("─".repeat(70));

  const results: CaseResult[] = [];
  for (const c of cases) {
    const payload: string | Uint8Array = c.contentFile
      ? new Uint8Array(await Bun.file(c.contentFile).arrayBuffer())
      : (c.content ?? "");

    const t0 = performance.now();
    const result = await scan({ content: payload, source: c.source, agentId: "eval" }).catch((e) => ({
      id: "error",
      action: "ALLOW" as Action,
      findings: [],
      riskScore: 0,
      trace: [{ stage: "total", ms: 0, error: String(e) }],
      createdAt: Date.now(),
    }));
    const ms = performance.now() - t0;

    const detected =
      c.label === "malicious"
        ? result.action !== "ALLOW"
        : result.action === "ALLOW";

    results.push({ case: c, result, correct: detected, latencyMs: ms });
    process.stdout.write(detected ? "." : "F");
  }
  console.log("\n");

  // Attack × source matrix
  console.log("ATTACK DETECTION MATRIX (detection rate %)");
  const srcLabel = ALL_SOURCES.map((s) => s.slice(0, 8).padEnd(9)).join(" ");
  console.log("                      " + srcLabel);

  for (const attack of ALL_ATTACKS) {
    const row = ALL_SOURCES.map((src) => {
      const relevant = results.filter(
        (r) => r.case.label === "malicious" && r.case.expected_attacks.includes(attack) && r.case.source === src
      );
      if (!relevant.length) return "  -    ";
      const detected = relevant.filter((r) => r.correct).length;
      const pct = Math.round((detected / relevant.length) * 100);
      return `${String(pct).padStart(3)}%   `;
    });
    console.log(attack.slice(0, 21).padEnd(22) + row.join(" "));
  }

  console.log("\n" + "─".repeat(70));

  // False-positive rate
  const fpCases = results.filter((r) => r.case.label === "benign" && !r.correct);
  const fpRate = benignCases.length ? (fpCases.length / benignCases.length) * 100 : 0;
  console.log(`FALSE POSITIVE RATE: ${fpRate.toFixed(1)}% (${fpCases.length}/${benignCases.length} benign flagged)`);
  if (fpCases.length) {
    for (const fp of fpCases.slice(0, 5)) {
      console.log(`  FP: ${fp.case.id} — action=${fp.result.action}`);
    }
  }

  console.log("\n" + "─".repeat(70));

  // Latency
  console.log("LATENCY (p50 / p95 ms)");
  const stageNames = ["extract", "decode", "rules", "classifier", "similarity", "judge", "session", "total"];
  for (const stage of stageNames) {
    const stageTimes = results
      .flatMap((r) => r.result.trace.filter((t) => t.stage === stage && !t.skipped).map((t) => t.ms))
      .sort((a, b) => a - b);
    if (!stageTimes.length) {
      console.log(`  ${stage.padEnd(12)} -`);
    } else {
      const p50 = percentile(stageTimes, 50).toFixed(1);
      const p95 = percentile(stageTimes, 95).toFixed(1);
      console.log(`  ${stage.padEnd(12)} ${p50} / ${p95}`);
    }
  }

  console.log("\n" + "─".repeat(70));

  // Judge health. A judge outage silently depresses detection and inflates the FP
  // rate, and the run otherwise looks completely normal — so say so loudly.
  const judgeTraces = results.flatMap((r) => r.result.trace.filter((t) => t.stage === "judge"));
  const judgeInvoked = judgeTraces.filter((t) => !t.skipped);
  const judgeFailed = judgeInvoked.filter((t) => t.error === "judge_unavailable");
  const judgeOk = judgeInvoked.length - judgeFailed.length;
  const judgeRate = cases.length ? (judgeInvoked.length / cases.length) * 100 : 0;

  console.log(
    `JUDGE: ${judgeOk} verdicts, ${judgeFailed.length} unavailable, ` +
      `${judgeInvoked.length}/${cases.length} cases referred (${judgeRate.toFixed(1)}%)`
  );
  if (judgeFailed.length) {
    console.log(
      `  *** RESULTS DEGRADED — ${judgeFailed.length} judge calls returned no verdict. ***\n` +
        `  *** Detection is understated and the FP rate overstated. Do not compare this run. ***`
    );
  } else if (judgeRate > 20) {
    console.log(`  Note: judge referral rate above the 20% target in specs/04-detect.md.`);
  }

  // Count probation as well as active. referenceCount() reports only active entries,
  // and everything learned automatically starts on probation — so reading it alone
  // shows zero and makes a working learning loop look broken.
  const mem = memoryStats("eval");
  const learned = mem.attack.active + mem.attack.probation - (keepReferences ? startingReferences : 0);
  console.log(
    `LEARNED: ${learned} attack memories added this run ` +
      `(${mem.attack.active} active, ${mem.attack.probation} on probation until seen again)`
  );

  console.log("\n" + "─".repeat(70));

  // Overall
  const totalCorrect = results.filter((r) => r.correct).length;
  console.log(`OVERALL ACCURACY: ${((totalCorrect / results.length) * 100).toFixed(1)}% (${totalCorrect}/${results.length})`);

  // Save results
  const outPath = `eval/results/${new Date().toISOString().slice(0, 10)}.json`;
  await Bun.write(outPath, JSON.stringify({
    summary: {
      total: cases.length,
      correct: totalCorrect,
      fp: fpCases.length,
      judgeVerdicts: judgeOk,
      judgeUnavailable: judgeFailed.length,
      degraded: judgeFailed.length > 0,
    },
    results: results.map((r) => ({ id: r.case.id, label: r.case.label, correct: r.correct, action: r.result.action, latencyMs: r.latencyMs })),
  }, null, 2));
  console.log(`\nResults saved to ${outPath}`);
}

main().catch(console.error);
