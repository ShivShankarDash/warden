import { randomUUID } from "crypto";
import type { ScanRequest, ScanResult, Finding, Action, SourceType } from "../types.ts";
import { extract } from "../extract/index.ts";
import { sniff, formatMismatch, isUnscannable } from "../extract/sniff.ts";
import { decode } from "../decode/index.ts";
import { applyRules, suspectsJailbreak } from "./rules.ts";
import { classify } from "./classifier.ts";
import { classifyWithLaya } from "./laya.ts";
import { similarityCheck } from "./similarity.ts";
import { judge, judgeDeferred, shouldDeferJudge } from "./judge.ts";
import { updateSession, type SessionAssessment } from "./session.ts";
import { addReference } from "./similarity.ts";
import { loadPolicy, failModeFor } from "../policy/loader.ts";
import { reputationAdjustment, recordObservation } from "../store/reputation.ts";
import { recordCoverageOutcome } from "../store/coverage.ts";

/** Matches the session tracker's own suspicion floor — a turn that contributed
 *  nothing to session risk should not be punished by it either. */
const SESSION_ESCALATION_FLOOR = 0.25;

/** Judge confidence at which a verdict is trustworthy enough to learn from.
 *  Set high: a wrong entry in the reference set poisons every future lookup. */
const LEARN_THRESHOLD = Number(process.env.LEARN_THRESHOLD ?? 0.85);

/** Most risk a safe-memory match may subtract. Bounded so resemblance to cleared
 *  content can soften a verdict but never silence a confident one. */
const SAFE_SUPPRESSION_MAX = Number(process.env.SAFE_SUPPRESSION_MAX ?? 0.4);

const SEVERITY: Record<Action, number> = {
  ALLOW: 0, SPOTLIGHT: 1, SANITIZE: 2, HUMAN_REVIEW: 3, QUARANTINE: 4, BLOCK: 5,
};

const INDIRECT_SOURCES: SourceType[] = [
  "html", "email", "pdf", "docx", "markdown", "api_json", "code",
  "ocr_text", "image", "mcp_tool_description", "a2a_message",
];

function dedupeByAttackType(findings: Finding[]): Finding[] {
  const byType = new Map<string, Finding>();
  for (const f of findings) {
    const existing = byType.get(f.attackType);
    if (!existing || f.confidence > existing.confidence) byType.set(f.attackType, f);
  }
  return [...byType.values()];
}

function determineAction(
  riskScore: number,
  source: SourceType,
  findings: Finding[],
  highConfidence: number
): Action {
  if (riskScore >= highConfidence) return "BLOCK";
  if (riskScore >= highConfidence - 0.1) return "QUARANTINE";
  if (riskScore >= 0.5) return "HUMAN_REVIEW";
  const hasSpans = findings.some((f) => f.spans.length > 0);
  const isIndirect = INDIRECT_SOURCES.includes(source);
  if (riskScore >= 0.3 && hasSpans) return "SANITIZE";
  if (riskScore >= 0.15 && isIndirect) return "SPOTLIGHT";
  return "ALLOW";
}

export async function scan(req: ScanRequest): Promise<ScanResult> {
  const startTotal = performance.now();
  const scanId = randomUUID();
  const findings: Finding[] = [];
  const trace: ScanResult["trace"] = [];

  // Per-agent policy drives every threshold below. Falls back to DEFAULT_POLICY when
  // the agent has no file, so an unconfigured agent still gets sane behaviour.
  const policy = await loadPolicy(req.agentId ?? "default");
  const {
    highConfidence: HIGH_CONFIDENCE,
    judge: JUDGE_THRESHOLD,
    session: SESSION_THRESHOLD,
    benignCertainty: BENIGN_CERTAINTY_THRESHOLD,
    classifier: CLASSIFIER_THRESHOLD,
    similarity: SIMILARITY_THRESHOLD,
    rules: RULES_THRESHOLD,
  } = policy.thresholds;
  const failMode = failModeFor(policy, req.source);
  const JUDGE_MODE = policy.judgeMode ?? "sync";

  // Stage 1: Extract.
  // The declared source is a caller assertion. Its *format* half can be checked
  // against the bytes, so a wrong declaration routes to the wrong parser and loses
  // hidden content. Parse by what the content actually is; keep the declared source
  // for trust decisions, which sniffing cannot verify.
  const t0 = performance.now();
  const sniffed = sniff(req.content);
  const mismatched = formatMismatch(req.source, sniffed);

  // Archives, executables and media have nothing a text scanner can read. Decoding
  // them as UTF-8 yields replacement characters that still traverse every stage — a
  // 3KB PNG cost 1178ms and found nothing. Stop here rather than pay that, and flag
  // it, because binary arriving where text was declared is itself worth knowing.
  if (isUnscannable(sniffed)) {
    trace.push({
      stage: "extract",
      ms: performance.now() - t0,
      skipped: false,
      error: `unscannable_binary: declared ${req.source}, content is binary — not text-scannable`,
    });
    trace.push({ stage: "total", ms: performance.now() - startTotal });
    return {
      id: scanId,
      // Not an endorsement: nothing was scanned. The caller decides what to do with
      // a binary it did not expect, and the trace says why no analysis happened.
      action: mismatched ? "SPOTLIGHT" : "ALLOW",
      findings: mismatched
        ? [{
            attackType: "indirect_injection" as const,
            confidence: 0.2,
            stage: "extract" as const,
            spans: [],
            reason: `Binary content supplied where ${req.source} was declared; not scannable as text`,
          }]
        : [],
      riskScore: 0,
      trace,
      createdAt: Date.now(),
    };
  }

  const parseAs: SourceType =
    mismatched && sniffed !== "text" ? (sniffed as SourceType) : req.source;

  const extracted = await extract(req.content, parseAs).catch((e) => {
    trace.push({ stage: "extract", ms: performance.now() - t0, error: String(e), skipped: false });
    return null;
  });
  if (extracted) {
    trace.push({
      stage: "extract",
      ms: performance.now() - t0,
      skipped: false,
      ...(mismatched
        ? { error: `declared_source_mismatch: declared ${req.source}, content looks like ${sniffed}; parsed as ${parseAs}` }
        : {}),
    });
  }

  const fullText = extracted
    ? [extracted.visibleText, extracted.hiddenText].filter(Boolean).join("\n")
    : typeof req.content === "string"
    ? req.content
    : new TextDecoder().decode(req.content);

  // Stage 2: Decode
  const t1 = performance.now();
  const decoded = decode(fullText);
  trace.push({ stage: "decode", ms: performance.now() - t1, skipped: false });
  const scanText = decoded.text;

  // Stage 3: Rules
  // Run over the raw text too — decode() strips invisible Unicode and unwraps
  // encodings, so smuggling artifacts are gone from scanText by this point.
  const t2 = performance.now();
  const ruleFindings = dedupeByAttackType([
    ...applyRules(scanText, req.source),
    ...(scanText === fullText ? [] : applyRules(fullText, req.source)),
  ]).filter((f) => f.confidence >= RULES_THRESHOLD);
  findings.push(...ruleFindings);
  const ruleScore = ruleFindings.length ? Math.max(...ruleFindings.map((f) => f.confidence)) : 0;
  trace.push({ stage: "rules", ms: performance.now() - t2, score: ruleScore, skipped: false });

  // Stage 4: Classifier (Laya primary, Prompt Guard 2 fallback)
  let classifierScore = 0;
  let benignScore: number | null = null;
  let layaSkipJudge = false;
  if (ruleScore < HIGH_CONFIDENCE) {
    const t3 = performance.now();

    // Try Laya first; fall back to Prompt Guard 2 if the sidecar is down.
    const laya = await classifyWithLaya(scanText, CLASSIFIER_THRESHOLD).catch(
      () => ({ findings: [] as Finding[], benignScore: null, injectionProbability: 0 })
    );

    let clf: { findings: Finding[]; benignScore: number | null };
    if (laya.injectionProbability === 0 && laya.benignScore === null) {
      // Laya unavailable — fall back to Prompt Guard 2.
      clf = await classify(scanText, CLASSIFIER_THRESHOLD).catch(
        () => ({ findings: [] as Finding[], benignScore: null })
      );
    } else {
      // Laya responded — use its result.
      clf = laya;
      // When Laya is confident, the judge adds latency without improving
      // accuracy. The base model's probabilities are well-calibrated (unlike
      // the fine-tuned checkpoint), so these thresholds are safe.
      // IMPORTANT: only skip when Laya and rules agree. If rules fire high
      // but Laya says benign (NotInject pattern), the judge must arbitrate.
      if (laya.injectionProbability > 0.85) {
        layaSkipJudge = true;  // confident attack — skip judge
      } else if (laya.injectionProbability < 0.15 && ruleScore < 0.3) {
        layaSkipJudge = true;  // confident benign AND rules agree — skip judge
      }
      // Otherwise: Laya and rules disagree, or both uncertain → judge runs
    }

    findings.push(...clf.findings);
    benignScore = clf.benignScore;
    classifierScore = clf.findings.length ? Math.max(...clf.findings.map((f) => f.confidence)) : 0;
    trace.push({ stage: "classifier", ms: performance.now() - t3, score: classifierScore, skipped: false });
  } else {
    trace.push({ stage: "classifier", ms: 0, skipped: true });
  }

  // Stage 5: Similarity, against both learned attacks and human-cleared safe examples.
  const combinedScore = Math.max(ruleScore, classifierScore);
  let similarityScore = 0;
  let safeMatch = 0;
  if (combinedScore < HIGH_CONFIDENCE) {
    const t4 = performance.now();
    const sim = await similarityCheck(scanText, SIMILARITY_THRESHOLD, req.agentId ?? "default").catch(
      () => ({ findings: [] as Finding[], safeMatch: 0 })
    );
    findings.push(...sim.findings);
    safeMatch = sim.safeMatch;
    similarityScore = sim.findings.length ? Math.max(...sim.findings.map((f) => f.confidence)) : 0;
    trace.push({ stage: "similarity", ms: performance.now() - t4, score: similarityScore, skipped: false });
  } else {
    trace.push({ stage: "similarity", ms: 0, skipped: true });
  }

  // Stage 6: Judge (LLM) — only if uncertain.
  // Also escalate when upstream found nothing but the text looks like a direct-channel
  // jailbreak: those carry no lexical signature and Prompt Guard 2 is scoped to ignore
  // them, so without this referral the judge would never see the cases it exists for.
  const preJudgeScore = Math.max(ruleScore, classifierScore, similarityScore);
  const inUncertainBand = preJudgeScore >= JUDGE_THRESHOLD && preJudgeScore < HIGH_CONFIDENCE;

  // The classifier hedging is itself a signal. Benign text scores ~0.999 benign in
  // every language, so a weaker clearance means the model has no confident opinion
  // rather than that the content is safe — which is exactly the case for phrasings
  // outside its training distribution. Unlike a language check this also covers
  // adversarial suffixes and novel wordings.
  const classifierUncertain =
    benignScore !== null && benignScore < BENIGN_CERTAINTY_THRESHOLD;
  const referred =
    preJudgeScore < JUDGE_THRESHOLD && (suspectsJailbreak(scanText) || classifierUncertain);

  /*
   * On judgeMode, and what deferring the judge actually costs.
   *
   * Sync is the default because the judge is authoritative here: it is the only stage
   * that can *lower* a score, and that acquittal power is what holds the measured
   * false-positive rate at zero. Deferring it is not a free latency win — it changes
   * the security properties in two directions, and both are real:
   *
   *  1. Referred-but-quiet content (preJudgeScore < 0.5, referred by a jailbreak
   *     trigger or classifier hedging) resolves inline to ALLOW/SPOTLIGHT. In sync
   *     mode the judge may catch it; in async mode the FIRST instance of such an
   *     attack is released. The learning loop closes the door behind it — the next
   *     instance is matched by similarity at ~1ms — but the first one got through.
   *     This is the exposure async buys, and deferredJudgeStats().missedInline
   *     counts it rather than hiding it.
   *
   *  2. Uncertain-band content (0.5 ≤ score < 0.9) is already held at HUMAN_REVIEW or
   *     QUARANTINE, so deferring costs nothing in containment. It costs accuracy in
   *     the other direction: the judge is not there to acquit, so false positives
   *     that sync would clear now reach a human instead.
   *
   * The deferred verdict never retroactively downgrades the inline action. By the
   * time it lands the result has gone to the caller and been acted on; a late
   * "actually that was fine" is unactionable, while a late "that was an attack" is
   * worth recording and learning from. Asymmetric on purpose.
   *
   * JUDGE_ALWAYS_SYNC in judge.ts overrides this per source for cases where (1) is
   * unacceptable.
   */
  const judgeEvidence = {
    decodingApplied: decoded.decodingApplied,
    ruleHits: ruleFindings.map((f) => f.reason),
  };

  let judgeScore = 0;
  let judgeRan = false;
  // Set when the judge was referred but deferred. The deferred call is fired at the
  // end of scan(), once the inline action is known — the audit record is only
  // meaningful if it says what was returned to the caller in the meantime.
  let judgeDeferredToBackground = false;

  if ((inUncertainBand || referred) && !layaSkipJudge) {
    const t5 = performance.now();

    if (shouldDeferJudge(JUDGE_MODE, req.source)) {
      judgeDeferredToBackground = true;
      trace.push({
        stage: "judge",
        ms: performance.now() - t5,
        score: 0,
        skipped: false,
        // Third distinct state, alongside a verdict and "judge_unavailable". A reader
        // must be able to tell "deferred, not yet ruled" from "ran and found nothing".
        error: "judge_deferred",
      });
    } else {
      const res = await judge(scanText, req.source, judgeEvidence).catch(() => ({
        ran: false,
        findings: [] as Finding[],
      }));
      judgeRan = res.ran;
      findings.push(...res.findings);
      judgeScore = res.findings.length ? Math.max(...res.findings.map((f) => f.confidence)) : 0;

      // Close the learning loop: a confirmed attack joins the reference set, so the
      // next variant is matched by the similarity stage in ~2ms rather than costing
      // another judge call. Fire-and-forget — this must never delay the verdict.
      if (res.ran && judgeScore >= LEARN_THRESHOLD) {
        const confirmed = res.findings[0];
        void addReference(scanText, confirmed.attackType, req.source, {
          origin: "judge",
          agentId: req.agentId ?? "default",
          sourceId: req.sourceId,
        }).catch(() => {});
      }
      trace.push({
        stage: "judge",
        ms: performance.now() - t5,
        score: judgeScore,
        skipped: false,
        // Distinguishes "ran and acquitted" from "never reached a verdict". Without this
        // an outage looks identical to a clean run in the results.
        ...(res.ran ? {} : { error: "judge_unavailable" }),
      });
    }
  } else {
    trace.push({ stage: "judge", ms: 0, skipped: true });
  }

  // The judge only ever adjudicates cases the earlier stages left uncertain — anything
  // at or above HIGH_CONFIDENCE short-circuits before it. So when it reaches a verdict,
  // that verdict wins. max() would make the judge able to escalate but never acquit,
  // which is what specs/04-detect.md asks for when it says later stages should "push
  // the combined score down below the block threshold".
  const rawRisk = judgeRan
    ? judgeScore
    : Math.max(ruleScore, classifierScore, similarityScore);

  // A human-cleared lookalike is exculpatory. Relief scales with how close the match
  // is and is capped, so a loose resemblance cannot wave content through — and it
  // never applies at or above HIGH_CONFIDENCE, so a confident detection stands no
  // matter what the content resembles. Without that bound, getting one benign-looking
  // payload into safe memory would be enough to disarm the whole pipeline.
  let riskScore = rawRisk;

  // Reputation nudges content that already looks borderline. It is clamped below
  // HIGH_CONFIDENCE so a bad record can never on its own push something to BLOCK —
  // otherwise poisoning one identity's history would be enough to block unrelated
  // content from it, and a long-clean identity would become a smuggling channel.
  const reputation = reputationAdjustment(req.sourceId, req.agentId ?? "default");
  if (reputation.delta !== 0 && rawRisk > 0) {
    const adjusted = Math.max(0, Math.min(HIGH_CONFIDENCE - 0.01, rawRisk + reputation.delta));
    if (adjusted !== riskScore) {
      trace.push({
        stage: "session",
        ms: 0,
        score: adjusted,
        skipped: false,
        error: `reputation: ${rawRisk.toFixed(2)} -> ${adjusted.toFixed(2)} — ${reputation.reason}`,
      });
    }
    riskScore = adjusted;
  }

  if (safeMatch >= SIMILARITY_THRESHOLD && riskScore < HIGH_CONFIDENCE) {
    const before = riskScore;
    const relief =
      SAFE_SUPPRESSION_MAX * ((safeMatch - SIMILARITY_THRESHOLD) / (1 - SIMILARITY_THRESHOLD));
    riskScore = Math.max(0, before - relief);
    if (riskScore < before) {
      trace.push({
        stage: "similarity",
        ms: 0,
        score: riskScore,
        skipped: false,
        error: `safe_memory_relief: ${before.toFixed(2)} -> ${riskScore.toFixed(2)} (matched a human-cleared example at ${safeMatch.toFixed(3)})`,
      });
    }
  }

  // Stage 7: Session — runs after the per-message stages so this turn's final risk,
  // including the judge's verdict, feeds into it. Needs a sessionId; single-shot scans skip it.
  const t6 = performance.now();
  let sessionRisk: number | undefined;
  let sessionEscalation: SessionAssessment | null = null;
  if (req.sessionId) {
    sessionEscalation = updateSession(
      req.sessionId,
      req.agentId,
      riskScore,
      findings,
      SESSION_THRESHOLD
    );
    sessionRisk = sessionEscalation.sessionRisk;
    if (sessionEscalation.escalate) {
      findings.push({
        attackType: "multi_step_jailbreak",
        confidence: sessionEscalation.sessionRisk,
        stage: "session",
        spans: [],
        reason: sessionEscalation.reason,
      });
    }
    trace.push({ stage: "session", ms: performance.now() - t6, score: sessionRisk, skipped: false });
  } else {
    trace.push({ stage: "session", ms: 0, skipped: true });
  }

  // A session-level pattern can raise the action for an otherwise unremarkable turn,
  // which is the whole point: no single Crescendo turn justifies blocking on its own.
  // It never lowers it, and never escalates past QUARANTINE — the evidence is a
  // trajectory rather than anything in this specific message.
  //
  // It only applies when this turn is itself at least mildly suspicious. Session risk
  // modulates borderline content; it must not condemn content with no evidence against
  // it at all, or a single detection would quarantine every clean message that follows
  // until the accumulator decays. Crescendo turns always clear this bar — they sit at
  // 0.30-0.45 from the multi-step rules — so detection is unaffected.
  let action = determineAction(riskScore, req.source, findings, HIGH_CONFIDENCE);
  if (
    sessionEscalation?.escalate &&
    riskScore >= SESSION_ESCALATION_FLOOR &&
    SEVERITY[action] < SEVERITY.QUARANTINE
  ) {
    action = "QUARANTINE";
  }

  // Record the outcome against the sender's identity so the next message from them
  // is weighed with this one in mind.
  if (req.sourceId) {
    recordObservation(req.sourceId, action !== "ALLOW", req.agentId ?? "default");
  }

  // Learn from attacks the fast stages caught outright.
  //
  // Learning used to require a judge verdict, which meant the clearest attacks taught
  // Warden nothing: anything scoring >= HIGH_CONFIDENCE on rules short-circuits the
  // judge entirely. The tempting reading is "why memorise what rules already catch" —
  // but a robustness sweep showed two missing homoglyph characters let 55% of known
  // attacks through. Rules match surface forms and are brittle to obfuscation;
  // embeddings match meaning and are not. Storing the canonical attack is what catches
  // the reworded variant the pattern misses.
  //
  // Deliberately excluded: findings from the similarity stage itself, which would be
  // circular — memory confirming memory, with drift and no outside signal.
  const learnable = findings.find(
    (f) =>
      (f.stage === "rules" || f.stage === "classifier") && f.confidence >= LEARN_THRESHOLD
  );
  if (learnable && SEVERITY[action] >= SEVERITY.QUARANTINE) {
    void addReference(scanText, learnable.attackType, req.source, {
      origin: "rules",
      agentId: req.agentId ?? "default",
      sourceId: req.sourceId,
    }).catch(() => {});
  }

  // Fire the deferred judge now that the inline action is settled. It cannot change
  // this result — that has already been decided — but it feeds the learning loop so
  // the next instance is caught inline, and records what was released in the meantime.
  if (judgeDeferredToBackground) {
    judgeDeferred(scanText, req.source, judgeEvidence, {
      scanId,
      source: req.source,
      inlineAction: action,
      inlineRisk: riskScore,
      learnThreshold: LEARN_THRESHOLD,
      onConfirmed: (text, attackType, source) => {
        void addReference(text, attackType, source, {
          origin: "judge",
          agentId: req.agentId ?? "default",
          sourceId: req.sourceId,
        }).catch(() => {});
      },
    });
  }

  // Coverage tracking: record a detection outcome for each unique attack type found.
  // Only fires when findings carry attack types — a clean ALLOW with no findings is
  // not recorded. detected=true when the action is BLOCK, QUARANTINE, or HUMAN_REVIEW.
  const attackTypesInFindings = [
    ...new Set(findings.map((f) => f.attackType).filter(Boolean)),
  ];
  if (attackTypesInFindings.length > 0) {
    const wasDetected = SEVERITY[action] >= SEVERITY.HUMAN_REVIEW;
    const agentId = req.agentId ?? "default";
    for (const at of attackTypesInFindings) {
      recordCoverageOutcome(at, wasDetected, agentId);
    }
  }

  trace.push({ stage: "total", ms: performance.now() - startTotal });

  return {
    id: scanId,
    action,
    findings,
    riskScore,
    sessionRisk,
    ...(judgeDeferredToBackground ? { judgePending: true } : {}),
    trace,
    createdAt: Date.now(),
  };
}
