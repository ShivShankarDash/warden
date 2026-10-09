/**
 * Verdict explainer — generates human-readable explanations for scan results.
 *
 * Two modes:
 *  - **fast** (default): pure template logic, no network calls, works without any LLM
 *    configuration. Suitable for real-time display and audit logs.
 *  - **rich**: sends a summary to the LLM for a polished, non-technical explanation.
 *    Falls back to fast mode when no provider is configured or the call fails.
 *
 * Content is ALWAYS truncated to 200 characters max to prevent data leakage through
 * explanation strings.
 */

import type { ScanResult, Finding, Action, AttackType } from "../types.ts";
import type { Reputation } from "../store/reputation.ts";

// ─── Action verb map ─────────────────────────────────────────────────────────

const ACTION_VERB: Record<Action, string> = {
  BLOCK: "BLOCKED",
  ALLOW: "ALLOWED",
  QUARANTINE: "QUARANTINED",
  HUMAN_REVIEW: "FLAGGED FOR HUMAN REVIEW",
  SANITIZE: "SANITIZED",
  SPOTLIGHT: "SPOTLIGHTED",
};

// ─── Attack type readable labels (mirrors dashboard/shared.ts) ───────────────

const ATTACK_LABEL: Record<AttackType, string> = {
  instruction_override: "Instruction override",
  role_change: "Role change",
  secret_extraction: "Secret extraction",
  tool_abuse: "Tool abuse",
  credential_theft: "Credential theft",
  context_poisoning: "Context poisoning",
  multi_step_jailbreak: "Multi-step jailbreak",
  encoded_instructions: "Encoded instructions",
  indirect_injection: "Indirect injection",
};

function attackLabel(t: string): string {
  return ATTACK_LABEL[t as AttackType] ?? t.replace(/_/g, " ");
}

// ─── Content truncation ─────────────────────────────────────────────────────

export function truncateContent(content: string, max = 200): string {
  if (content.length <= max) return content;
  return content.slice(0, max) + "…";
}

// ─── LLM provider (same env-var precedence as redteam/provider.ts) ──────────

type Provider = {
  kind: "anthropic" | "openai";
  apiKey: string;
  baseUrl: string;
  model: string;
  workspaceId?: string;
};

function getProvider(): Provider | null {
  const anthropic = process.env.ANTHROPIC_API_KEY;
  if (anthropic) {
    return {
      kind: "anthropic",
      apiKey: anthropic,
      baseUrl: process.env.JUDGE_BASE_URL ?? "https://api.anthropic.com/v1",
      model: process.env.JUDGE_MODEL ?? "claude-haiku-4-5-20251001",
      workspaceId: process.env.ANTHROPIC_WORKSPACE_ID,
    };
  }
  const openai = process.env.OPENROUTER_API_KEY ?? process.env.OPENAI_API_KEY;
  if (openai) {
    return {
      kind: "openai",
      apiKey: openai,
      baseUrl: process.env.JUDGE_BASE_URL ?? "https://openrouter.ai/api/v1",
      model: process.env.JUDGE_MODEL ?? "anthropic/claude-haiku-4.5",
    };
  }
  return null;
}

// ─── Public API ──────────────────────────────────────────────────────────────

export interface ExplainOpts {
  mode?: "fast" | "rich";
  includeContent?: boolean;
  reputation?: Reputation | null;
  sessionInfo?: { turnCount: number; sessionRisk: number } | null;
}

/**
 * Generate a human-readable explanation for a scan verdict.
 *
 * In **fast** mode (default), the explanation is built from templates — no LLM, no
 * network, no external dependencies. In **rich** mode, an LLM is called for a
 * polished version; on failure the function silently falls back to fast mode.
 */
export async function explainVerdict(
  result: ScanResult,
  content: string,
  opts?: ExplainOpts,
): Promise<string> {
  const mode = opts?.mode ?? "fast";

  if (mode === "rich") {
    return richExplain(result, content, opts);
  }
  return fastExplain(result, content, opts);
}

// ─── Fast mode (template) ───────────────────────────────────────────────────

function fastExplain(
  result: ScanResult,
  content: string,
  opts?: ExplainOpts,
): string {
  const lines: string[] = [];

  // (a) HEADLINE
  lines.push(buildHeadline(result));

  // (b) DETAIL
  lines.push(...buildDetail(result));

  // (c) DETECTION PATH
  const pathLine = buildDetectionPath(result);
  if (pathLine) lines.push(pathLine);

  // (d) REPUTATION
  if (opts?.reputation && opts.reputation.total > 0) {
    lines.push(
      `Source reputation: ${opts.reputation.sourceId} has ${opts.reputation.attacks} prior attack(s) in ${opts.reputation.total} observations.`,
    );
  }

  // (e) SESSION
  if (opts?.sessionInfo) {
    lines.push(
      `Session risk: ${opts.sessionInfo.sessionRisk.toFixed(2)} (${opts.sessionInfo.turnCount} turns in this conversation).`,
    );
  }

  // (f) CONTENT EXCERPT
  if (opts?.includeContent) {
    lines.push(`Content excerpt: "${truncateContent(content, 200)}"`);
  }

  return lines.join("\n");
}

function buildHeadline(result: ScanResult): string {
  const verb = ACTION_VERB[result.action];

  if (result.action === "ALLOW") {
    return `${verb}: Content is clean (risk score ${result.riskScore.toFixed(2)}).`;
  }

  // For non-ALLOW actions, summarise the top finding(s).
  const types = [...new Set(result.findings.map((f) => attackLabel(f.attackType)))];
  const topConf = result.findings.length
    ? Math.max(...result.findings.map((f) => f.confidence))
    : 0;
  const confPct = Math.round(topConf * 100);

  const typeSummary = types.length ? types.join(", ") : "suspicious content";
  return `${verb}: Detected ${typeSummary} (${confPct}% confidence).`;
}

function buildDetail(result: ScanResult): string[] {
  const lines: string[] = [];

  if (result.action === "ALLOW") {
    lines.push("All detection stages cleared this content.");
  } else {
    // Show top finding detail: stage, spans
    for (const f of result.findings) {
      const spanTexts = f.spans
        .map((s) => truncateContent(s.text, 80))
        .filter(Boolean);
      const spanStr = spanTexts.length ? ` — flagged: "${spanTexts.join('", "')}"` : "";
      lines.push(
        `${attackLabel(f.attackType)} detected by ${f.stage} stage (${Math.round(f.confidence * 100)}% confidence)${spanStr}.`,
      );
    }
  }

  // Trace summary — one line per stage
  for (const t of result.trace) {
    const status = t.skipped
      ? "skipped"
      : t.error
        ? `error: ${t.error}`
        : t.score != null
          ? `score ${t.score.toFixed(2)}`
          : "ran";
    lines.push(`  ${t.stage}: ${status} (${t.ms}ms)`);
  }

  return lines;
}

function buildDetectionPath(result: ScanResult): string | null {
  const active = result.trace.filter(
    (t) => !t.skipped && t.score != null && t.score > 0,
  );
  if (active.length === 0) {
    if (result.judgePending) return "Detection path: (judge deferred)";
    return null;
  }

  const parts = active.map((t) => `${t.stage} (${t.score!.toFixed(2)})`);
  const suffix = result.judgePending ? " (judge deferred)" : "";
  return `Detection path: ${parts.join(" -> ")}${suffix}`;
}

// ─── Rich mode (LLM) ───────────────────────────────────────────────────────

const EXPLAINER_SYSTEM = `You are a security analyst explaining why a firewall made a specific decision. Be clear, factual, and concise. Write for a non-technical audience.`;

const TIMEOUT_MS = 15_000;

async function richExplain(
  result: ScanResult,
  content: string,
  opts?: ExplainOpts,
): Promise<string> {
  const provider = getProvider();
  if (!provider) {
    return "[Auto-generated] " + fastExplain(result, content, opts);
  }

  const truncated = truncateContent(content, 200);

  const userPrompt = [
    `Action taken: ${result.action}`,
    `Risk score: ${result.riskScore.toFixed(2)}`,
    `Findings: ${result.findings.length}`,
    result.findings.length
      ? result.findings
          .map(
            (f) =>
              `- ${attackLabel(f.attackType)} (${Math.round(f.confidence * 100)}% confidence, ${f.stage} stage): ${f.reason}`,
          )
          .join("\n")
      : "No specific findings.",
    `\nTrace:`,
    ...result.trace.map(
      (t) =>
        `- ${t.stage}: ${t.skipped ? "skipped" : t.score != null ? `score ${t.score.toFixed(2)}` : "ran"} (${t.ms}ms)`,
    ),
    `\nContent excerpt (truncated): "${truncated}"`,
    `\nExplain this firewall decision clearly for someone without a security background.`,
  ].join("\n");

  try {
    const isAnthropic = provider.kind === "anthropic";

    const res = await fetch(
      `${provider.baseUrl}${isAnthropic ? "/messages" : "/chat/completions"}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(isAnthropic
            ? {
                "x-api-key": provider.apiKey,
                "anthropic-version": "2023-06-01",
                ...(provider.workspaceId
                  ? { "anthropic-workspace-id": provider.workspaceId }
                  : {}),
              }
            : { Authorization: `Bearer ${provider.apiKey}` }),
        },
        body: JSON.stringify({
          model: provider.model,
          max_tokens: 500,
          temperature: 0.3,
          ...(isAnthropic
            ? {
                system: EXPLAINER_SYSTEM,
                messages: [{ role: "user", content: userPrompt }],
              }
            : {
                messages: [
                  { role: "system", content: EXPLAINER_SYSTEM },
                  { role: "user", content: userPrompt },
                ],
              }),
        }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      },
    );

    if (!res.ok) {
      console.warn(
        `[explain] LLM ${res.status} ${res.statusText}: ${(await res.text()).slice(0, 160)}`,
      );
      return "[Auto-generated] " + fastExplain(result, content, opts);
    }

    const body = await res.json();
    const text: string | null = isAnthropic
      ? (body?.content?.find((b: { type: string }) => b.type === "text")?.text ?? null)
      : (body?.choices?.[0]?.message?.content ?? null);

    if (!text) {
      return "[Auto-generated] " + fastExplain(result, content, opts);
    }

    return text;
  } catch (e) {
    console.warn(
      `[explain] LLM call failed: ${e instanceof Error ? e.message : e}`,
    );
    return "[Auto-generated] " + fastExplain(result, content, opts);
  }
}
