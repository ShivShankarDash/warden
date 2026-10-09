/**
 * The human review panel.
 *
 * It lives on the dashboard as a collapsible section rather than its own page:
 * triage is part of watching traffic, not a separate errand, and a decision here
 * changes the memory figures in the cards above it. Keeping it in its own module
 * keeps the markup and the decision handling out of the overview's way.
 */

import { $, ago, atkLabel, esc, formatExplanation, num, srcLabel, tierOf, toast, token, TIERS } from "./shared.ts";

export interface ReviewItem {
  id: string;
  content: string;
  source: string;
  action: string;
  riskScore: number;
  findings: { attackType: string; confidence: number }[];
  createdAt: number;
  explanation?: string;
}

/** The one-line digest shown on the collapsed header, so the queue can be judged
 *  without opening it. */
export function reviewSummary(items: ReviewItem[]): string {
  if (!items.length) return "nothing awaiting a decision";
  const topRisk = Math.max(...items.map((i) => i.riskScore));
  const oldest = Math.min(...items.map((i) => i.createdAt));
  return `highest risk ${topRisk.toFixed(2)} · oldest ${ago(oldest)}`;
}

function card(it: ReviewItem): string {
  const tier = tierOf(it.action);
  const color = token(TIERS.find((t) => t.key === tier)!.varName);
  const findings = it.findings.length
    ? it.findings
        .map((f) => `<span class="badge">${esc(atkLabel(f.attackType))} ${(f.confidence * 100).toFixed(0)}%</span>`)
        .join("")
    : `<span class="badge">No findings</span>`;

  return `
    <article class="rev" data-id="${esc(it.id)}">
      <div class="meta">
        <span class="badge"><span class="tierdot" style="background:${color}"></span>${esc(it.action.replace("_", " ").toLowerCase())}</span>
        <span class="badge">${esc(srcLabel(it.source))}</span>
        <span class="risk-chip">risk <b>${it.riskScore.toFixed(2)}</b></span>
        ${findings}
        <span class="when">${ago(it.createdAt)}</span>
      </div>
      <div class="explain-text">${it.explanation ? formatExplanation(it.explanation) : `<span style="color:var(--ink-3)">No explanation available.</span>`}</div>
      <pre class="content">${esc(it.content.slice(0, 2000))}${it.content.length > 2000 ? "\n…" : ""}</pre>
      <div class="acts">
        <button class="act danger" data-decision="attack">Confirm attack</button>
        <button class="act ok" data-decision="safe">Mark safe</button>
        <span class="hint">Writes a human-origin entry straight to active memory.</span>
      </div>
    </article>`;
}

/**
 * Paints the queue into `host` and wires the decision buttons.
 *
 * `onResolved` runs after a decision lands so the caller can refresh the figures
 * the decision just changed.
 */
export function renderReviewPanel(
  host: HTMLElement,
  items: ReviewItem[],
  onResolved: () => void | Promise<void>
) {
  if (!items.length) {
    host.innerHTML = `<div class="empty">
      <b>Nothing awaiting review.</b><br>
      Verdicts of HUMAN_REVIEW or QUARANTINE queue here — everything else is already decided.
    </div>`;
    return;
  }

  // Most urgent first; a tie falls back to the longest wait.
  const ordered = [...items].sort((a, b) => b.riskScore - a.riskScore || a.createdAt - b.createdAt);
  host.innerHTML = `<div class="queue">${ordered.map(card).join("")}</div>`;

  for (const btn of host.querySelectorAll<HTMLButtonElement>("button[data-decision]")) {
    btn.addEventListener("click", () => void decide(btn, onResolved));
  }
}

async function decide(btn: HTMLButtonElement, onResolved: () => void | Promise<void>) {
  const article = btn.closest<HTMLElement>(".rev")!;
  const id = article.dataset.id!;
  const decision = btn.dataset.decision!;
  const buttons = [...article.querySelectorAll<HTMLButtonElement>("button")];
  for (const b of buttons) b.disabled = true;

  try {
    const res = await fetch(`/review/${id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision, note: "via dashboard" }),
    });
    const out = await res.json();

    if (!res.ok) {
      toast(out.error ? `Could not record: ${out.error}` : "Could not record that decision");
      for (const b of buttons) b.disabled = false;
      return;
    }

    toast(
      out.learned
        ? `Written to memory as a human-confirmed ${decision} example`
        : `Recorded as ${decision} — already close to an existing memory`
    );
    await onResolved();
  } catch {
    toast("Network error — decision not recorded");
    for (const b of buttons) b.disabled = false;
  }
}
