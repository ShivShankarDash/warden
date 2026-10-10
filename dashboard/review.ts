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
export function reviewSummary(items: ReviewItem[], pendingTotal = items.length): string {
  if (!items.length) return "nothing awaiting a decision";
  const topRisk = Math.max(...items.map((i) => i.riskScore));
  const oldest = Math.min(...items.map((i) => i.createdAt));
  // Say so when the panel is showing a page rather than the whole queue, so a
  // backlog cannot look like it has been fully triaged.
  const more = pendingTotal > items.length ? ` · showing ${items.length} of ${pendingTotal}` : "";
  return `highest risk ${topRisk.toFixed(2)} · oldest ${ago(oldest)}${more}`;
}

function card(it: ReviewItem): string {
  // Roughly the clamp height in base.css. Only cards that are actually cut off get
  // a toggle, so a two-line note does not carry a pointless button.
  const longContent = it.content.length > 400 || it.content.split("\n").length > 6;
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
        ${longContent ? `<button class="act subtle" data-expand>Show more</button>` : ""}
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
  onResolved: () => void | Promise<void>,
  pendingTotal = items.length
) {
  if (!items.length) {
    host.innerHTML = `<div class="empty">
      <b>Nothing awaiting review.</b><br>
      Verdicts of HUMAN_REVIEW or QUARANTINE queue here — everything else is already decided.
    </div>`;
    delete host.dataset.sig;
    return;
  }

  // The dashboard refreshes every 15 seconds. Replacing innerHTML destroys the
  // scroll container and drops the reader back to the top mid-read — so repaint only
  // when the queue has actually changed, not merely because the clock ticked. A
  // queue that is sitting still now stays exactly where the reader left it.
  const sig = `${pendingTotal}:${items.map((i) => i.id).join(",")}`;
  if (host.dataset.sig === sig) return;
  const prevScroll = host.querySelector<HTMLElement>(".queue")?.scrollTop ?? 0;

  // Most urgent first; a tie falls back to the longest wait.
  const ordered = [...items].sort((a, b) => b.riskScore - a.riskScore || a.createdAt - b.createdAt);

  // The server pages the queue. Without a way to ask for the next page, everything
  // past the first was unreachable — a reviewer could only ever see the newest 50,
  // however long the backlog was.
  const more = pendingTotal > items.length
    ? `<div class="acts" style="justify-content:center">
         <button class="act" id="review-more">Load ${Math.min(50, pendingTotal - items.length)} more
           (${pendingTotal - items.length} still queued)</button>
       </div>`
    : "";
  host.innerHTML = `<div class="queue">${ordered.map(card).join("")}</div>${more}`;
  host.dataset.sig = sig;

  // A repaint that did happen (a decision landed, or a page was appended) should
  // still not throw away where the reader was.
  const queue = host.querySelector<HTMLElement>(".queue");
  if (queue && prevScroll) queue.scrollTop = prevScroll;

  for (const btn of host.querySelectorAll<HTMLButtonElement>("button[data-decision]")) {
    btn.addEventListener("click", () => void decide(btn, onResolved));
  }

  // Long content is clamped rather than given its own scrollbar; this reveals it.
  for (const btn of host.querySelectorAll<HTMLButtonElement>("button[data-expand]")) {
    btn.addEventListener("click", () => {
      const art = btn.closest<HTMLElement>(".rev")!;
      const open = art.classList.toggle("expanded");
      btn.textContent = open ? "Show less" : "Show more";
    });
  }

  const moreBtn = host.querySelector<HTMLButtonElement>("#review-more");
  moreBtn?.addEventListener("click", () => void loadMore(moreBtn, host, items, onResolved, pendingTotal));
}

/** Fetches the next page and appends it, keeping the decisions already on screen. */
async function loadMore(
  btn: HTMLButtonElement,
  host: HTMLElement,
  shown: ReviewItem[],
  onResolved: () => void | Promise<void>,
  pendingTotal: number
) {
  btn.disabled = true;
  btn.textContent = "Loading…";
  try {
    const res = await fetch(`/review?offset=${shown.length}&limit=50`);
    const next = (await res.json()) as ReviewItem[];
    if (!next.length) {
      btn.textContent = "No more items";
      return;
    }
    renderReviewPanel(host, [...shown, ...next], onResolved, pendingTotal);
  } catch {
    toast("Could not load more");
    btn.disabled = false;
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
