/**
 * Warden — dashboard.
 *
 * Shows the four figures that decide whether the firewall is working (is it
 * catching attacks, is it crying wolf, what is it stopping, and what does it cost
 * in latency), then the shape of the traffic underneath them.
 *
 * The human review queue is a collapsible section rather than a separate page: it
 * is the only part of the page that asks the reader to act, and a decision there
 * moves the memory figures shown further down. Collapsed, its header still carries
 * the count, the highest risk waiting and the longest wait, so it can be skipped
 * without being hidden.
 */

import {
  $, ago, atkLabel, clock, connectLive, esc, formatExplanation, initTheme, json, ms, num,
  setQueueBadge, srcLabel, stageLabel, tierOf, token, TIERS, type ScanEvent, type Tier,
} from "./shared.ts";
import {
  type Bucket, type HeatData, barList, columnsTable, heatGrid, heatTable, stackedColumns,
} from "./charts.ts";
import { type ReviewItem, renderReviewPanel, reviewSummary } from "./review.ts";

interface Metrics {
  total: number;
  blocked: number;
  blocked_rate: number;
  pending_review: number;
  latency: { p50: number; p95: number; samples: number };
  evaluation: {
    date: string; total: number; correct: number; fp: number;
    judgeVerdicts: number; judgeUnavailable: number; degraded: boolean;
  } | null;
  memory: { attack: { active: number; probation: number }; safe: { active: number; probation: number } };
}

interface Analytics {
  range: string;
  from: number; to: number; bucketMs: number;
  series: Bucket[];
  heatmap: HeatData;
  decisions: { stage: string; n: number }[];
  savedMs: number;
  totals: { scans: number; allowed: number; flagged: number; blocked: number; threats: number };
}

interface MemorySummary {
  id: string; label: "attack" | "safe"; text: string;
  status: string; origin: string; confirmations: number;
}

interface FeedRow {
  id: string; source: string; action: string; riskScore: number;
  attackTypes: string[]; decidedBy: string; savedMs: number; latencyMs: number;
  preview?: string; at: number; explanation?: string;
}

const RANGE_LABEL: Record<string, string> = {
  "1h": "the last hour", "24h": "the last 24 hours", "7d": "the last 7 days",
  "30d": "the last 30 days", all: "all recorded traffic",
};

let range = "24h";
let latest: Analytics | null = null;

// ---------------------------------------------------------------- tiles

function renderTiles(m: Metrics, a: Analytics) {
  const ev = m.evaluation;
  const tiles: string[] = [];

  if (ev && ev.total > 0) {
    const detection = (ev.correct / ev.total) * 100;
    tiles.push(`
      <div class="tile">
        <div class="k">Detection rate</div>
        <div class="v">${detection.toFixed(1)}%</div>
        <div class="s"><b>${num(ev.correct)}</b> of ${num(ev.total)} eval cases · ${esc(ev.date)}</div>
      </div>`);
    tiles.push(`
      <div class="tile">
        <div class="k">False positives</div>
        <div class="v">${num(ev.fp)}</div>
        <div class="s">${ev.fp === 0 ? `<span class="ok">clean</span> across benign cases` : "benign content wrongly flagged"}</div>
      </div>`);
  } else {
    tiles.push(`
      <div class="tile">
        <div class="k">Detection rate</div>
        <div class="v">—</div>
        <div class="s">no eval run saved yet · <code>bun run eval</code></div>
      </div>`);
  }

  tiles.push(`
    <div class="tile">
      <div class="k">Threats stopped</div>
      <div class="v">${num(a.totals.threats)}</div>
      <div class="s"><b>${num(a.totals.blocked)}</b> blocked · <b>${num(a.totals.flagged)}</b> flagged
        of ${num(a.totals.scans)} scans</div>
    </div>`);

  tiles.push(`
    <div class="tile">
      <div class="k">Latency p50</div>
      <div class="v">${m.latency.samples ? ms(m.latency.p50) : "—"}</div>
      <div class="s">${m.latency.samples
        ? `p95 <b>${ms(m.latency.p95)}</b> · n=${num(m.latency.samples)}`
        : "no traffic recorded yet"}</div>
    </div>`);

  $("tiles").innerHTML = tiles.join("");
}

// ---------------------------------------------------------------- volume

function renderVolume(a: Analytics) {
  $("vol-sub").textContent = `${num(a.totals.scans)} scans · ${RANGE_LABEL[a.range] ?? a.range}`;

  const counts: Record<Tier, number> = {
    allowed: a.totals.allowed, flagged: a.totals.flagged, blocked: a.totals.blocked,
  };
  $("vol-legend").innerHTML = TIERS.map(
    (t) =>
      `<span class="item"><span class="sw" style="background:${token(t.varName)}"></span>${t.label}
        <span class="n">${num(counts[t.key])}</span></span>`
  ).join("");

  const longRange = a.range === "7d" || a.range === "30d" || a.range === "all";
  stackedColumns($("volume"), a.series, { bucketMs: a.bucketMs, longRange });
  $("volume-table").innerHTML = columnsTable(a.series);
}

// ---------------------------------------------------------------- decisions

function renderDecisions(a: Analytics) {
  // With no traffic at all, one sentence beats three stacked empty states.
  if (!a.totals.scans) {
    $("saved").innerHTML =
      `<span class="fig">—</span><span class="cap">No traffic in this range yet.</span>`;
    $("decisions").innerHTML = "";
    return;
  }

  const saved = a.savedMs;
  $("saved").innerHTML = saved > 0
    ? `<span class="fig">${(saved / 1000).toFixed(1)}s</span>
       <span class="cap">of judge time avoided — a learned attack is matched in about a
         millisecond where the judge costs ~1.4s.</span>`
    : `<span class="fig">—</span>
       <span class="cap">No fast-path decisions in this range yet. Time saved accrues here
         once memory or rules settle a scan without the judge.</span>`;

  // Scans that produced no finding are context, not a decision path — and at ~87%
  // of traffic they flatten every other bar to a hairline. They move to the footer
  // so the bars compare the three stages that actually settled something.
  const settled = a.decisions.filter((d) => d.stage !== "none");
  const clean = a.decisions.find((d) => d.stage === "none")?.n ?? 0;
  const settledTotal = settled.reduce((t, d) => t + d.n, 0);

  const rank = (stage: string) =>
    stage === "similarity" ? 0 : stage === "rules" ? 1 : stage === "judge" ? 2 : 3;

  if (settledTotal) {
    barList(
      $("decisions"),
      [...settled].sort((x, y) => rank(x.stage) - rank(y.stage) || y.n - x.n).map((d) => ({
        label: stageLabel(d.stage),
        value: d.n,
        emphasis: d.stage === "similarity",
        note: d.stage === "similarity"
          ? "fast path — matched against memory, no judge call"
          : d.stage === "rules"
            ? "fast path — settled by a rule, no judge call"
            : d.stage === "judge"
              ? "full reasoning call"
              : undefined,
      })),
      settledTotal
    );
  } else {
    $("decisions").innerHTML = "";
  }

  const foot = document.createElement("div");
  foot.className = "bar-note";
  foot.style.cssText = settledTotal
    ? "margin-top:14px;padding-top:12px;border-top:1px solid var(--line-soft)"
    : "";
  foot.textContent = settledTotal
    ? `${num(clean)} of ${num(a.totals.scans)} scans produced no finding at all.`
    : `All ${num(clean)} scans in this range were clean — nothing needed a decision.`;
  $("decisions").appendChild(foot);
}

// ---------------------------------------------------------------- memory

function renderMemory(m: Metrics, mem: { recent: MemorySummary[]; promotions: unknown[] }) {
  const s = m.memory;
  const stat = (n: number, label: string) =>
    `<div><div class="v" style="font-size:19px;font-weight:600;letter-spacing:-.02em">${num(n)}</div>
      <div style="font-size:11.5px;color:var(--ink-3)">${label}</div></div>`;

  $("mem-stats").innerHTML =
    `<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;
                 padding-bottom:14px;margin-bottom:12px;border-bottom:1px solid var(--line-soft)">
       ${stat(s.attack.active, "active attacks")}
       ${stat(s.safe.active, "safe examples")}
       ${stat(s.attack.probation + s.safe.probation, "on probation")}
     </div>`;

  $("mem-list").innerHTML = mem.recent.length
    ? mem.recent.slice(0, 8).map((r) => `
        <div class="mem-row">
          <span class="badge">${r.label === "attack" ? "Attack" : "Safe"}</span>
          <span class="t" title="${esc(r.text)}">${esc(r.text.slice(0, 120))}</span>
          <span class="m">${esc(r.origin)}${r.confirmations > 1 ? ` ×${r.confirmations}` : ""}</span>
        </div>`).join("")
    : `<div class="empty">Nothing learned yet. A confirmed attack lands here on probation,
         then promotes after a second independent sighting.</div>`;
}

// ---------------------------------------------------------------- feed

const feedRows: FeedRow[] = [];

function feedRowHtml(e: FeedRow): string {
  const tier = tierOf(e.action);
  const color = token(TIERS.find((t) => t.key === tier)!.varName);
  const detail = e.preview
    ? `<div class="preview">${esc(e.preview)}</div>`
    : `<div class="preview" style="color:var(--ink-3)">${e.attackTypes.length
        ? e.attackTypes.map((t) => esc(atkLabel(t))).join(" · ")
        : "—"}</div>`;
  const types = e.preview && e.attackTypes.length
    ? `<div class="types">${e.attackTypes.map((t) => esc(atkLabel(t))).join(" · ")}</div>`
    : "";
  const fast = e.savedMs > 0;

  return `
    <div class="feed-row" data-scan-id="${esc(e.id)}">
      <span class="badge"><span class="tierdot" style="background:${color}"></span>${esc(e.action.replace("_", " ").toLowerCase())}</span>
      <span class="src">${esc(srcLabel(e.source))}</span>
      <div style="min-width:0">${detail}${types}</div>
      <span class="risk">${e.riskScore.toFixed(2)}</span>
      <span class="by">${esc(stageLabel(e.decidedBy))}
        <span class="${fast ? "fast" : ""}">${fast ? `saved ${ms(e.savedMs)}` : ms(e.latencyMs)}</span></span>
    </div>`;
}

function paintFeed() {
  const host = $("feed");
  if (!feedRows.length) {
    host.innerHTML = `<div class="empty">Waiting for traffic. <b>POST to <code>/scan</code></b> to see scans arrive here live.</div>`;
    return;
  }
  host.innerHTML = feedRows.map(feedRowHtml).join("") +
    `<div class="explain-panel" id="explain-panel" hidden></div>`;
  $("feed-sub").textContent = `newest ${ago(feedRows[0]!.at)} · ${num(feedRows.length)} in view, scroll for more`;
  wireFeedClicks();
}

/** Currently expanded scan id — null when the panel is hidden. */
let expandedScanId: string | null = null;

function wireFeedClicks() {
  const host = $("feed");
  for (const row of host.querySelectorAll<HTMLElement>(".feed-row[data-scan-id]")) {
    row.style.cursor = "pointer";
    row.addEventListener("click", () => {
      const scanId = row.dataset.scanId!;
      const panel = $("explain-panel");
      // Toggle: re-clicking the same row hides the panel.
      if (expandedScanId === scanId) {
        panel.hidden = true;
        panel.classList.remove("open");
        expandedScanId = null;
        return;
      }
      expandedScanId = scanId;
      panel.innerHTML = `<div style="color:var(--ink-3)">Loading explanation…</div>`;
      panel.hidden = false;
      panel.classList.add("open");
      // Position the panel after the clicked row.
      row.insertAdjacentElement("afterend", panel);
      json<{ scanId: string; explanation: string }>(`/explain/${encodeURIComponent(scanId)}`)
        .then((data) => {
          if (expandedScanId !== scanId) return; // user clicked elsewhere
          panel.innerHTML = formatExplanation(data.explanation);
        })
        .catch(() => {
          if (expandedScanId !== scanId) return;
          panel.innerHTML = `<div style="color:var(--ink-3)">Could not load explanation.</div>`;
        });
    });
  }
}

function pushFeed(e: FeedRow) {
  feedRows.unshift(e);
  while (feedRows.length > 50) feedRows.pop();
  paintFeed();
}

// ---------------------------------------------------------------- review panel

const REVIEW_OPEN_KEY = "warden-review-open";

const readOpenPref = (): string | null => {
  try {
    return localStorage.getItem(REVIEW_OPEN_KEY);
  } catch {
    return null; // private browsing — fall back to the count-based default
  }
};

function renderReview(items: ReviewItem[], pendingTotal = items.length) {
  $("review-summary").textContent = reviewSummary(items, pendingTotal);
  renderReviewPanel($("review-body"), items, refresh, pendingTotal);

  // Until the reader expresses a preference, the panel opens only when there is
  // something to decide — so a clear queue costs one line, not a screen.
  const card = $<HTMLDetailsElement>("review-card");
  const pref = readOpenPref();
  card.open = pref === null ? items.length > 0 : pref === "1";
}

function wireReview() {
  const card = $<HTMLDetailsElement>("review-card");
  card.addEventListener("toggle", () => {
    try {
      localStorage.setItem(REVIEW_OPEN_KEY, card.open ? "1" : "0");
    } catch {
      // Not remembering the choice is not worth failing the toggle.
    }
  });

  // The header link is a jump, so it has to open the section it jumps to.
  $("queue-link")?.addEventListener("click", () => {
    card.open = true;
  });
}

// ---------------------------------------------------------------- table toggles

function wireToggle(btnId: string, chartId: string, tableId: string) {
  const btn = $(btnId);
  btn.addEventListener("click", () => {
    const showing = btn.getAttribute("aria-pressed") === "true";
    btn.setAttribute("aria-pressed", String(!showing));
    $(chartId).hidden = !showing;
    $(tableId).hidden = showing;
  });
}

// ---------------------------------------------------------------- boot

async function refresh() {
  const [metrics, a, mem, queue] = await Promise.all([
    json<Metrics>("/metrics"),
    json<Analytics>(`/analytics?range=${range}`),
    json<{ recent: MemorySummary[]; promotions: unknown[] }>("/memory"),
    json<ReviewItem[]>("/review"),
  ]);
  latest = a;

  renderTiles(metrics, a);
  renderVolume(a);
  heatGrid($("heat"), a.heatmap);
  $("heat-table").innerHTML = heatTable(a.heatmap);
  renderDecisions(a);
  renderMemory(metrics, mem);
  renderReview(queue, metrics.pending_review);
  // The true backlog, not the length of the page just fetched. These diverge the
  // moment the queue exceeds one page, and showing the page length made a
  // several-hundred-item queue read as a tidy 50.
  setQueueBadge(metrics.pending_review);

  $("stamp").textContent = `Updated ${clock(Date.now())}`;

  const ev = metrics.evaluation;
  $("footnote").textContent = !ev
    ? "No saved eval run. Run `bun run eval` to populate the detection figures."
    : ev.degraded
      ? `Last eval run was degraded — ${ev.judgeUnavailable} judge calls returned no verdict, so detection is understated.`
      : `Eval ${ev.date}: ${ev.judgeVerdicts} judge verdicts, ${ev.judgeUnavailable} unavailable. Run \`bun run eval\` to refresh.`;
}

for (const btn of $("range").querySelectorAll<HTMLButtonElement>("button[data-range]")) {
  btn.addEventListener("click", () => {
    for (const b of $("range").querySelectorAll("button")) b.setAttribute("aria-pressed", "false");
    btn.setAttribute("aria-pressed", "true");
    range = btn.dataset.range!;
    void refresh();
  });
}

wireReview();
wireToggle("vol-table", "volume", "volume-table");
wireToggle("heat-table-btn", "heat", "heat-table");

initTheme();

// Charts read their colours from CSS tokens, so a theme change needs a repaint.
window.addEventListener("themechange", () => {
  if (latest) {
    renderVolume(latest);
    heatGrid($("heat"), latest.heatmap);
  }
  paintFeed();
});

const seed = await json<FeedRow[]>("/recent");
feedRows.push(...seed);
paintFeed();

await refresh();

let debounce = 0;
connectLive((e: ScanEvent) => {
  pushFeed(e);
  // Aggregates move as scans land; coalesce so a burst does not spam the server.
  clearTimeout(debounce);
  debounce = setTimeout(refresh, 700) as unknown as number;
});

setInterval(refresh, 15_000);
