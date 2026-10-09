/**
 * Chart renderers — hand-written SVG and CSS grid, no charting dependency.
 *
 * Marks are deliberately thin, gridlines are solid hairlines one shade off the
 * surface, and every chart ships a hover layer plus a table-view twin so no value
 * is reachable only by colour or only by pointer.
 */

import {
  TIERS, type Tier, atkLabel, clock, esc, hideTip, num, showTip, srcLabel, token,
} from "./shared.ts";

const SVG = "http://www.w3.org/2000/svg";
const el = <K extends keyof SVGElementTagNameMap>(n: K, attrs: Record<string, string | number> = {}) => {
  const e = document.createElementNS(SVG, n);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  return e;
};

/** Round a scale maximum up to something a reader can divide in their head. */
function niceMax(v: number): number {
  if (v <= 4) return Math.max(1, v);
  const mag = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10]) {
    if (v <= m * mag) return m * mag;
  }
  return 10 * mag;
}

/** A rect whose top corners are rounded and whose base sits flat on the axis. */
function topRoundedPath(x: number, y: number, w: number, h: number, r: number): string {
  const rad = Math.max(0, Math.min(r, w / 2, h));
  return `M${x},${y + h}V${y + rad}a${rad},${rad} 0 0 1 ${rad},${-rad}h${w - 2 * rad}a${rad},${rad} 0 0 1 ${rad},${rad}V${y + h}Z`;
}

/** Re-render on width change, so text stays at its true size instead of being
 *  stretched by a viewBox. */
function responsive(host: HTMLElement, draw: (width: number) => void) {
  let last = 0;
  const run = () => {
    const w = Math.round(host.clientWidth);
    if (w > 0 && w !== last) {
      last = w;
      draw(w);
    }
  };
  new ResizeObserver(run).observe(host);
  run();
  return () => {
    last = 0;
    run();
  };
}

// ---------------------------------------------------------------- columns

export interface Bucket {
  t: number;
  allowed: number;
  flagged: number;
  blocked: number;
}

export interface ColumnOpts {
  height?: number;
  bucketMs: number;
  /** Long ranges need a date, short ones a clock time. */
  longRange: boolean;
}

export function stackedColumns(host: HTMLElement, data: Bucket[], opts: ColumnOpts) {
  const H = opts.height ?? 180;
  const PAD = { t: 10, r: 8, b: 22, l: 34 };
  const GAP = 2; // surface gap between stacked segments — never a stroke

  host.innerHTML = "";
  if (!data.length) return;

  responsive(host, (W) => {
    host.innerHTML = "";
    const plotW = W - PAD.l - PAD.r;
    const plotH = H - PAD.t - PAD.b;
    if (plotW <= 0) return;

    const totals = data.map((d) => d.allowed + d.flagged + d.blocked);
    const max = niceMax(Math.max(1, ...totals));
    const y = (v: number) => PAD.t + plotH - (v / max) * plotH;

    const step = plotW / data.length;
    const bw = Math.max(2, Math.min(step - 2, 26));

    const svg = el("svg", {
      width: W, height: H, viewBox: `0 0 ${W} ${H}`,
      role: "img",
      "aria-label": `Scan volume by severity across ${data.length} time buckets`,
    });

    const ink3 = token("--ink-3");

    // --- y gridlines: solid hairlines, never dashed ---
    // Counts are whole numbers, so a midpoint tick is only drawn when it rounds to
    // something distinct — otherwise a quiet chart shows "1" twice.
    const ticks = [...new Set([0, Math.round(max / 2), max].map(Math.round))].sort((a, b) => a - b);
    for (const v of ticks) {
      svg.appendChild(el("line", {
        x1: PAD.l, x2: W - PAD.r, y1: y(v), y2: y(v),
        stroke: v === 0 ? token("--axis") : token("--grid"), "stroke-width": 1,
        "shape-rendering": "crispEdges",
      }));
      const label = el("text", {
        x: PAD.l - 7, y: y(v) + 3.5, "text-anchor": "end",
        "font-size": 10.5, fill: ink3, "font-variant-numeric": "tabular-nums",
      });
      label.textContent = String(Math.round(v));
      svg.appendChild(label);
    }

    // --- columns ---
    const colors: Record<Tier, string> = {
      allowed: token("--tier-allowed"),
      flagged: token("--tier-flagged"),
      blocked: token("--tier-blocked"),
    };

    data.forEach((d, i) => {
      const cx = PAD.l + i * step + (step - bw) / 2;
      const order: Tier[] = ["allowed", "flagged", "blocked"];
      const present = order.filter((k) => d[k] > 0);
      const topKey = present[present.length - 1];

      let base = y(0);
      for (const key of order) {
        const v = d[key];
        if (!v) continue;
        // A single blocked scan must not vanish into a sub-pixel sliver on a
        // chart whose point is that it was blocked. The table view carries the
        // exact counts.
        const h = Math.max(2, (v / max) * plotH);
        const top = base - h;
        const isTop = key === topKey;
        const drawH = isTop ? h : Math.max(1, h - GAP);
        const node = isTop
          ? el("path", { d: topRoundedPath(cx, top, bw, drawH, 4), fill: colors[key] })
          : el("rect", { x: cx, y: top, width: bw, height: drawH, fill: colors[key] });
        svg.appendChild(node);
        base = top;
      }
    });

    // --- x labels: a handful, evenly spaced ---
    const wantTicks = Math.max(2, Math.min(6, Math.floor(plotW / 90)));
    const everyN = Math.max(1, Math.round(data.length / wantTicks));
    data.forEach((d, i) => {
      if (i % everyN !== 0 && i !== data.length - 1) return;
      const t = el("text", {
        x: PAD.l + i * step + step / 2, y: H - 6, "text-anchor": "middle",
        "font-size": 10.5, fill: ink3, "font-variant-numeric": "tabular-nums",
      });
      t.textContent = opts.longRange
        ? new Date(d.t).toLocaleDateString([], { month: "short", day: "numeric" })
        : clock(d.t);
      svg.appendChild(t);
    });

    // --- hover layer: a full-height band per column, so the target is the whole
    //     column rather than the few pixels the mark happens to occupy ---
    const hl = el("rect", {
      x: 0, y: PAD.t, width: 0, height: plotH,
      fill: token("--ink"), opacity: 0.045, rx: 3, "pointer-events": "none",
    });
    svg.appendChild(hl);

    data.forEach((d, i) => {
      const band = el("rect", {
        x: PAD.l + i * step, y: PAD.t, width: step, height: plotH,
        fill: "transparent",
      });
      const total = d.allowed + d.flagged + d.blocked;
      const end = d.t + opts.bucketMs;
      const show = (ev: MouseEvent) => {
        hl.setAttribute("x", String(PAD.l + i * step));
        hl.setAttribute("width", String(step));
        const rows = TIERS.map(
          (t) =>
            `<div class="tt-row"><span class="sw" style="background:${colors[t.key]}"></span>${t.label}<span class="val">${num(d[t.key])}</span></div>`
        ).join("");
        showTip(
          `<div class="tt-title">${clock(d.t)} – ${clock(end)}</div>${rows}` +
            `<div class="tt-foot">${num(total)} scan${total === 1 ? "" : "s"} in this bucket</div>`,
          ev.clientX, ev.clientY
        );
      };
      band.addEventListener("mousemove", show as EventListener);
      band.addEventListener("mouseleave", () => {
        hl.setAttribute("width", "0");
        hideTip();
      });
      svg.appendChild(band);
    });

    host.appendChild(svg);
  });
}

export function columnsTable(data: Bucket[]): string {
  const rows = data
    .filter((d) => d.allowed + d.flagged + d.blocked > 0)
    .map(
      (d) => `<tr><td>${clock(d.t)}</td><td>${num(d.allowed)}</td><td>${num(d.flagged)}</td>
        <td>${num(d.blocked)}</td><td>${num(d.allowed + d.flagged + d.blocked)}</td></tr>`
    )
    .join("");
  return rows
    ? `<div class="tablewrap"><table class="dataview">
         <thead><tr><th>Bucket</th><th>Allowed</th><th>Flagged</th><th>Blocked</th><th>Total</th></tr></thead>
         <tbody>${rows}</tbody></table></div>`
    : `<div class="empty">No scans in this range.</div>`;
}

// ---------------------------------------------------------------- heatmap

export interface HeatData {
  sources: string[];
  attackTypes: string[];
  cells: number[][]; // [source][attackType]
  rowTotals: number[];
  max: number;
}

/** Eight sequential steps, light→dark, one hue. Step 0 means "none". */
const SEQ = ["--seq-0", "--seq-1", "--seq-2", "--seq-3", "--seq-4", "--seq-5", "--seq-6", "--seq-7"];

function seqStep(v: number, max: number): number {
  if (v <= 0) return 0;
  if (max <= 1) return 4;
  // Square-root scaling keeps a long tail of ones from all collapsing onto step 1.
  const f = Math.sqrt(v / max);
  return Math.min(7, 1 + Math.round(f * 6));
}

/**
 * Attack type (rows) by source (columns).
 *
 * Rows are the long labels, so they go down the left where there is room; sources
 * are short enough for a column header, which avoids rotated text entirely.
 */
export function heatGrid(host: HTMLElement, d: HeatData) {
  host.innerHTML = "";

  if (!d.sources.length) {
    host.innerHTML = `<div class="empty">No traffic in this range.<br>
      <b>POST to <code>/scan</code></b> to populate the grid.</div>`;
    return;
  }
  if (!d.attackTypes.length) {
    const seen = d.sources.map((s) => `${srcLabel(s)} (${num(d.rowTotals[d.sources.indexOf(s)] ?? 0)})`).join(" · ");
    host.innerHTML = `<div class="empty"><b>No attack types detected in this range.</b><br>
      Clean traffic across ${seen}.</div>`;
    return;
  }

  const grid = document.createElement("div");
  grid.className = "heat";
  grid.style.setProperty("--cols", String(d.sources.length));

  const head = (txt: string, sub?: string, cls = "") => {
    const c = document.createElement("div");
    c.className = `heat-head ${cls}`;
    c.innerHTML = `<span>${esc(txt)}</span>${sub ? `<em>${esc(sub)}</em>` : ""}`;
    return c;
  };

  grid.appendChild(head("", ""));
  d.sources.forEach((s, i) => grid.appendChild(head(srcLabel(s), `${num(d.rowTotals[i] ?? 0)}`, "col")));
  grid.appendChild(head("Total", "", "col total"));

  d.attackTypes.forEach((atk, ai) => {
    const label = document.createElement("div");
    label.className = "heat-row-label";
    label.textContent = atkLabel(atk);
    grid.appendChild(label);

    let rowTotal = 0;
    d.sources.forEach((src, si) => {
      const v = d.cells[si]?.[ai] ?? 0;
      rowTotal += v;
      const cell = document.createElement("div");
      cell.className = "heat-cell";
      cell.tabIndex = 0;
      cell.style.background = `var(${SEQ[seqStep(v, d.max)]})`;
      cell.dataset.v = String(v);
      // The number stays on the cell at low density; the tooltip and the table
      // view carry it everywhere else, so nothing is colour-only.
      if (v > 0) cell.textContent = String(v);
      if (seqStep(v, d.max) >= 5) cell.classList.add("on-dark");

      const label2 = `${atkLabel(atk)} · ${srcLabel(src)}`;
      cell.setAttribute("aria-label", `${label2}: ${v} scans`);
      const show = (x: number, y: number) =>
        showTip(
          `<div class="tt-title">${esc(atkLabel(atk))}</div>` +
            `<div class="tt-row">Source<span class="val">${esc(srcLabel(src))}</span></div>` +
            `<div class="tt-row">Scans flagged<span class="val">${num(v)}</span></div>` +
            `<div class="tt-foot">${num(d.rowTotals[si] ?? 0)} total scans from this source</div>`,
          x, y
        );
      cell.addEventListener("mousemove", (e) => show(e.clientX, e.clientY));
      cell.addEventListener("mouseleave", hideTip);
      cell.addEventListener("focus", () => {
        const r = cell.getBoundingClientRect();
        show(r.left + r.width / 2, r.top);
      });
      cell.addEventListener("blur", hideTip);
      grid.appendChild(cell);
    });

    const tot = document.createElement("div");
    tot.className = "heat-total";
    tot.textContent = String(rowTotal);
    grid.appendChild(tot);
  });

  host.appendChild(grid);

  // Scale legend — a sequential encoding is unreadable without one.
  const legend = document.createElement("div");
  legend.className = "heat-legend";
  legend.innerHTML =
    `<span>Fewer</span>` +
    SEQ.map((s) => `<i style="background:var(${s})"></i>`).join("") +
    `<span>More (max ${num(d.max)})</span>`;
  host.appendChild(legend);
}

export function heatTable(d: HeatData): string {
  if (!d.attackTypes.length) return `<div class="empty">No attack types detected in this range.</div>`;
  const head = `<tr><th>Attack type</th>${d.sources.map((s) => `<th>${esc(srcLabel(s))}</th>`).join("")}<th>Total</th></tr>`;
  const body = d.attackTypes
    .map((atk, ai) => {
      const cells = d.sources.map((_, si) => d.cells[si]?.[ai] ?? 0);
      return `<tr><td>${esc(atkLabel(atk))}</td>${cells.map((v) => `<td>${v}</td>`).join("")}<td>${cells.reduce((a, b) => a + b, 0)}</td></tr>`;
    })
    .join("");
  return `<div class="tablewrap"><table class="dataview"><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
}

// ---------------------------------------------------------------- bar list

export interface BarItem {
  label: string;
  value: number;
  note?: string;
  /** Marks the one bar that carries the story; the rest stay recessive. */
  emphasis?: boolean;
}

/** Nominal categories, so one hue for every bar — length already encodes size. */
export function barList(host: HTMLElement, items: BarItem[], totalOverride?: number) {
  host.innerHTML = "";
  if (!items.length) {
    host.innerHTML = `<div class="empty">Nothing recorded in this range.</div>`;
    return;
  }
  const total = totalOverride ?? items.reduce((a, b) => a + b.value, 0);
  const max = Math.max(1, ...items.map((i) => i.value));

  const list = document.createElement("div");
  // When one bar carries the story the others recede to gray; with no emphasis
  // every bar keeps the single hue, since length already encodes the size.
  list.className = items.some((i) => i.emphasis) ? "bars has-emph" : "bars";
  for (const it of items) {
    const pct = total ? (it.value / total) * 100 : 0;
    const row = document.createElement("div");
    row.className = `bar${it.emphasis ? " emph" : ""}`;
    row.innerHTML = `
      <div class="bar-top">
        <span class="bar-label">${esc(it.label)}</span>
        <span class="bar-val num">${num(it.value)}<em>${pct.toFixed(0)}%</em></span>
      </div>
      <div class="bar-track"><div class="bar-fill" style="width:${(it.value / max) * 100}%"></div></div>
      ${it.note ? `<div class="bar-note">${esc(it.note)}</div>` : ""}`;
    list.appendChild(row);
  }
  host.appendChild(list);
}
