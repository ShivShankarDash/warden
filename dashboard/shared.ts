/**
 * Helpers shared by the overview and the review queue.
 *
 * Every figure the dashboard shows is read from the live database or a saved eval
 * run — nothing here invents a number, so an empty panel means there is genuinely
 * no data rather than a placeholder waiting to be filled.
 */

export const $ = <T extends HTMLElement = HTMLElement>(id: string) =>
  document.getElementById(id) as T;

export const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!
  );

export const ms = (n: number) =>
  n < 1 ? `${n.toFixed(1)}ms` : n < 1000 ? `${Math.round(n)}ms` : `${(n / 1000).toFixed(1)}s`;

export const num = (n: number) => n.toLocaleString();

export function ago(t: number): string {
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export const clock = (t: number) =>
  new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

// ---------------------------------------------------------------- vocabulary

/** Short display names. The raw enum values are correct but too long to fit a
 *  column header, and truncating them loses the end that distinguishes them. */
export const SOURCE_LABEL: Record<string, string> = {
  user_message: "User msg",
  html: "HTML",
  email: "Email",
  pdf: "PDF",
  docx: "DOCX",
  markdown: "Markdown",
  api_json: "API JSON",
  code: "Code",
  ocr_text: "OCR",
  image: "Image",
  mcp_tool_description: "MCP tool",
  a2a_message: "A2A",
};

export const ATTACK_LABEL: Record<string, string> = {
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

export const STAGE_LABEL: Record<string, string> = {
  similarity: "Memory match",
  rules: "Rules",
  judge: "LLM judge",
  classifier: "Classifier",
  session: "Session",
  none: "No finding",
};

export const srcLabel = (s: string) => SOURCE_LABEL[s] ?? s;
export const atkLabel = (s: string) => ATTACK_LABEL[s] ?? s.replace(/_/g, " ");
export const stageLabel = (s: string) => STAGE_LABEL[s] ?? s;

export type Tier = "allowed" | "flagged" | "blocked";

export const TIERS: { key: Tier; label: string; varName: string }[] = [
  { key: "allowed", label: "Allowed", varName: "--tier-allowed" },
  { key: "flagged", label: "Flagged", varName: "--tier-flagged" },
  { key: "blocked", label: "Blocked", varName: "--tier-blocked" },
];

export function tierOf(action: string): Tier {
  if (action === "ALLOW") return "allowed";
  if (action === "BLOCK" || action === "QUARANTINE") return "blocked";
  return "flagged";
}

/** Resolve a token to its computed value so SVG fills follow the theme. */
export const token = (name: string) =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// ---------------------------------------------------------------- tooltip

let tipEl: HTMLDivElement | null = null;

function tip(): HTMLDivElement {
  if (!tipEl) {
    tipEl = document.createElement("div");
    tipEl.className = "tooltip";
    tipEl.setAttribute("role", "status");
    document.body.appendChild(tipEl);
  }
  return tipEl;
}

export function showTip(html: string, x: number, y: number) {
  const el = tip();
  el.innerHTML = html;
  el.classList.add("on");
  // Measure after painting the content, so a wide tooltip near the right edge
  // flips instead of being clipped.
  const r = el.getBoundingClientRect();
  const left = Math.min(Math.max(8, x + 14), window.innerWidth - r.width - 8);
  const top = Math.min(Math.max(8, y - r.height - 12), window.innerHeight - r.height - 8);
  el.style.left = `${left}px`;
  el.style.top = `${top}px`;
}

export function hideTip() {
  tip().classList.remove("on");
}

// ---------------------------------------------------------------- toast

export function toast(text: string) {
  const el = document.createElement("div");
  el.className = "toast";
  el.setAttribute("role", "status");
  el.textContent = text;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3800);
}

// ---------------------------------------------------------------- live socket

export interface ScanEvent {
  type: "scan";
  id: string;
  source: string;
  action: string;
  riskScore: number;
  attackTypes: string[];
  decidedBy: string;
  savedMs: number;
  latencyMs: number;
  preview: string;
  at: number;
  explanation?: string;
}

/**
 * Converts a plain-text explanation into formatted HTML.
 *
 * The first line is rendered bold (headline). Lines matching
 * "Detection path:" get a `.detection-path` class for highlighting.
 * All text is escaped before wrapping.
 */
export function formatExplanation(text: string): string {
  const lines = text.split("\n");
  return lines
    .map((line, i) => {
      const escaped = esc(line);
      if (i === 0) return `<div style="font-weight:600">${escaped}</div>`;
      if (/^Detection path:/i.test(line))
        return `<div class="detection-path">${escaped}</div>`;
      return `<div>${escaped}</div>`;
    })
    .join("");
}

/** Connects, reconnects, and drives the header's live pill. */
export function connectLive(onScan: (e: ScanEvent) => void) {
  const pill = $("live");
  const txt = $("live-txt");
  let backoff = 1000;

  const open = () => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/events`);

    ws.onopen = () => {
      backoff = 1000;
      pill?.classList.add("on");
      if (txt) txt.textContent = "Live";
    };
    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        if (data.type === "scan") onScan(data as ScanEvent);
      } catch {
        // A malformed frame is not worth tearing the socket down for.
      }
    };
    ws.onclose = () => {
      pill?.classList.remove("on");
      if (txt) txt.textContent = "Reconnecting";
      setTimeout(open, backoff);
      backoff = Math.min(backoff * 2, 15000);
    };
    ws.onerror = () => ws.close();
  };

  open();
}

/**
 * Theme. White is the default on every machine — an OS dark setting does not
 * silently override it — and dark is reached by the header toggle, remembered
 * per browser. Charts read their colours from CSS tokens, so a switch fires
 * `themechange` for anything that paints to canvas-like SVG.
 */
export function initTheme() {
  const saved = (() => {
    try {
      return localStorage.getItem("warden-theme");
    } catch {
      return null; // private browsing — fall through to the light default
    }
  })();
  if (saved === "dark") document.documentElement.setAttribute("data-theme", "dark");

  const btn = $("theme");
  btn?.addEventListener("click", () => {
    const dark = document.documentElement.getAttribute("data-theme") === "dark";
    if (dark) document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", "dark");
    try {
      localStorage.setItem("warden-theme", dark ? "light" : "dark");
    } catch {
      // Not being able to remember the choice is not worth failing the toggle.
    }
    btn.setAttribute("aria-label", dark ? "Switch to dark theme" : "Switch to light theme");
    window.dispatchEvent(new Event("themechange"));
  });
}

/**
 * The pending count appears twice — on the header jump link and on the review
 * panel's own header — so it updates in one place. The header link only exists
 * while something is actually waiting.
 */
export function setQueueBadge(n: number) {
  for (const id of ["queue-count", "review-count"]) {
    const el = $(id);
    if (!el) continue;
    el.textContent = String(n);
    el.classList.toggle("alert", n > 0);
  }
  const link = $("queue-link");
  if (link) link.hidden = n === 0;
}

export const json = <T>(url: string) => fetch(url).then((r) => r.json() as Promise<T>);
