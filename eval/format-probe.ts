/**
 * Format-equivalence probe.
 *
 * The same payload carries the same risk whatever container it arrives in. A benign
 * message is still benign inside a PDF; an attack is still an attack inside JSON. So
 * for each payload this renders every supported container, scans them all, and
 * compares each against the plain-text verdict.
 *
 * Any disagreement is a bug in that format's path, and the plain-text run is the
 * control: it isolates container handling from detection quality, which a
 * single-format benchmark cannot do. Two kinds matter:
 *
 *   FALSE ALARM  benign flagged in a container but clean as text
 *   BLIND SPOT   attack caught as text but missed in a container
 *
 * Run against a live Warden: bun eval/format-probe.ts
 */
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";

const CORPUS = process.env.CORPUS ?? "eval/cases/corpus.jsonl";
const N = Number(process.env.N ?? 120);
const CONC = Number(process.env.CONC ?? 8);
const URL_BASE = process.env.WARDEN_URL ?? "http://localhost:3000";
const AGENT = process.env.PROBE_AGENT ?? "format-probe";

interface Row { dataset: string; content: string; label: "attack" | "benign" }

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** Accent-folded, word-wrapped: a crude renderer would garble text and the garbling,
 *  not the container, would show up as the defect. */
function pdfLines(text: string): string[] {
  const folded = text.slice(0, 1200)
    .normalize("NFKD").replace(/[̀-ͯ]/g, "").replace(/[^\x20-\x7E\n]/g, " ");
  const out: string[] = [];
  for (const para of folded.split("\n")) {
    let line = "";
    for (const w of para.split(/\s+/)) {
      if (!w) continue;
      if ((line + " " + w).trim().length > 88) { out.push(line.trim()); line = w; }
      else line = (line + " " + w).trim();
    }
    if (line) out.push(line);
  }
  return out.length ? out : [folded];
}

async function makePdf(text: string): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([612, 792]);
  const font = await doc.embedFont(StandardFonts.Helvetica);
  page.drawText("Quarterly Report", { x: 50, y: 740, size: 16, font });
  let y = 700;
  for (const line of pdfLines(text).slice(0, 40)) {
    page.drawText(line, { x: 50, y, size: 9, font, color: rgb(0, 0, 0) });
    y -= 13;
    if (y < 40) break;
  }
  return doc.save();
}

function wrap(source: string, text: string): string {
  switch (source) {
    case "api_json":
      return JSON.stringify({ status: "ok", data: { ticket: { id: 4471, body: text } } });
    case "html":
      return `<!doctype html><html><body><h1>Knowledge base</h1><p>${esc(text)}</p></body></html>`;
    case "markdown":
      return `# Entry\n\n${text}\n`;
    case "email":
      return `From: support@acme.com\nTo: agent@company.com\nSubject: ticket 4471\n\n${text}`;
    case "code":
      return `// notes.ts\n/*\n${text.replace(/\*\//g, "* /")}\n*/\nexport const noop = () => {};`;
    case "mcp_tool_description":
      return `lookup_record — Looks up a customer record. ${text}`;
    default:
      return text;
  }
}

const TEXT_FORMATS = ["api_json", "html", "markdown", "email", "code", "mcp_tool_description"];

async function post(body: unknown): Promise<{ action: string; riskScore: number }> {
  const res = await fetch(`${URL_BASE}/scan`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body), signal: AbortSignal.timeout(120000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<{ action: string; riskScore: number }>;
}

// ---------------------------------------------------------------- run
const rows: Row[] = [];
for (const line of (await Bun.file(CORPUS).text()).split("\n")) {
  if (line.trim()) rows.push(JSON.parse(line));
}
const benign = rows.filter((r) => r.label === "benign");
const attacks = rows.filter((r) => r.label === "attack");
const pick = <T,>(a: T[], n: number) =>
  Array.from({ length: Math.min(n, a.length) }, (_, i) => a[Math.floor(i * (a.length / Math.min(n, a.length)))]);
const cases = [...pick(benign, Math.floor(N / 2)), ...pick(attacks, Math.ceil(N / 2))];

interface Delta { falseAlarm: number; blindSpot: number; n: number }
const byFormat = new Map<string, Delta>();
const examples: string[] = [];
let done = 0, errors = 0;
const started = Date.now();

async function probe(r: Row) {
  try {
    const base = await post({ content: r.content, source: "user_message", agentId: AGENT });
    const baseFlagged = base.action !== "ALLOW";

    const variants: [string, unknown][] = TEXT_FORMATS.map((f) =>
      [f, { content: wrap(f, r.content), source: f, agentId: AGENT }] as [string, unknown]);
    variants.push(["pdf", {
      contentBase64: Buffer.from(await makePdf(r.content)).toString("base64"),
      source: "pdf", agentId: AGENT,
    }]);

    for (const [fmt, body] of variants) {
      let v: { action: string; riskScore: number };
      try { v = await post(body); } catch { errors++; continue; }
      const flagged = v.action !== "ALLOW";
      if (!byFormat.has(fmt)) byFormat.set(fmt, { falseAlarm: 0, blindSpot: 0, n: 0 });
      const d = byFormat.get(fmt)!;
      d.n++;
      if (r.label === "benign" && flagged && !baseFlagged) {
        d.falseAlarm++;
        if (examples.length < 25)
          examples.push(`FALSE ALARM  ${fmt.padEnd(21)} ${v.action} ${v.riskScore.toFixed(2)} | ${r.content.slice(0, 54).replace(/\n/g, " ")}`);
      }
      if (r.label === "attack" && !flagged && baseFlagged) {
        d.blindSpot++;
        if (examples.length < 25)
          examples.push(`BLIND SPOT   ${fmt.padEnd(21)} base=${base.action} | ${r.content.slice(0, 54).replace(/\n/g, " ")}`);
      }
    }
  } catch { errors++; }
  if (++done % 20 === 0) process.stderr.write(`  ${done}/${cases.length}\n`);
}

let idx = 0;
await Promise.all(Array.from({ length: CONC }, async () => {
  while (idx < cases.length) await probe(cases[idx++]);
}));

console.log("\n" + "=".repeat(72));
console.log(`FORMAT EQUIVALENCE — ${cases.length} payloads x ${TEXT_FORMATS.length + 1} containers`);
console.log("  control: the same payload as plain user_message");
console.log("=".repeat(72));
console.log("\n  " + "container".padEnd(24) + "false alarms".padEnd(16) + "blind spots");
let tf = 0, tb = 0;
for (const [f, d] of [...byFormat.entries()].sort()) {
  tf += d.falseAlarm; tb += d.blindSpot;
  console.log("  " + f.padEnd(24) + `${d.falseAlarm}`.padEnd(16) + `${d.blindSpot}`);
}
console.log(`\n  total false alarms ${tf}   total blind spots ${tb}   errors ${errors}`);
if (examples.length) {
  console.log("\n  examples:");
  for (const e of examples) console.log("    " + e);
}
console.log(`\n  ${((Date.now() - started) / 1000).toFixed(0)}s\n`);
