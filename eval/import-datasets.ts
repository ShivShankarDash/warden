import type { SourceType, AttackType, Action } from "../src/types.ts";

interface EvalCase {
  id: string;
  source: SourceType;
  content: string;
  label: "malicious" | "benign";
  expected_attacks: AttackType[];
  expected_action: Action;
  notes?: string;
}

interface HFRow {
  row_idx: number;
  row: Record<string, unknown>;
}

interface HFResponse {
  rows: HFRow[];
  num_rows_total: number;
}

// ── Attack type heuristics (applied when dataset has no fine-grained label) ──

const ATTACK_PATTERNS: { type: AttackType; patterns: RegExp[] }[] = [
  {
    type: "encoded_instructions",
    patterns: [/[A-Za-z0-9+/]{30,}={0,2}/, /\\u[0-9a-f]{4}/i, /&#x[0-9a-f]+;/i],
  },
  {
    type: "role_change",
    patterns: [
      /you are now/i, /act as/i, /pretend (you are|to be)/i,
      /\|\|.*system.*\|/i, /\[INST\]/i, /###\s*System/i, /im_start.*system/i,
    ],
  },
  {
    type: "credential_theft",
    patterns: [/api.?key/i, /\.env/i, /password/i, /bearer token/i, /secret key/i],
  },
  {
    type: "secret_extraction",
    patterns: [
      /system prompt/i, /reveal your/i, /show me your (instructions|rules|prompt)/i,
      /what are your instructions/i, /repeat (everything|your)/i,
    ],
  },
  {
    type: "tool_abuse",
    patterns: [/call.*send_email/i, /execute.*tool/i, /run.*function/i, /invoke/i],
  },
  {
    type: "indirect_injection",
    patterns: [/\[hidden\]/i, /<!--.*-->/i, /display:\s*none/i],
  },
  {
    type: "instruction_override",
    patterns: [
      /ignore (all |your |the |previous |above )?instructions/i,
      /disregard/i, /forget (everything|all|your)/i,
      /new (directive|instruction|task)/i, /override/i, /supersede/i,
    ],
  },
];

function guessAttackType(text: string): AttackType[] {
  const found = new Set<AttackType>();
  for (const { type, patterns } of ATTACK_PATTERNS) {
    if (patterns.some((re) => re.test(text))) found.add(type);
  }
  return found.size ? [...found] : ["instruction_override"];
}

function guessSource(text: string): SourceType {
  if (/<html|<body|<div|<script/i.test(text)) return "html";
  if (/^From:|^Subject:|^To:/m.test(text)) return "email";
  if (/```|def |function |import |class /m.test(text)) return "code";
  if (/^\s*[{[]/.test(text.trim())) return "api_json";
  return "user_message";
}

// ── HuggingFace rows API fetcher ──

const HF_PAGE_SIZE = 100; // API hard cap

async function fetchHF(
  dataset: string,
  split: string,
  limit: number,
  offset = 0
): Promise<HFRow[]> {
  const url = `https://datasets-server.huggingface.co/rows?dataset=${encodeURIComponent(dataset)}&config=default&split=${split}&offset=${offset}&limit=${Math.min(limit, HF_PAGE_SIZE)}`;
  const res = await fetch(url, { headers: { "User-Agent": "warden-eval-importer/0.1" } });
  if (!res.ok) throw new Error(`HF API error ${res.status} for ${dataset}: ${await res.text()}`);
  const data = (await res.json()) as HFResponse;
  return data.rows;
}

// Paginate through a dataset collecting only rows that pass a filter, up to maxRows
async function fetchHFPaginated(
  dataset: string,
  split: string,
  filter: (row: Record<string, unknown>) => boolean,
  maxRows: number
): Promise<HFRow[]> {
  const results: HFRow[] = [];
  let offset = 0;
  let total: number | null = null;

  while (results.length < maxRows) {
    const url = `https://datasets-server.huggingface.co/rows?dataset=${encodeURIComponent(dataset)}&config=default&split=${split}&offset=${offset}&limit=${HF_PAGE_SIZE}`;
    const res = await fetch(url, { headers: { "User-Agent": "warden-eval-importer/0.1" } });
    if (!res.ok) break;
    const data = (await res.json()) as HFResponse;
    if (total === null) total = data.num_rows_total;

    for (const row of data.rows) {
      if (filter(row.row)) results.push(row);
    }

    offset += HF_PAGE_SIZE;
    if (offset >= (total ?? 0)) break;
  }

  return results.slice(0, maxRows);
}

// ── Dataset importers ──

async function importDeepset(maxAttack = 120, maxBenign = 40): Promise<EvalCase[]> {
  console.log("Fetching deepset/prompt-injections (paginating for attacks + benign)...");

  const [attackRows, benignRows] = await Promise.all([
    fetchHFPaginated("deepset/prompt-injections", "train", (r) => Number(r.label) === 1, maxAttack),
    fetchHFPaginated("deepset/prompt-injections", "train", (r) => Number(r.label) === 0, maxBenign),
  ]);

  const toCase = (isInjection: boolean) => ({ row_idx, row }: HFRow): EvalCase => {
    const text = String(row.text ?? "").trim();
    return {
      id: `deepset-${String(row_idx).padStart(4, "0")}`,
      source: guessSource(text),
      content: text,
      label: isInjection ? "malicious" : "benign",
      expected_attacks: isInjection ? guessAttackType(text) : [],
      expected_action: isInjection ? "BLOCK" : "ALLOW",
      notes: "deepset/prompt-injections — review expected_attacks label",
    };
  };

  const cases = [
    ...attackRows.filter((r) => String(r.row.text ?? "").trim()).map(toCase(true)),
    ...benignRows.filter((r) => String(r.row.text ?? "").trim()).map(toCase(false)),
  ];

  console.log(`  deepset: ${cases.filter((c) => c.label === "malicious").length} attack, ${cases.filter((c) => c.label === "benign").length} benign`);
  return cases;
}

async function importNotInject(): Promise<EvalCase[]> {
  console.log("Fetching leolee99/NotInject (3 splits)...");
  // Splits: NotInject_one, NotInject_two, NotInject_three — ~113 rows each
  const splits = ["NotInject_one", "NotInject_two", "NotInject_three"];
  const allRows: HFRow[] = [];

  for (const split of splits) {
    try {
      const rows = await fetchHF("leolee99/NotInject", split, 113);
      allRows.push(...rows);
    } catch (e) {
      console.warn(`  NotInject ${split}: ${e}`);
    }
  }

  const cases: EvalCase[] = [];
  for (const { row_idx, row } of allRows) {
    const text = String(row.prompt ?? row.text ?? "").trim();
    if (!text || /[一-鿿Ѐ-ӿ]/.test(text.slice(0, 20))) continue; // skip non-English

    cases.push({
      id: `notinject-${String(row_idx).padStart(4, "0")}`,
      source: "user_message",
      content: text,
      label: "benign",
      expected_attacks: [],
      expected_action: "ALLOW",
      notes: `NotInject (${row.category ?? "?"}) — benign-but-scary: contains trigger word "${(row.word_list as string[] | undefined)?.[0] ?? "?"}" but is NOT an attack`,
    });
  }

  console.log(`  NotInject: ${cases.length} benign-but-scary cases`);
  return cases;
}

async function importPromptSentinel(limit = 100): Promise<EvalCase[]> {
  // Try multiple known splits/configs for this dataset
  const attempts: { split: string }[] = [
    { split: "train" },
    { split: "test" },
    { split: "validation" },
  ];

  console.log("Fetching nuhmanpk/prompt-sentinel...");
  let rows: HFRow[] = [];

  for (const { split } of attempts) {
    try {
      rows = await fetchHF("nuhmanpk/prompt-sentinel", split, limit);
      if (rows.length) { console.log(`  sentinel: using split="${split}"`); break; }
    } catch { /* try next */ }
  }

  if (!rows.length) {
    console.warn("  sentinel: no rows found across all splits — skipping");
    return [];
  }

  const cases: EvalCase[] = [];
  for (const { row_idx, row } of rows) {
    const text = String(row.text ?? row.prompt ?? row.content ?? row.instruction ?? "").trim();
    const rawLabel = String(row.label ?? row.category ?? row.type ?? "").toLowerCase();
    const isInjection = rawLabel.includes("inject") || rawLabel === "1" || rawLabel === "unsafe" || rawLabel === "malicious";
    if (!text) continue;

    cases.push({
      id: `sentinel-${String(row_idx).padStart(4, "0")}`,
      source: guessSource(text),
      content: text,
      label: isInjection ? "malicious" : "benign",
      expected_attacks: isInjection ? guessAttackType(text) : [],
      expected_action: isInjection ? "BLOCK" : "ALLOW",
      notes: "nuhmanpk/prompt-sentinel — review expected_attacks label",
    });
  }

  console.log(`  sentinel: ${cases.filter((c) => c.label === "malicious").length} attack, ${cases.filter((c) => c.label === "benign").length} benign`);
  return cases;
}

async function importHorizonEval(limit = 100): Promise<EvalCase[]> {
  console.log("Fetching Horizon-Labs/prompt-injection-eval-suite...");
  try {
    const rows = await fetchHF("Horizon-Labs/prompt-injection-eval-suite", "test", limit);
    const cases: EvalCase[] = [];

    for (const { row_idx, row } of rows) {
      const text = String(row.prompt ?? row.text ?? row.input ?? "").trim();
      const rawLabel = String(row.label ?? row.is_injection ?? "").toLowerCase();
      const isInjection = rawLabel === "1" || rawLabel === "true" || rawLabel.includes("inject");
      if (!text) continue;

      cases.push({
        id: `horizon-${String(row_idx).padStart(4, "0")}`,
        source: guessSource(text),
        content: text,
        label: isInjection ? "malicious" : "benign",
        expected_attacks: isInjection ? guessAttackType(text) : [],
        expected_action: isInjection ? "BLOCK" : "ALLOW",
        notes: "Horizon-Labs/prompt-injection-eval-suite — review expected_attacks label",
      });
    }

    console.log(`  horizon-eval: ${cases.filter((c) => c.label === "malicious").length} attack, ${cases.filter((c) => c.label === "benign").length} benign`);
    return cases;
  } catch (e) {
    console.warn(`  horizon-eval: fetch failed (${e}) — skipping`);
    return [];
  }
}

// ── Deduplication by content hash ──

function deduplicate(cases: EvalCase[]): EvalCase[] {
  const seen = new Set<string>();
  return cases.filter((c) => {
    const key = c.content.slice(0, 100).toLowerCase().replace(/\s+/g, " ");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ── Main ──

async function main() {
  const args = process.argv.slice(2);
  const limitArg = parseInt(args.find((a) => a.startsWith("--limit="))?.split("=")[1] ?? "200");

  console.log("\nWARDEN — Dataset importer");
  console.log(`Fetching up to ${limitArg} rows per dataset...\n`);

  const [deepset, notinject, sentinel, horizon] = await Promise.allSettled([
    importDeepset(120, 40),
    importNotInject(339),
    importPromptSentinel(100),
    importHorizonEval(100),
  ]);

  const allCases: EvalCase[] = [
    ...(deepset.status === "fulfilled" ? deepset.value : []),
    ...(sentinel.status === "fulfilled" ? sentinel.value : []),
    ...(horizon.status === "fulfilled" ? horizon.value : []),
  ];

  const benignCases: EvalCase[] = [
    ...(notinject.status === "fulfilled" ? notinject.value : []),
    ...allCases.filter((c) => c.label === "benign"),
  ];

  const attackCases = deduplicate(allCases.filter((c) => c.label === "malicious"));
  const deduped_benign = deduplicate(benignCases);

  // Cap to reasonable sizes
  const finalAttack = attackCases.slice(0, 120);
  const finalBenign = deduped_benign.slice(0, 60);

  // Save
  await Bun.write("eval/cases/from-datasets-attacks.json", JSON.stringify(finalAttack, null, 2));
  await Bun.write("eval/cases/from-datasets-benign.json", JSON.stringify(finalBenign, null, 2));

  console.log("\n── Summary ──────────────────────────────────────");
  console.log(`Attack cases saved: ${finalAttack.length}  →  eval/cases/from-datasets-attacks.json`);
  console.log(`Benign cases saved: ${finalBenign.length}  →  eval/cases/from-datasets-benign.json`);
  console.log("\n── What to do next ──────────────────────────────");
  console.log("1. Open from-datasets-attacks.json");
  console.log("   For each case: check expected_attacks[] — the importer guesses, but you decide.");
  console.log("   Assign the correct AttackType(s) from:");
  console.log("   instruction_override | role_change | secret_extraction | tool_abuse |");
  console.log("   credential_theft | context_poisoning | multi_step_jailbreak |");
  console.log("   encoded_instructions | indirect_injection");
  console.log("2. For cases that are clearly email/html/pdf in content, fix the source field.");
  console.log("3. Delete cases that are low quality (too short, nonsensical, duplicates of each other).");
  console.log("4. Run: bun run eval");
}

main().catch(console.error);
