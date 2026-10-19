#!/usr/bin/env bun
/**
 * False-positive audit against real-world documents.
 *
 * The dataset benchmark measures short, prompt-shaped samples. An IDE feeds
 * Warden something else entirely: multi-kilobyte READMEs, changelogs and source
 * files, where a single classifier hit was enough to block the read. This audit
 * scores that distribution directly — benign documents from node_modules on one
 * side, the curated attack corpus on the other — so a change to detection can be
 * judged on both at once rather than on recall alone.
 *
 *   bun eval/fp-audit.ts [--limit N] [--url http://localhost:3000]
 */

import { readFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";

const args = process.argv.slice(2);
const flag = (name: string, fallback: string) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};

const URL_BASE = flag("--url", process.env.WARDEN_URL ?? "http://localhost:3000");
const LIMIT = parseInt(flag("--limit", "120"), 10);

type Case = { id: string; content: string; source: string; benign: boolean };

/** Benign: package READMEs and changelogs — ordinary prose an agent reads daily. */
function benignCorpus(limit: number): Case[] {
  const root = join(import.meta.dir, "..", "node_modules");
  if (!existsSync(root)) return [];
  const out: Case[] = [];
  for (const pkg of readdirSync(root).sort()) {
    if (out.length >= limit) break;
    for (const name of ["README.md", "readme.md", "CHANGELOG.md"]) {
      const p = join(root, pkg, name);
      if (!existsSync(p)) continue;
      let content: string;
      try {
        content = readFileSync(p, "utf-8");
      } catch {
        continue;
      }
      if (content.trim().length < 200) continue;
      out.push({ id: `${pkg}/${name}`, content: content.slice(0, 50_000), source: "markdown", benign: true });
      break;
    }
  }
  return out;
}

/** Attacks: the curated corpus, so a false-positive fix cannot quietly cost recall. */
function attackCorpus(limit: number): Case[] {
  const dir = join(import.meta.dir, "cases");
  const out: Case[] = [];
  for (const file of ["from-datasets-attacks.json", "multi-source-attacks.json", "examples.json"]) {
    const p = join(dir, file);
    if (!existsSync(p)) continue;
    const items = JSON.parse(readFileSync(p, "utf-8")) as any[];
    for (const c of items) {
      if (out.length >= limit) break;
      if (!["attack", "malicious"].includes(c.label) || typeof c.content !== "string") continue;
      out.push({ id: c.id, content: c.content, source: c.source ?? "api_json", benign: false });
    }
  }
  return out;
}

async function scanOne(c: Case): Promise<{ action: string; risk: number; stages: string[]; why: string }> {
  const res = await fetch(`${URL_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: c.content, source: c.source, agentId: "fp-audit" }),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  const j = (await res.json()) as any;
  const why = (j.findings ?? [])
    .map((f: any) => String(f.reason ?? "").slice(0, 70))
    .slice(0, 1)
    .join("");
  return {
    action: j.action,
    risk: j.riskScore ?? 0,
    stages: [...new Set((j.findings ?? []).map((f: any) => f.stage ?? "?"))] as string[],
    why,
  };
}

/** A verdict the IDE hooks turn into a block: anything at HUMAN_REVIEW or above. */
const BLOCKS = new Set(["HUMAN_REVIEW", "QUARANTINE", "BLOCK"]);

const main = async () => {
  const benign = benignCorpus(LIMIT);
  const attacks = attackCorpus(LIMIT);
  console.log(`benign: ${benign.length} docs   attacks: ${attacks.length} cases   → ${URL_BASE}\n`);

  let fp = 0;
  const fpDetail: string[] = [];
  const byStage = new Map<string, number>();
  for (const c of benign) {
    try {
      const r = await scanOne(c);
      if (BLOCKS.has(r.action)) {
        fp++;
        if (fpDetail.length < 30) fpDetail.push(`   ${c.id} → ${r.action} ${r.risk.toFixed(2)} [${r.stages.join(",")}] ${r.why}`);
        for (const s of r.stages) byStage.set(s, (byStage.get(s) ?? 0) + 1);
      }
    } catch (e: any) {
      console.error(`   scan failed on ${c.id}: ${e.message}`);
    }
  }

  let caught = 0;
  const misses: string[] = [];
  const caughtByStage = new Map<string, number>();
  let classifierOnly = 0;
  for (const c of attacks) {
    try {
      const r = await scanOne(c);
      if (BLOCKS.has(r.action)) {
        caught++;
        for (const s of r.stages) caughtByStage.set(s, (caughtByStage.get(s) ?? 0) + 1);
        if (r.stages.length === 1 && r.stages[0] === "classifier") classifierOnly++;
      } else if (misses.length < 10) misses.push(`   ${c.id} → ${r.action} ${r.risk.toFixed(2)}`);
    } catch {
      /* counted as a miss */
    }
  }

  const fpRate = benign.length ? (100 * fp) / benign.length : 0;
  const recall = attacks.length ? (100 * caught) / attacks.length : 0;

  console.log(`FALSE POSITIVES  ${fp}/${benign.length}  (${fpRate.toFixed(1)}%)`);
  if (fpDetail.length) console.log(fpDetail.join("\n"));
  if (byStage.size) {
    console.log("   by stage: " + [...byStage.entries()].map(([s, n]) => `${s}=${n}`).join(" "));
  }
  console.log(`\nRECALL           ${caught}/${attacks.length}  (${recall.toFixed(1)}%)`);
  if (caughtByStage.size) {
    console.log("   by stage: " + [...caughtByStage.entries()].map(([s, n]) => `${s}=${n}`).join(" "));
    console.log(`   caught by classifier ALONE (no corroboration): ${classifierOnly}`);
  }
  if (misses.length) console.log(misses.slice(0, 4).join("\n"));
  console.log(`\nSCORE            fp=${fpRate.toFixed(1)}%  recall=${recall.toFixed(1)}%`);
};

await main();
