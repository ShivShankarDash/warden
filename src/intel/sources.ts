/**
 * Threat intelligence source definitions and parsers.
 *
 * Defines the public datasets and repos Warden monitors for new prompt-injection
 * examples. Each source carries its own parser that knows the API response shape
 * and extracts IntelItems the processor can seed into memory.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IntelSource {
  name: string;
  type: "huggingface_dataset" | "github_repo" | "rss_feed";
  url: string;
  /** Hours between fetches. */
  checkInterval: number;
  parser: (raw: any) => IntelItem[];
}

export interface IntelItem {
  text: string;
  isAttack: boolean;
  attackType?: string;
  source: string;
  /** Timestamp of the item — use the upstream date, not Date.now(). */
  fetchedAt: number;
  /** When false the processor skips seeding this item into memory. Defaults to true. */
  seedable?: boolean;
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/** Parser for deepset/prompt-injections — field 'text', label 1 = attack. */
function parseDeepset(raw: any): IntelItem[] {
  const rows: any[] = raw?.rows ?? [];
  const now = Date.now();
  return rows
    .filter((r: any) => r?.row?.text && typeof r.row.text === "string")
    .map((r: any) => ({
      text: r.row.text,
      isAttack: r.row.label === 1 || r.row.label === "1",
      attackType: r.row.label === 1 || r.row.label === "1" ? "instruction_override" : undefined,
      source: "deepset/prompt-injections",
      fetchedAt: now,
    }));
}

/** Parser for neuralchemy/Prompt-injection-dataset — field 'text', label 1 = attack. */
function parseNeuralchemy(raw: any): IntelItem[] {
  const rows: any[] = raw?.rows ?? [];
  const now = Date.now();
  return rows
    .filter((r: any) => r?.row?.text && typeof r.row.text === "string")
    .map((r: any) => ({
      text: r.row.text,
      isAttack: r.row.label === 1 || r.row.label === "1",
      attackType: r.row.label === 1 || r.row.label === "1" ? "instruction_override" : undefined,
      source: "neuralchemy/Prompt-injection-dataset",
      fetchedAt: now,
    }));
}

/** Parser for Antijection/prompt-injection-dataset-v1 — field 'prompt', label 'injection' = attack. */
function parseAntijection(raw: any): IntelItem[] {
  const rows: any[] = raw?.rows ?? [];
  const now = Date.now();
  return rows
    .filter((r: any) => r?.row?.prompt && typeof r.row.prompt === "string")
    .map((r: any) => ({
      text: r.row.prompt,
      isAttack: r.row.label === "injection",
      attackType: r.row.label === "injection" ? "instruction_override" : undefined,
      source: "Antijection/prompt-injection-dataset-v1",
      fetchedAt: now,
    }));
}

/**
 * Parser for JailbreakBench releases — currently disabled.
 *
 * Release bodies are changelogs and contributor lists, not jailbreak prompts.
 * Seeding them as attack references would pollute similarity memory. A proper
 * parser would fetch actual jailbreak artifacts from the repo's data files.
 * Returns empty until that parser exists.
 */
function parseJailbreakBenchReleases(_raw: any): IntelItem[] {
  // TODO: parse actual jailbreak artifacts from data files, not release notes.
  return [];
}

/**
 * Parser for BIPIA commits — commit messages are technique signals, not attacks.
 *
 * Uses the commit's author date as fetchedAt so the dedup filter in fetchGitHub
 * works correctly. Items are marked seedable: false because commit messages like
 * "Fix typo in README" are not representative of benign user prompts and would
 * add noise to the safe-reference pool.
 */
function parseBIPIACommits(raw: any): IntelItem[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((r: any) => r?.commit?.message && typeof r.commit.message === "string")
    .map((r: any) => ({
      text: r.commit.message,
      isAttack: false,
      source: "microsoft/BIPIA",
      fetchedAt: r.commit?.author?.date
        ? new Date(r.commit.author.date).getTime()
        : Date.now(),
      seedable: false,
    }));
}

// ---------------------------------------------------------------------------
// Default sources
// ---------------------------------------------------------------------------

export const DEFAULT_SOURCES: IntelSource[] = [
  {
    name: "deepset/prompt-injections",
    type: "huggingface_dataset",
    url: "https://datasets-server.huggingface.co/rows?dataset=deepset/prompt-injections&config=default&split=train",
    checkInterval: 12,
    parser: parseDeepset,
  },
  {
    name: "neuralchemy/Prompt-injection-dataset",
    type: "huggingface_dataset",
    url: "https://datasets-server.huggingface.co/rows?dataset=neuralchemy/Prompt-injection-dataset&config=default&split=train",
    checkInterval: 12,
    parser: parseNeuralchemy,
  },
  {
    name: "Antijection/prompt-injection-dataset-v1",
    type: "huggingface_dataset",
    url: "https://datasets-server.huggingface.co/rows?dataset=Antijection/prompt-injection-dataset-v1&config=default&split=train",
    checkInterval: 12,
    parser: parseAntijection,
  },
  {
    name: "JailbreakBench/jailbreakbench",
    type: "github_repo",
    url: "https://api.github.com/repos/JailbreakBench/jailbreakbench/releases",
    checkInterval: 24,
    parser: parseJailbreakBenchReleases,
  },
  {
    name: "microsoft/BIPIA",
    type: "github_repo",
    url: "https://api.github.com/repos/microsoft/BIPIA/commits",
    checkInterval: 24,
    parser: parseBIPIACommits,
  },
];

// ---------------------------------------------------------------------------
// Custom sources
// ---------------------------------------------------------------------------

const customSources: IntelSource[] = [];

/**
 * Returns enabled intel sources. When enabledIds is provided, only sources whose
 * name is in the list are returned. Custom sources registered via registerSource()
 * are always included in the candidate set.
 */
export function getEnabledSources(enabledIds?: string[]): IntelSource[] {
  const all = [...DEFAULT_SOURCES, ...customSources];
  if (!enabledIds || enabledIds.length === 0) return all;
  const idSet = new Set(enabledIds);
  return all.filter((s) => idSet.has(s.name));
}

/**
 * Register a user-defined intel source at runtime.
 */
export function registerSource(source: IntelSource): void {
  customSources.push(source);
}

/**
 * Removes all custom sources. Used by tests to prevent cross-test leaks from
 * the module-level customSources array.
 */
export function clearCustomSources(): void {
  customSources.length = 0;
}
