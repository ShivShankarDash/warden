/**
 * Custom YAML Rules — operator-defined detection rules loaded from a YAML file.
 *
 * Loads rules from the path in WARDEN_CUSTOM_RULES env var, or the default
 * `policies/custom-rules.yaml`. Supports hot-reload: re-parses when the file's
 * mtime changes.
 *
 * @module detect/custom-rules
 */

import { parse } from "yaml";
import { statSync, readFileSync } from "fs";
import type { Finding, AttackType, SourceType } from "../types.ts";

// ── YAML schema ──────────────────────────────────────────────────────────────

interface RawCustomRule {
  name: string;
  pattern: string;
  attack_type: string;
  confidence: number;
  source_filter?: string[];
}

interface ParsedCustomRule {
  name: string;
  pattern: RegExp;
  attackType: AttackType;
  confidence: number;
  sourceFilter?: Set<SourceType>;
}

// ── Module-level cache ───────────────────────────────────────────────────────

let cachedRules: ParsedCustomRule[] = [];
let cachedMtime: number = 0;
let cachedPath: string | null = null;

// ── Helpers ──────────────────────────────────────────────────────────────────

function resolveFilePath(): string {
  return process.env.WARDEN_CUSTOM_RULES || "policies/custom-rules.yaml";
}

function getMtime(filePath: string): number {
  try {
    const stat = statSync(filePath);
    return stat.mtimeMs;
  } catch {
    return 0;
  }
}

function parseRules(raw: RawCustomRule[]): ParsedCustomRule[] {
  const parsed: ParsedCustomRule[] = [];
  for (const r of raw) {
    try {
      parsed.push({
        name: r.name,
        pattern: new RegExp(r.pattern, "i"),
        attackType: r.attack_type as AttackType,
        confidence: r.confidence,
        sourceFilter: r.source_filter
          ? new Set(r.source_filter as SourceType[])
          : undefined,
      });
    } catch (e) {
      // Invalid regex — skip this rule silently
      console.warn(
        `[custom-rules] Skipping rule "${r.name}": ${e instanceof Error ? e.message : e}`
      );
    }
  }
  return parsed;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Load (or reload) custom rules from the YAML file. Called automatically by
 * applyCustomRules on each invocation when the file mtime changes.
 *
 * Can also be called directly (e.g. at startup) to pre-warm the cache.
 */
export function loadCustomRules(): ParsedCustomRule[] {
  const filePath = resolveFilePath();
  const mtime = getMtime(filePath);

  // Return cache if same file and mtime hasn't changed
  if (filePath === cachedPath && mtime === cachedMtime && cachedRules.length > 0) {
    return cachedRules;
  }

  // File doesn't exist — return empty, no error
  if (mtime === 0) {
    cachedPath = filePath;
    cachedMtime = 0;
    cachedRules = [];
    return cachedRules;
  }

  try {
    const text = readFileSync(filePath, "utf-8");
    const doc = parse(text) as { rules?: RawCustomRule[] } | null;
    cachedRules = doc?.rules ? parseRules(doc.rules) : [];
  } catch (e) {
    console.warn(
      `[custom-rules] Failed to load "${filePath}": ${e instanceof Error ? e.message : e}`
    );
    cachedRules = [];
  }

  cachedPath = filePath;
  cachedMtime = mtime;
  return cachedRules;
}

/**
 * Apply operator-defined custom rules against the given text.
 *
 * Returns findings in the same shape as the built-in rule engine. Automatically
 * reloads the YAML file when its mtime changes (hot-reload).
 */
export function applyCustomRules(
  text: string,
  source: SourceType = "user_message"
): Finding[] {
  const rules = loadCustomRules();
  const findings: Finding[] = [];

  for (const rule of rules) {
    // Source filter: skip if the rule specifies sources and this one isn't included
    if (rule.sourceFilter && !rule.sourceFilter.has(source)) continue;

    const re = new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", "") + "g");
    const spans: { start: number; end: number; text: string }[] = [];
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
      spans.push({
        start: match.index,
        end: match.index + match[0].length,
        text: match[0],
      });
      if (!re.global) break;
    }

    if (!spans.length) continue;

    findings.push({
      attackType: rule.attackType,
      confidence: rule.confidence,
      stage: "rules",
      spans,
      reason: `Custom rule: ${rule.name}`,
    });
  }

  return findings;
}

/**
 * Reset the module-level cache. Useful for testing.
 */
export function resetCustomRulesCache(): void {
  cachedRules = [];
  cachedMtime = 0;
  cachedPath = null;
}
