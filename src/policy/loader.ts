import { parse } from "yaml";
import type { Policy, SourceType } from "../types.ts";

/**
 * Per-agent policy. Values here are the defaults every threshold in the pipeline
 * falls back to; a policy file overrides any subset of them.
 *
 * Environment variables still win over both, so a deployment can pin a value
 * without editing policy files.
 */
export const DEFAULT_POLICY: Policy = {
  agentId: "default",
  failMode: "closed",
  // Sync by default: the judge's ability to acquit is what holds the false-positive
  // rate at zero, and deferring it trades first-instance detection for latency.
  // Deployments that need the latency opt in explicitly.
  judgeMode: "sync",
  thresholds: {
    rules: 0,
    classifier: 0.6,
    similarity: 0.7,
    judge: 0.5,
    session: 0.8,
    highConfidence: 0.9,
    benignCertainty: 0.99,
  },
  allowedTools: [],
};

const cache = new Map<string, Policy>();

function envOverride(key: string, fallback: number): number {
  const raw = process.env[key];
  const n = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Agent ids that may be used to name a policy file.
 *
 * The id was interpolated straight into `./policies/${agentId}.yaml`, so it selected
 * any .yaml on the filesystem. An attacker who controls the id — a multi-tenant
 * caller, or anything that forwards a value from a request — could point it at a file
 * they could write and define their own policy. With `failMode: open` and thresholds
 * above 1.0, no score can reach them and the firewall stops blocking. Measured on the
 * same payload: agentId "normal-agent" gave BLOCK 0.95, and
 * "../../../../tmp/wprobe/evil" gave HUMAN_REVIEW 0.95 against a planted file.
 *
 * One leading alphanumeric, then word characters, dot, or dash. That admits every
 * real agent name and no path: no slash, no "..", no absolute path, no NUL.
 */
const SAFE_AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** Bounded so an attacker-chosen id cannot grow the map without limit. */
const MAX_CACHED_POLICIES = 512;

export async function loadPolicy(agentId: string): Promise<Policy> {
  const cached = cache.get(agentId);
  if (cached) return cached;

  let policy: Policy = DEFAULT_POLICY;

  // An id that cannot name a file gets the default policy, never a file read. It is
  // still a usable id everywhere else — memory and review rows are parameterised, so
  // the scan proceeds rather than failing — it simply cannot choose its own rules.
  const named = SAFE_AGENT_ID.test(agentId);
  if (!named && agentId !== DEFAULT_POLICY.agentId) {
    console.warn(
      `Agent id ${JSON.stringify(agentId.slice(0, 64))} cannot name a policy file; using defaults.`
    );
  }

  const file = named ? Bun.file(`./policies/${agentId}.yaml`) : null;
  if (file && await file.exists()) {
    try {
      const parsed = (parse(await file.text()) ?? {}) as Partial<Policy>;
      policy = {
        ...DEFAULT_POLICY,
        ...parsed,
        agentId,
        // Merge rather than replace, so a file setting one threshold doesn't drop the rest.
        thresholds: { ...DEFAULT_POLICY.thresholds, ...(parsed.thresholds ?? {}) },
      };
    } catch (e) {
      console.warn(`Policy for "${agentId}" is invalid, using defaults: ${e instanceof Error ? e.message : e}`);
    }
  }

  const envJudgeMode = process.env.JUDGE_MODE;
  policy = {
    ...policy,
    judgeMode:
      envJudgeMode === "sync" || envJudgeMode === "async"
        ? envJudgeMode
        : policy.judgeMode ?? "sync",
    thresholds: {
      rules: envOverride("RULES_THRESHOLD", policy.thresholds.rules),
      classifier: envOverride("CLASSIFIER_THRESHOLD", policy.thresholds.classifier),
      similarity: envOverride("SIMILARITY_THRESHOLD", policy.thresholds.similarity),
      judge: envOverride("JUDGE_THRESHOLD", policy.thresholds.judge),
      session: envOverride("SESSION_THRESHOLD", policy.thresholds.session),
      highConfidence: envOverride("HIGH_CONFIDENCE", policy.thresholds.highConfidence),
      benignCertainty: envOverride("BENIGN_CERTAINTY_THRESHOLD", policy.thresholds.benignCertainty),
    },
  };

  // Oldest-out when full. A caller that invents a fresh id per request would
  // otherwise hold one policy object per id for the life of the process.
  if (cache.size >= MAX_CACHED_POLICIES) {
    const oldest = cache.keys().next();
    if (!oldest.done) cache.delete(oldest.value);
  }
  cache.set(agentId, policy);
  return policy;
}

/** Source-specific fail mode, falling back to the agent's. */
export function failModeFor(policy: Policy, source: SourceType): "closed" | "open" {
  return policy.sourceOverrides?.[source]?.failMode ?? policy.failMode;
}

/** Policies are cached for the process lifetime; call this after editing one. */
export function clearPolicyCache(): void {
  cache.clear();
}
