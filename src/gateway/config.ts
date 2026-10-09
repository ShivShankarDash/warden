/** A locally spawned server, launched as a child process speaking stdio. */
export interface StdioUpstream {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  disabled?: boolean;
}

/** A remote server reached over HTTP. */
export interface HttpUpstream {
  url: string;
  /** Extra headers, typically auth. */
  headers?: Record<string, string>;
  /**
   * Which HTTP transport to use. Omit to try Streamable HTTP and fall back to SSE —
   * hosted servers vary, and the older SSE transport is still common.
   */
  transport?: "http" | "sse";
  disabled?: boolean;
}

export type UpstreamSpec = StdioUpstream | HttpUpstream;

export function isHttpUpstream(spec: UpstreamSpec): spec is HttpUpstream {
  return typeof (spec as HttpUpstream).url === "string";
}

export interface PolicyConfig {
  failMode?: "closed" | "open";
  judgeMode?: "sync" | "async";
  thresholds?: {
    classifier?: number;
    similarity?: number;
    rules?: number;
    judge?: number;
    session?: number;
    highConfidence?: number;
    benignCertainty?: number;
  };
}

export interface JudgeConfig {
  provider?: string;
  model?: string;
  apiKey?: string;
  baseUrl?: string;
}

export interface GatewayConfig {
  upstreams: Record<string, UpstreamSpec>;
  policy?: PolicyConfig;
  judge?: JudgeConfig;
}

const DEFAULT_PATHS = [".warden.json", "warden-mcp.json"];

/**
 * Accepts either Warden's own shape (`{ upstreams: {...} }`) or a host's existing
 * `mcp.json` (`{ mcpServers: {...} }`), so moving servers behind the gateway is a
 * copy rather than a rewrite. Entries marked `disabled` are skipped, matching how
 * hosts treat that flag.
 */
export async function loadConfig(
  explicitPath?: string
): Promise<GatewayConfig> {
  // When an explicit path is given, use only that path (no fallback).
  if (explicitPath) {
    const file = Bun.file(explicitPath);
    if (!(await file.exists())) {
      throw new Error(
        `No gateway config at ${explicitPath}. Create one, or omit --config to auto-discover.`
      );
    }
    return parseConfigFile(await file.text());
  }

  // Auto-discover: try default paths, then WARDEN_MCP_CONFIG env var.
  for (const candidate of DEFAULT_PATHS) {
    const file = Bun.file(candidate);
    if (await file.exists()) {
      return parseConfigFile(await file.text());
    }
  }

  // Try env var as fallback.
  const envPath = process.env.WARDEN_MCP_CONFIG;
  if (envPath) {
    const file = Bun.file(envPath);
    if (await file.exists()) {
      return parseConfigFile(await file.text());
    }
  }

  // No config file found — return empty config so Warden can start in API-only mode.
  return { upstreams: {} };
}

function parseConfigFile(text: string): GatewayConfig {
  const parsed = JSON.parse(text);
  const raw: Record<string, UpstreamSpec> = parsed.upstreams ?? parsed.mcpServers ?? {};

  const upstreams: Record<string, UpstreamSpec> = {};
  for (const [name, spec] of Object.entries(raw)) {
    if (spec.disabled) continue;
    if (!isHttpUpstream(spec) && !(spec as StdioUpstream).command) {
      throw new Error(`Upstream "${name}" has neither "command" (stdio) nor "url" (http).`);
    }
    upstreams[name] = spec;
  }

  return {
    upstreams,
    policy: parsed.policy,
    judge: parsed.judge,
  };
}

/**
 * Translates config.policy and config.judge blocks into environment variables
 * so the policy loader, judge, and other subsystems pick them up. Must be called
 * BEFORE initWarden() so env vars are in place when the policy loader reads them.
 */
export function applyConfigToEnv(config: GatewayConfig): void {
  const { policy, judge } = config;

  if (policy) {
    if (policy.failMode) process.env.WARDEN_FAIL_MODE = policy.failMode;
    if (policy.judgeMode) process.env.JUDGE_MODE = policy.judgeMode;
    if (policy.thresholds) {
      const t = policy.thresholds;
      if (t.classifier != null) process.env.CLASSIFIER_THRESHOLD = String(t.classifier);
      if (t.similarity != null) process.env.SIMILARITY_THRESHOLD = String(t.similarity);
      if (t.rules != null) process.env.RULES_THRESHOLD = String(t.rules);
      if (t.judge != null) process.env.JUDGE_THRESHOLD = String(t.judge);
      if (t.session != null) process.env.SESSION_THRESHOLD = String(t.session);
      if (t.highConfidence != null) process.env.HIGH_CONFIDENCE_THRESHOLD = String(t.highConfidence);
      if (t.benignCertainty != null) process.env.BENIGN_CERTAINTY_THRESHOLD = String(t.benignCertainty);
    }
  }

  if (judge) {
    if (judge.provider) process.env.JUDGE_PROVIDER = judge.provider;
    if (judge.model) process.env.JUDGE_MODEL = judge.model;
    if (judge.apiKey) process.env.OPENAI_API_KEY = judge.apiKey;
    if (judge.baseUrl) process.env.JUDGE_BASE_URL = judge.baseUrl;
  }
}
