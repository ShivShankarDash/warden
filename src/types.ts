export type SourceType =
  | "user_message"
  | "html"
  | "email"
  | "pdf"
  | "docx"
  | "markdown"
  | "api_json"
  | "code"
  | "ocr_text"
  | "image"
  | "mcp_tool_description"
  | "a2a_message";

export type AttackType =
  | "instruction_override"
  | "role_change"
  | "secret_extraction"
  | "tool_abuse"
  | "credential_theft"
  | "context_poisoning"
  | "multi_step_jailbreak"
  | "encoded_instructions"
  | "indirect_injection";

export type Action =
  | "ALLOW"
  | "SPOTLIGHT"
  | "SANITIZE"
  | "QUARANTINE"
  | "BLOCK"
  | "HUMAN_REVIEW";

export type Stage =
  | "extract"
  | "decode"
  | "rules"
  | "classifier"
  | "similarity"
  | "judge"
  | "session";

export interface ScanRequest {
  content: string | Uint8Array;
  source: SourceType;
  /** Identity of the sender — email address, domain, MCP server name. Distinct from
   *  `source`, which is the content type. Drives per-identity reputation. */
  sourceId?: string;
  sessionId?: string;
  agentId: string;
  metadata?: Record<string, unknown>;
}

export interface Finding {
  attackType: AttackType;
  confidence: number;
  stage: Stage;
  spans: { start: number; end: number; text: string }[];
  reason: string;
}

export interface ScanResult {
  id: string;
  action: Action;
  findings: Finding[];
  sanitizedContent?: string;
  riskScore: number;
  sessionRisk?: number;
  /**
   * True when the judge was referred but deferred to the background, so this verdict
   * is provisional. Callers must not read the absence of a judge finding as an
   * acquittal — same distinction the trace draws with "judge_unavailable".
   */
  judgePending?: boolean;
  trace: {
    stage: string;
    ms: number;
    score?: number;
    skipped?: boolean;
    error?: string;
  }[];
  createdAt: number;
}

export interface ToolCallCheck {
  agentId: string;
  sessionId: string;
  tool: string;
  args: Record<string, unknown>;
  argProvenance?: Record<string, "trusted" | "tainted">;
}

export interface ToolCallResult {
  allowed: boolean;
  reason: string;
  blockedArgs?: string[];
}

export interface ExtractResult {
  visibleText: string;
  hiddenText: string;
  provenance: {
    source: SourceType;
    hiddenSections: { type: string; content: string }[];
  };
}

export interface DecodeResult {
  text: string;
  decodingApplied: string[];
  depth: number;
}

export interface StageResult {
  stage: Stage;
  ms: number;
  findings: Finding[];
  score: number;
  skipped: boolean;
  error?: string;
}

export interface Policy {
  agentId: string;
  /** What to do when a detection stage errors: "closed" treats the failure as
   *  suspicious, "open" ignores it and lets the content through. */
  failMode: "closed" | "open";
  thresholds: {
    /** Minimum confidence for a rule hit to count as a finding. */
    rules: number;
    /** Minimum confidence for the classifier to report an injection. */
    classifier: number;
    /** Cosine above which the similarity stage reports a known-attack match. */
    similarity: number;
    /** Minimum score that justifies spending a judge call. */
    judge: number;
    /** Accumulated session risk at which a trajectory escalates. */
    session: number;
    /** Score at or above which remaining stages are skipped and the action is BLOCK. */
    highConfidence: number;
    /** Classifier benign-confidence below which the content is referred to the judge. */
    benignCertainty: number;
  };
  /**
   * Whether the LLM judge runs on the request path.
   *
   * "sync" (default) waits for the verdict, so the judge can acquit and the returned
   * action is final. "async" returns on the fast-stage verdict and runs the judge
   * out-of-band — p50 drops from ~1.4s to ~10ms on referred content, at the cost of
   * the judge no longer influencing *this* scan. See JUDGE_ALWAYS_SYNC in judge.ts
   * for the sources that ignore this setting.
   */
  judgeMode?: "sync" | "async";
  allowedTools: string[];
  sourceOverrides?: Partial<Record<SourceType, { failMode: "closed" | "open" }>>;
}
