import type { Finding } from "../types.ts";

/**
 * Output-side guard.
 *
 * The input pipeline stops injected instructions entering the model's context. This
 * stops the consequences leaving: a leaked system prompt, a credential in a reply,
 * or data smuggled out in a URL the model was told to fetch. Inbound detection is
 * never perfect, so the exfiltration path is defended separately.
 */

/** Hosts an agent is expected to talk to; URLs elsewhere are treated as egress. */
const DEFAULT_ALLOWED_HOSTS = (process.env.WARDEN_ALLOWED_HOSTS ?? "")
  .split(",")
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);

/** Query parameter names that typically carry smuggled payloads. */
const DATA_PARAM = /\b(data|q|text|content|session|token|payload|body|info|dump|c|s)\b/i;

const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "openai_key", re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { name: "anthropic_key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "github_token", re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { name: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{30,}\b/ },
  { name: "private_key", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

export interface OutputScanRequest {
  /** The model's response text, or a tool call serialised to text. */
  content: string;
  /** Canary values planted in the system prompt; any appearance means a leak. */
  canaries?: string[];
  /** Hosts this agent is allowed to reach, overriding the global default. */
  allowedHosts?: string[];
}

export interface OutputScanResult {
  allowed: boolean;
  findings: Finding[];
  riskScore: number;
}

/**
 * Creates a canary to plant in a system prompt. It never appears in legitimate
 * output, so finding one in a response is unambiguous evidence the prompt leaked —
 * no heuristics and no false positives.
 */
export function generateCanary(): string {
  return `WARDEN-CANARY-${crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`;
}

function finding(
  attackType: Finding["attackType"],
  confidence: number,
  reason: string,
  spans: Finding["spans"] = []
): Finding {
  return { attackType, confidence, stage: "session", spans, reason };
}

function findSpan(text: string, needle: string) {
  const start = text.indexOf(needle);
  return start === -1 ? [] : [{ start, end: start + needle.length, text: needle }];
}

function extractUrls(text: string): string[] {
  return text.match(/https?:\/\/[^\s<>"')\]]+/gi) ?? [];
}

/** Markdown images render without a click, so they exfiltrate silently. */
function autoLoadingUrls(text: string): string[] {
  const urls: string[] = [];
  for (const m of text.matchAll(/!\[[^\]]*\]\(\s*(https?:\/\/[^\s)]+)/gi)) urls.push(m[1]);
  for (const m of text.matchAll(/^\s*\[[^\]]+\]:\s*(https?:\/\/\S+)/gim)) urls.push(m[1]);
  for (const m of text.matchAll(/<img[^>]+src=["'](https?:\/\/[^"']+)["']/gi)) urls.push(m[1]);
  return urls;
}

export function scanOutput(req: OutputScanRequest): OutputScanResult {
  const { content } = req;
  const findings: Finding[] = [];
  const allowed = (req.allowedHosts ?? DEFAULT_ALLOWED_HOSTS).map((h) => h.toLowerCase());

  // 1. Canary leak — unambiguous, so it outranks everything else.
  for (const canary of req.canaries ?? []) {
    if (canary && content.includes(canary)) {
      findings.push(
        finding("secret_extraction", 1.0, `Canary token leaked — the system prompt reached the output`, findSpan(content, canary))
      );
    }
  }

  // 2. Credentials in the output.
  for (const { name, re } of SECRET_PATTERNS) {
    const match = content.match(re);
    if (match) {
      findings.push(
        finding("credential_theft", 0.95, `Secret of type ${name} present in output`, findSpan(content, match[0]))
      );
    }
  }

  // 3. Exfiltration via URL.
  const autoLoading = new Set(autoLoadingUrls(content));
  for (const raw of extractUrls(content)) {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      continue;
    }

    const host = url.hostname.toLowerCase();
    const external = allowed.length > 0 && !allowed.some((h) => host === h || host.endsWith(`.${h}`));
    const carriesData = [...url.searchParams].some(
      ([k, v]) => DATA_PARAM.test(k) && v.length >= 16
    );
    const longPath = url.pathname.length > 120;
    const loadsAutomatically = autoLoading.has(raw);

    if (carriesData && (loadsAutomatically || external || allowed.length === 0)) {
      findings.push(
        finding(
          "tool_abuse",
          loadsAutomatically ? 0.95 : 0.85,
          `URL carries data in a query parameter${loadsAutomatically ? " and loads automatically (image/reference)" : ""}: ${host}`,
          findSpan(content, raw)
        )
      );
    } else if (loadsAutomatically && external) {
      findings.push(
        finding("tool_abuse", 0.8, `Auto-loading resource pointing at an unapproved host: ${host}`, findSpan(content, raw))
      );
    } else if (longPath && loadsAutomatically) {
      findings.push(
        finding("tool_abuse", 0.75, `Auto-loading URL with an unusually long path — possible data in path: ${host}`, findSpan(content, raw))
      );
    }
  }

  const riskScore = findings.length ? Math.max(...findings.map((f) => f.confidence)) : 0;
  return { allowed: riskScore < 0.8, findings, riskScore };
}
