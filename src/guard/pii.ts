/**
 * PII Scanner with Prompt Mutation.
 *
 * Detects personally identifiable information and secrets in text via pure regex,
 * replaces them with typed placeholders, and returns the mutated content alongside
 * match metadata. No external dependencies — regex only.
 *
 * Controlled by two env vars:
 *   WARDEN_PII_ENABLED  — "1" (default) to enable, "0" to disable.
 *   WARDEN_PII_TYPES    — comma-separated list of types to detect (default: all).
 */

/** A single PII match found in the input text. */
export interface PiiMatch {
  type: string;
  original: string;
  replacement: string;
  start: number;
  end: number;
}

/** Result of scanning text for PII. */
export interface PiiScanResult {
  hasPii: boolean;
  matches: PiiMatch[];
  mutatedContent: string;
}

/* ─── Pattern definitions ─────────────────────────────────────────────── */

interface PiiPattern {
  type: string;
  regex: RegExp;
  replacement: string;
}

const PII_PATTERNS: PiiPattern[] = [
  // Private key headers — match the full block to avoid partial leaks.
  {
    type: "private_key",
    regex: /-----BEGIN\s[\w\s]*PRIVATE KEY-----[\s\S]*?-----END\s[\w\s]*PRIVATE KEY-----/g,
    replacement: "[REDACTED_PRIVATE_KEY]",
  },
  // JWT — three base64url segments separated by dots.
  {
    type: "jwt",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replacement: "[REDACTED_JWT]",
  },
  // AWS access key — always starts with AKIA followed by 16 uppercase alphanumeric.
  {
    type: "aws_key",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    replacement: "[REDACTED_AWS_KEY]",
  },
  // AWS secret key — 40+ char base64 string near "secret" context.
  {
    type: "aws_secret",
    regex: /(?:secret[\s_-]*(?:access)?[\s_-]*key[\s:="']*)[A-Za-z0-9/+=]{40,}/gi,
    replacement: "[REDACTED_AWS_SECRET]",
  },
  // API keys — sk-*, ghp_*, gho_*, ghu_*, ghs_*, ghr_*, xoxb-*, xoxp-*, xoxs-*, xoxa-*, xoxr-*.
  {
    type: "api_key",
    regex: /\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[bpasr]-[A-Za-z0-9-]{10,})\b/g,
    replacement: "[REDACTED_API_KEY]",
  },
  // Credit card — 4 groups of 4 digits, optionally separated by spaces or dashes.
  {
    type: "credit_card",
    regex: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    replacement: "[REDACTED_CC]",
  },
  // SSN — US Social Security Number.
  {
    type: "ssn",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    replacement: "[REDACTED_SSN]",
  },
  // Email address.
  {
    type: "email",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    replacement: "[REDACTED_EMAIL]",
  },
  // Machine hostname — AWS-style internal hostnames.
  {
    type: "hostname",
    regex: /\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.[A-Za-z0-9.-]*\.internal\b/g,
    replacement: "[REDACTED_HOSTNAME]",
  },
  // IPv6 — common colon-separated hex patterns (simplified, catches most forms).
  {
    type: "ip_address",
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{0,4}\b|\b::(?:ffff:)?(?:\d{1,3}\.){3}\d{1,3}\b/g,
    replacement: "[REDACTED_IP]",
  },
  // IPv4 — four octets.
  {
    type: "ip_address",
    regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
    replacement: "[REDACTED_IP]",
  },
  // International phone — starts with + and country code.
  {
    type: "phone",
    regex: /\+\d{1,3}[-\s]\d[\d\s-]{6,14}\d\b/g,
    replacement: "[REDACTED_PHONE]",
  },
  // US phone — 10 digits with optional separators.
  {
    type: "phone",
    regex: /\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    replacement: "[REDACTED_PHONE]",
  },
];

/* ─── Type filter ─────────────────────────────────────────────────────── */

function allowedTypes(): Set<string> | null {
  const env = process.env.WARDEN_PII_TYPES;
  if (!env || !env.trim()) return null; // all types
  return new Set(env.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean));
}

/* ─── Overlap resolution ──────────────────────────────────────────────── */

/**
 * Given a list of candidate matches that may overlap, returns a non-overlapping
 * subset. Matches are sorted by start position, then longest match first. A match
 * whose start falls within a previously accepted range is discarded.
 */
function resolveOverlaps(matches: PiiMatch[]): PiiMatch[] {
  if (matches.length <= 1) return matches;

  const sorted = [...matches].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const accepted: PiiMatch[] = [];
  let lastEnd = -1;

  for (const m of sorted) {
    if (m.start >= lastEnd) {
      accepted.push(m);
      lastEnd = m.end;
    }
  }
  return accepted;
}

/* ─── Public API ──────────────────────────────────────────────────────── */

/**
 * Scan text for PII and return matches plus a mutated version with placeholders.
 *
 * When WARDEN_PII_ENABLED is "0", returns immediately with hasPii: false and the
 * original content unchanged.
 */
export function scanPii(text: string): PiiScanResult {
  if (process.env.WARDEN_PII_ENABLED === "0") {
    return { hasPii: false, matches: [], mutatedContent: text };
  }

  const filter = allowedTypes();
  const candidates: PiiMatch[] = [];

  for (const pattern of PII_PATTERNS) {
    if (filter && !filter.has(pattern.type)) continue;

    // Reset lastIndex for global regexes reused across calls.
    pattern.regex.lastIndex = 0;

    let m: RegExpExecArray | null;
    while ((m = pattern.regex.exec(text)) !== null) {
      candidates.push({
        type: pattern.type,
        original: m[0],
        replacement: pattern.replacement,
        start: m.index,
        end: m.index + m[0].length,
      });
    }
  }

  const matches = resolveOverlaps(candidates);

  if (!matches.length) {
    return { hasPii: false, matches: [], mutatedContent: text };
  }

  // Build mutated content by replacing matches from end to start to preserve indices.
  let mutated = text;
  for (let i = matches.length - 1; i >= 0; i--) {
    const match = matches[i];
    mutated = mutated.slice(0, match.start) + match.replacement + mutated.slice(match.end);
  }

  return { hasPii: true, matches, mutatedContent: mutated };
}
