import type { ToolCallCheck, ToolCallResult } from "../types.ts";
import { checkTaint } from "./taint.ts";
import { scanOutput } from "./output.ts";

/**
 * Tool-call guard — the enforcement point for outbound actions.
 *
 * A tool call is where a compromised agent does its damage: sends the email, fetches
 * the attacker's URL, writes the file. Unlike output scanning this runs *before*
 * execution, so it can prevent rather than merely report.
 */

/** Tools that move data out of the trust boundary. Taint in their arguments matters. */
const EGRESS_TOOLS = /^(send_email|fetch_url|http_request|post|upload|webhook|curl|share|publish|send_message|create_issue|write_file)/i;

/** Proportion of a tool argument that may come from untrusted content before it is
 *  treated as carrying that content outward. Set above zero because short quoted
 *  fragments are legitimate — summarising a document is the agent's job. */
const TAINT_RATIO_LIMIT = Number(process.env.WARDEN_TAINT_RATIO ?? 0.35);

function argsToText(args: Record<string, unknown>): string {
  return Object.values(args)
    .map((v) => (typeof v === "string" ? v : JSON.stringify(v ?? "")))
    .join("\n");
}

export function checkToolCall(req: ToolCallCheck & { allowedTools?: string[] }): ToolCallResult {
  const { tool, args, sessionId } = req;
  const text = argsToText(args ?? {});
  const blockedArgs: string[] = [];

  // 1. Allowlist. An empty list means unrestricted — policy decides, not this module.
  if (req.allowedTools?.length && !req.allowedTools.includes(tool)) {
    return { allowed: false, reason: `Tool "${tool}" is not in this agent's allowlist`, blockedArgs: [] };
  }

  // 2. Explicit provenance from the caller, when it tracks its own.
  for (const [key, provenance] of Object.entries(req.argProvenance ?? {})) {
    if (provenance === "tainted") blockedArgs.push(key);
  }

  const isEgress = EGRESS_TOOLS.test(tool);

  // 3. Secrets and exfiltration URLs in the arguments. Checked for every tool,
  //    since a credential in a file write is as bad as one in an email.
  const outbound = scanOutput({ content: text });
  if (outbound.riskScore >= 0.8) {
    const reasons = outbound.findings.map((f) => f.reason).join("; ");
    return {
      allowed: false,
      reason: `Blocked: ${reasons}`,
      blockedArgs: Object.keys(args ?? {}),
    };
  }

  // 4. Taint — only for tools that actually send data somewhere.
  if (isEgress && sessionId) {
    const taint = checkTaint(sessionId, text);
    if (taint.ratio > TAINT_RATIO_LIMIT && taint.matched >= 2) {
      return {
        allowed: false,
        reason:
          `Blocked: ${Math.round(taint.ratio * 100)}% of the arguments to "${tool}" come from untrusted ` +
          `content scanned earlier in this session (${taint.sources.join(", ")}). ` +
          `This is the shape of an exfiltration attempt.`,
        blockedArgs: Object.keys(args ?? {}),
      };
    }
  }

  if (blockedArgs.length) {
    return {
      allowed: false,
      reason: `Blocked: arguments marked tainted by the caller: ${blockedArgs.join(", ")}`,
      blockedArgs,
    };
  }

  return {
    allowed: true,
    reason: isEgress ? "Egress tool call cleared" : "No policy violation",
    blockedArgs: [],
  };
}
