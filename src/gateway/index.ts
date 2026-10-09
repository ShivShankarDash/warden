#!/usr/bin/env bun
/**
 * Warden MCP gateway.
 *
 * Sits between an MCP host (IDE, desktop app, CLI) and the real MCP servers it
 * would otherwise talk to directly. The host sees one server — this one — and every
 * tool listing and tool result passes through here on the way.
 *
 * That position is the whole point: an MCP server offering a `scan` tool can be
 * skipped by a model that has already read the poisoned content. A gateway inspects
 * content before it ever reaches the model's context.
 *
 *   host ── warden ──┬── fetch
 *                    └── google-maps
 *
 * stdout is the MCP wire. Nothing may be written to it except protocol frames, so
 * all logging goes to stderr and the detection engine is reached over HTTP rather
 * than imported (loading the model in-process prints to stdout and would corrupt
 * the stream).
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { loadConfig, isHttpUpstream, type UpstreamSpec, type HttpUpstream, type GatewayConfig } from "./config.ts";
import { scanContent, checkOutboundToolCall } from "./scan.ts";
import { sniff } from "../extract/sniff.ts";
import { scanPii } from "../guard/pii.ts";
import type { Action, Finding, SourceType } from "../types.ts";
import { red, green, yellow, dim, bold, cyan, rule, emoji } from "./colors.ts";

/* ─── Module-level scan stats ─────────────────────────────────────────── */

const stats = {
  totalScans: 0,
  allowed: 0,
  blocked: 0,
  spotlighted: 0,
  /** Running sum of scan latencies in ms (avoids unbounded array growth). */
  latencySumMs: 0,
  /** Number of latency samples recorded. */
  latencyCount: 0,
  attackTypes: new Set<string>(),
};

/** Returns a snapshot of gateway scan statistics. */
export function getGatewayStats() {
  return {
    totalScans: stats.totalScans,
    allowed: stats.allowed,
    blocked: stats.blocked,
    spotlighted: stats.spotlighted,
    attackTypes: [...stats.attackTypes],
    avgLatencyMs: stats.latencyCount
      ? Math.round(stats.latencySumMs / stats.latencyCount)
      : 0,
  };
}

/* ─── Quiet mode ──────────────────────────────────────────────────────── */

let isQuiet = false;

/* ─── Rich logging helpers ────────────────────────────────────────────── */

/** One session per gateway process, so the session tracker sees the whole conversation. */
const SESSION_ID = `mcp-${crypto.randomUUID()}`;

/**
 * Log a per-scan result line to stderr.
 *
 * ALLOW lines are suppressed in quiet mode. BLOCK/QUARANTINE/HUMAN_REVIEW always print.
 */
function logScan(
  scanNum: number,
  toolName: string,
  args: string,
  action: Action,
  riskScore: number,
  findings: Finding[],
  elapsedMs: number,
): void {
  const prefix = `${emoji.shield} [warden] Scan #${scanNum}: ${toolName}(${args})`;

  switch (action) {
    case "ALLOW": {
      if (isQuiet) return;
      console.error(`${prefix} → ${green(`${emoji.check} ALLOW`)} (risk ${riskScore.toFixed(2)}) ${dim(`${elapsedMs}ms`)}`);
      break;
    }
    case "BLOCK":
    case "QUARANTINE":
    case "HUMAN_REVIEW": {
      const attacks = [...new Set(findings.map((f) => f.attackType))].join(", ") || "n/a";
      console.error(`${prefix} → ${red(`${emoji.block} ${action}`)} (${attacks}, ${riskScore.toFixed(2)}) ${dim(`${elapsedMs}ms`)}`);
      if (findings.length) {
        console.error(`  Reason: ${findings[0].reason}`);
      }
      console.error("  Content replaced with safety message.");
      break;
    }
    case "SPOTLIGHT": {
      // SPOTLIGHT is security-relevant (content wrapped in data boundary) — always print, even in quiet mode.
      console.error(`${prefix} → ${yellow(`${emoji.warn} SPOTLIGHT`)} (risk ${riskScore.toFixed(2)}) ${dim(`${elapsedMs}ms`)}`);
      console.error("  Passed with data boundary wrapper.");
      break;
    }
    default: {
      if (isQuiet) return;
      console.error(`${prefix} → ${action} (risk ${riskScore.toFixed(2)}) ${dim(`${elapsedMs}ms`)}`);
      break;
    }
  }
}

/** Log a tool-description vet result at registration time. */
function logToolVet(
  toolName: string,
  action: Action,
  riskScore: number,
  findings: Finding[],
  elapsedMs: number,
): void {
  const prefix = `${emoji.shield} [warden] Tool "${toolName}"`;

  if (action === "ALLOW") {
    console.error(`${prefix} — ${green(`${emoji.check} CLEAN`)} ${dim(`(${elapsedMs}ms)`)}`);
  } else if (action === "BLOCK" || action === "QUARANTINE") {
    const attacks = [...new Set(findings.map((f) => f.attackType))].join(", ") || "n/a";
    console.error(`${prefix} — ${red(`${emoji.block} BLOCKED`)} (${attacks}, ${riskScore.toFixed(2)}) ${dim(`${elapsedMs}ms`)}`);
    if (findings.length) {
      console.error(`  Reason: ${findings[0].reason}`);
    }
  } else {
    console.error(`${prefix} — ${yellow(`${action}`)} (risk ${riskScore.toFixed(2)}) ${dim(`${elapsedMs}ms`)}`);
  }
}

/** Print the startup banner after upstreams are connected and tools are vetted. */
function logStartup(
  upstreams: Upstream[],
  exposed: Tool[],
  wardenUrl: string,
): void {
  const upstreamList = upstreams
    .map((u) => `${u.name} (${u.tools.length} tools)`)
    .join(", ");

  const toolNames = exposed.map((t) => dim(t.name)).join(", ");
  const modeLabel = isQuiet ? "quiet" : "verbose";

  console.error(rule());
  console.error(`${emoji.shield}  ${bold("WARDEN — AI Agent Firewall")}`);
  console.error(`   Scanning: tool descriptions + tool results`);
  console.error(`   API: ${cyan(wardenUrl)}`);
  console.error(`   Upstreams: ${upstreamList}`);
  console.error(`   Exposed tools: ${toolNames}`);
  console.error(`   Mode: ${modeLabel}`);
  console.error(rule());
}

/* ─── Helpers ─────────────────────────────────────────────────────────── */

function textOf(result: unknown): string {
  const content = (result as { content?: { type?: string; text?: string }[] })?.content ?? [];
  return content.filter((c) => c?.type === "text").map((c) => c.text ?? "").join("\n");
}

interface Upstream {
  name: string;
  client: Client;
  tools: Tool[];
}

/** Tool name -> which upstream serves it. */
const routes = new Map<string, Upstream>();

function newClient(): Client {
  return new Client({ name: "warden-gateway", version: "0.1.0" }, { capabilities: {} });
}

/**
 * Hosted servers disagree about transport: Streamable HTTP is current, SSE is the
 * older one and still widely deployed. With no explicit `transport` we try the
 * modern one and fall back, since there is no reliable way to tell from the URL.
 * Each attempt needs a fresh Client — a failed connect leaves it unusable.
 */
async function connectHttp(name: string, spec: HttpUpstream): Promise<Client> {
  const url = new URL(spec.url);
  const requestInit = spec.headers ? { headers: spec.headers } : undefined;

  const order: ("http" | "sse")[] = spec.transport ? [spec.transport] : ["http", "sse"];
  let lastError: unknown;

  for (const kind of order) {
    const client = newClient();
    try {
      const transport =
        kind === "http"
          ? new StreamableHTTPClientTransport(url, { requestInit })
          : new SSEClientTransport(url, { requestInit });
      await client.connect(transport);
      if (!spec.transport) console.error(`[warden-gateway] ${name}: using ${kind} transport`);
      return client;
    } catch (e) {
      lastError = e;
      await client.close().catch(() => {});
      if (!spec.transport && kind === "http") {
        console.error(`[warden-gateway] ${name}: streamable http failed, trying sse`);
      }
    }
  }
  throw lastError;
}

async function connectUpstream(name: string, spec: UpstreamSpec): Promise<Upstream | null> {
  try {
    let client: Client;

    if (isHttpUpstream(spec)) {
      client = await connectHttp(name, spec);
    } else {
      client = newClient();
      await client.connect(
        new StdioClientTransport({
          command: spec.command,
          args: spec.args ?? [],
          // Inherit the parent env so upstreams keep PATH etc., then layer their own.
          env: { ...(process.env as Record<string, string>), ...(spec.env ?? {}) },
        })
      );
    }

    const listed = await client.listTools();
    console.error(`[warden-gateway] connected ${name} (${listed.tools.length} tools)`);
    return { name, client, tools: listed.tools };
  } catch (e) {
    console.error(`[warden-gateway] FAILED to connect ${name}: ${e instanceof Error ? e.message : e}`);
    return null;
  }
}

/**
 * Tool names are kept as-is wherever possible. Renaming them would silently break
 * host-side allowlists (an `autoApprove` entry for `search_places` stops matching
 * if the tool arrives as `maps__search_places`), so only genuine collisions between
 * two upstreams get a prefix.
 */
function registerTools(upstreams: Upstream[]): Tool[] {
  const seen = new Map<string, number>();
  for (const u of upstreams) {
    for (const t of u.tools) seen.set(t.name, (seen.get(t.name) ?? 0) + 1);
  }

  const exposed: Tool[] = [];
  for (const u of upstreams) {
    for (const t of u.tools) {
      const name = (seen.get(t.name) ?? 0) > 1 ? `${u.name}__${t.name}` : t.name;
      routes.set(name, u);
      exposed.push({ ...t, name });
    }
  }
  return exposed;
}

/**
 * Scan point 1: tool descriptions, at registration.
 *
 * A poisoned description is read by the model every time it decides which tool to
 * use, so it is more dangerous than any single result — and the host never shows it
 * to the user. Withheld tools are dropped from the listing entirely rather than
 * exposed with a warning, since a description the model can read is a description
 * that can instruct it.
 *
 * Known-good tools from popular MCP servers are whitelisted to avoid false positives
 * on descriptions that legitimately describe capabilities (e.g. "this tool grants
 * you internet access").
 */
const UPSTREAM_WHITELIST = new Set(
  (process.env.WARDEN_UPSTREAM_WHITELIST ?? "mcp-server-fetch,mcp-server-google-maps,mcp-server-filesystem,mcp-server-github").split(",").map(s => s.trim())
);

async function vetToolDescriptions(tools: Tool[], upstreamName: string): Promise<Tool[]> {
  // Skip scanning for whitelisted upstreams — these are known-good MCP servers.
  // Also skip for the internal "clean" upstream and auto-generated "upstream-N" names
  // from --upstream-cmd (these are user-specified and trusted by definition).
  // Their tools are not counted in stats.totalScans because no scan is performed;
  // the shutdown summary reflects only content that was actually analysed.
  if (UPSTREAM_WHITELIST.has(upstreamName) || upstreamName === "clean" || /^upstream-\d+$/.test(upstreamName)) {
    for (const tool of tools) {
      logToolVet(tool.name, "ALLOW", 0, [], 0);
    }
    return tools;
  }

  const safe: Tool[] = [];
  for (const tool of tools) {
    const text = `${tool.name}\n${tool.description ?? ""}`;
    const t0 = performance.now();
    const verdict = await scanContent(text, "mcp_tool_description", SESSION_ID);
    const elapsedMs = Math.round(performance.now() - t0);

    stats.totalScans++;

    logToolVet(tool.name, verdict.action, verdict.riskScore, verdict.findings, elapsedMs);

    if (verdict.action === "BLOCK" || verdict.action === "QUARANTINE") {
      continue;
    }
    safe.push(tool);
  }
  return safe;
}

export async function startGateway(config: GatewayConfig) {
  isQuiet = config.quiet ?? (process.env.WARDEN_QUIET === "1");

  // Connect to stdio IMMEDIATELY so the MCP host (Kiro/Claude) completes its
  // handshake before models load. Without this, the 20-second model init
  // causes a connection timeout on the host side.
  const server = new Server(
    { name: "warden", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  let exposed: Tool[] = [];
  let ready = false;
  let readyResolve: () => void;
  const readyPromise = new Promise<void>((resolve) => { readyResolve = resolve; });

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    if (!ready) await readyPromise;
    return { tools: exposed };
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (!ready) await readyPromise;
    const toolName = req.params.name;
    const upstream = routes.get(toolName);
    if (!upstream) {
      return {
        isError: true,
        content: [{ type: "text" as const, text: `Unknown tool: ${toolName}` }],
      };
    }

    // Strip the collision prefix before forwarding — the upstream knows its own name.
    const realName = toolName.startsWith(`${upstream.name}__`)
      ? toolName.slice(upstream.name.length + 2)
      : toolName;

    // PII scan outbound tool arguments before forwarding to upstream.
    let forwardArgs = req.params.arguments ?? {};
    if (process.env.WARDEN_PII_ENABLED !== "0") {
      const mutatedArgs: Record<string, unknown> = { ...forwardArgs };
      let argRedacted = false;
      const argPiiTypes: string[] = [];
      for (const [key, val] of Object.entries(mutatedArgs)) {
        if (typeof val === "string") {
          const piiResult = scanPii(val);
          if (piiResult.hasPii) {
            mutatedArgs[key] = piiResult.mutatedContent;
            argRedacted = true;
            for (const m of piiResult.matches) {
              if (!argPiiTypes.includes(m.type)) argPiiTypes.push(m.type);
            }
          }
        }
      }
      if (argRedacted) {
        forwardArgs = mutatedArgs;
        console.error(`     ${emoji.warn} PII redacted in args: ${argPiiTypes.join(", ")}`);
      }
    }

    // Scan point 3: the outbound call, before it executes.
    //
    // The two inbound scan points stop poisoned content reaching the model. This is
    // the other direction — the point where a compromised agent would actually send
    // the data. Checked before forwarding, so it prevents rather than reports.
    const outbound = await checkOutboundToolCall(toolName, forwardArgs, SESSION_ID);
    if (!outbound.allowed) {
      stats.blocked++;
      stats.totalScans++;
      console.error(
        `${emoji.shield} ${red("BLOCKED OUTBOUND")} ${bold(toolName)} ${dim("— " + outbound.reason)}`
      );
      return {
        isError: true,
        content: [
          {
            type: "text" as const,
            text:
              `[warden] This tool call was blocked before it ran.\n${outbound.reason}\n` +
              `Tell the user the action was prevented; do not retry it another way.`,
          },
        ],
      };
    }

    const result = await upstream.client.callTool({
      name: realName,
      arguments: forwardArgs,
    });

    // Scan point 2: the tool result, before it reaches the model's context. This is
    // the moment that matters — once this text is in context, injection has landed.
    const text = textOf(result);

    // Build a truncated summary of the arguments for the log line.
    const argsSummary = (() => {
      try {
        const s = JSON.stringify(req.params.arguments ?? {});
        return s.length > 60 ? s.slice(0, 57) + "..." : s;
      } catch {
        return "{}";
      }
    })();

    if (!text) {
      stats.totalScans++;
      stats.allowed++;
      stats.latencyCount++;
      // No scan performed — 0ms latency keeps the average denominator consistent.
      console.error(`${emoji.shield} [warden] Scan #${stats.totalScans}: ${toolName}(${argsSummary}) → ${dim("(empty result, skipped)")}`);
      return result as { content: unknown[]; isError?: boolean };
    }

    // Tool results are whatever the upstream returned — HTML from a browser tool,
    // markdown from a docs tool, JSON from an API. Hardcoding one source routes
    // every result to the wrong parser, so let the content decide.
    const sniffed = sniff(text);
    const source: SourceType = sniffed === "text" ? "api_json" : (sniffed as SourceType);

    const t0 = performance.now();
    const verdict = await scanContent(text, source, SESSION_ID);
    const elapsedMs = Math.round(performance.now() - t0);

    // Update stats.
    stats.totalScans++;
    stats.latencySumMs += elapsedMs;
    stats.latencyCount++;

    switch (verdict.action) {
      case "ALLOW":
        stats.allowed++;
        break;
      case "BLOCK":
      case "QUARANTINE":
      case "HUMAN_REVIEW":
        stats.blocked++;
        for (const f of verdict.findings) stats.attackTypes.add(f.attackType);
        break;
      case "SPOTLIGHT":
        stats.spotlighted++;
        break;
    }

    logScan(stats.totalScans, toolName, argsSummary, verdict.action, verdict.riskScore, verdict.findings, elapsedMs);

    if (verdict.action !== "ALLOW" && verdict.replacement) {
      return {
        content: [{ type: "text" as const, text: verdict.replacement }],
        isError: verdict.action === "BLOCK" || verdict.action === "QUARANTINE",
      };
    }

    // PII scan inbound tool result — redact PII before it reaches the model's context.
    if (process.env.WARDEN_PII_ENABLED !== "0") {
      const piiResult = scanPii(text);
      if (piiResult.hasPii) {
        const piiTypes = [...new Set(piiResult.matches.map((m) => m.type))];
        console.error(`     ${emoji.warn} PII redacted: ${piiResult.matches.length} items (${piiTypes.join(", ")})`);
        for (const m of piiResult.matches) {
          console.error(`        ${dim(m.original)} → ${yellow(m.replacement)}`);
        }
        // Replace text content entries with the mutated content.
        const mutatedContent = (result as { content?: { type?: string; text?: string }[] })?.content?.map(
          (c: { type?: string; text?: string }) =>
            c?.type === "text" ? { ...c, text: (c.text ?? "").length ? piiResult.mutatedContent : c.text } : c
        ) ?? [];
        return { content: mutatedContent, isError: false };
      }
    }

    return result as { content: unknown[]; isError?: boolean };
  });

  await server.connect(new StdioServerTransport());
  console.error(`[warden-gateway] MCP handshake complete — loading upstreams...`);

  // Now load upstreams and vet tools (this takes 15-20 seconds on first run).
  const entries = Object.entries(config.upstreams);
  console.error(`[warden-gateway] starting with ${entries.length} upstream(s)`);

  const connected = (
    await Promise.all(entries.map(([name, spec]) => connectUpstream(name, spec)))
  ).filter((u): u is Upstream => u !== null);

  if (!connected.length) console.error("[warden-gateway] WARNING: no upstreams connected — host will see no tools");

  for (const u of connected) {
    u.tools = await vetToolDescriptions(u.tools, u.name);
  }
  exposed = registerTools(connected);
  ready = true;
  readyResolve!();

  const wardenUrl = process.env.WARDEN_URL ?? "http://localhost:3000";
  logStartup(connected, exposed, wardenUrl);

  return { server, upstreams: connected };
}

if (import.meta.main) {
  const config = await loadConfig();
  startGateway(config).catch((e) => {
    console.error(`[warden-gateway] fatal: ${e instanceof Error ? e.stack : e}`);
    process.exit(1);
  });
}
