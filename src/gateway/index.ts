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
import { scanContent } from "./scan.ts";
import { sniff } from "../extract/sniff.ts";
import type { SourceType } from "../types.ts";

const log = (...args: unknown[]) => console.error("[warden-gateway]", ...args);

/** One session per gateway process, so the session tracker sees the whole conversation. */
const SESSION_ID = `mcp-${crypto.randomUUID()}`;

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
      if (!spec.transport) log(`${name}: using ${kind} transport`);
      return client;
    } catch (e) {
      lastError = e;
      await client.close().catch(() => {});
      if (!spec.transport && kind === "http") {
        log(`${name}: streamable http failed, trying sse`);
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
    log(`connected ${name} (${listed.tools.length} tools)`);
    return { name, client, tools: listed.tools };
  } catch (e) {
    log(`FAILED to connect ${name}: ${e instanceof Error ? e.message : e}`);
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
const TOOL_WHITELIST = new Set(
  (process.env.WARDEN_TOOL_WHITELIST ?? "fetch,read_file,write_file,search,bash,list_directory,grep_search,web_search,web_fetch,get_directions,search_places,get_distance").split(",").map(s => s.trim())
);

async function vetToolDescriptions(tools: Tool[]): Promise<Tool[]> {
  const safe: Tool[] = [];
  for (const tool of tools) {
    // Skip scanning for whitelisted tools — these are from known-good MCP servers.
    if (TOOL_WHITELIST.has(tool.name)) {
      safe.push(tool);
      continue;
    }

    const text = `${tool.name}\n${tool.description ?? ""}`;
    const verdict = await scanContent(text, "mcp_tool_description", SESSION_ID);

    if (verdict.action === "BLOCK" || verdict.action === "QUARANTINE") {
      log(
        `WITHHELD tool "${tool.name}" — poisoned description ` +
          `(risk ${verdict.riskScore.toFixed(2)}: ${[...new Set(verdict.findings.map((f) => f.attackType))].join(", ")})`
      );
      continue;
    }
    if (verdict.action !== "ALLOW") {
      log(`flagged tool "${tool.name}" (${verdict.action}, risk ${verdict.riskScore.toFixed(2)})`);
    }
    safe.push(tool);
  }
  return safe;
}

export async function startGateway(config: GatewayConfig) {
  const entries = Object.entries(config.upstreams);
  log(`starting with ${entries.length} upstream(s)`);

  const connected = (
    await Promise.all(entries.map(([name, spec]) => connectUpstream(name, spec)))
  ).filter((u): u is Upstream => u !== null);

  if (!connected.length) log("WARNING: no upstreams connected — host will see no tools");

  const exposed = await vetToolDescriptions(registerTools(connected));

  const server = new Server(
    { name: "warden", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: exposed }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
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

    const result = await upstream.client.callTool({
      name: realName,
      arguments: req.params.arguments ?? {},
    });

    // Scan point 2: the tool result, before it reaches the model's context. This is
    // the moment that matters — once this text is in context, injection has landed.
    const text = textOf(result);
    if (!text) return result as { content: unknown[]; isError?: boolean };

    // Tool results are whatever the upstream returned — HTML from a browser tool,
    // markdown from a docs tool, JSON from an API. Hardcoding one source routes
    // every result to the wrong parser, so let the content decide.
    const sniffed = sniff(text);
    const source: SourceType = sniffed === "text" ? "api_json" : (sniffed as SourceType);
    const verdict = await scanContent(text, source, SESSION_ID);
    if (verdict.action !== "ALLOW" && verdict.replacement) {
      log(
        `${verdict.action} ${toolName} result (risk ${verdict.riskScore.toFixed(2)}): ` +
          `${[...new Set(verdict.findings.map((f) => f.attackType))].join(", ") || "n/a"}`
      );
      return {
        content: [{ type: "text" as const, text: verdict.replacement }],
        isError: verdict.action === "BLOCK" || verdict.action === "QUARANTINE",
      };
    }

    return result as { content: unknown[]; isError?: boolean };
  });

  await server.connect(new StdioServerTransport());
  log(`ready — exposing ${exposed.length} tools: ${exposed.map((t) => t.name).join(", ")}`);

  return { server, upstreams: connected };
}

if (import.meta.main) {
  const config = await loadConfig();
  startGateway(config).catch((e) => {
    log(`fatal: ${e instanceof Error ? e.stack : e}`);
    process.exit(1);
  });
}
