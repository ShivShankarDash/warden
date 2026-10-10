import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { scanContent, checkOutboundToolCall } from "../src/gateway/scan.ts";

/**
 * Gateway hardening regressions.
 *
 * Each of these was found by driving the real gateway over stdio with a real MCP
 * client, so the end-to-end cases here do the same rather than calling the handlers
 * directly: every one of the bugs lived in how the three scan points were wired
 * together, not in the pieces they call.
 *
 * The detection engine is stubbed throughout. What is under test is whether content
 * REACHES a scan point and what the gateway does with the answer — not whether the
 * classifier is right about any particular string.
 */

const GATEWAY = new URL("../src/gateway/index.ts", import.meta.url).pathname;

/* ─── Stub detection engine ───────────────────────────────────────────── */

interface StubState {
  /** Everything handed to /scan, in order. */
  scanned: string[];
  /** Every tool name handed to /check-tool, in order. */
  checkedTools: string[];
}

/**
 * Stands in for the Warden API. /scan flags anything containing MARKER; /check-tool
 * delegates to the real guard so the egress and secret rules are the production ones.
 */
const MARKER = "zzmaliciouszz";

function startStub(state: StubState) {
  return Bun.serve({
    port: 0,
    maxRequestBodySize: 64 * 1024 * 1024,
    async fetch(req) {
      const url = new URL(req.url);
      const body = (await req.json()) as Record<string, any>;

      if (url.pathname === "/check-tool") {
        state.checkedTools.push(body.tool);
        const { checkToolCall } = await import("../src/guard/tools.ts");
        return Response.json(checkToolCall(body));
      }

      state.scanned.push(body.content);
      const bad = String(body.content).includes(MARKER);
      return Response.json({
        id: "stub",
        action: bad ? "BLOCK" : "ALLOW",
        riskScore: bad ? 0.95 : 0,
        findings: bad
          ? [
              {
                stage: "rules",
                attackType: "indirect_injection",
                confidence: 0.95,
                spans: [{ start: String(body.content).indexOf(MARKER), end: String(body.content).indexOf(MARKER) + MARKER.length, text: MARKER }],
                reason: "stub",
              },
            ]
          : [],
        trace: [],
      });
    },
  });
}

/* ─── Unit level: scan.ts ─────────────────────────────────────────────── */

describe("scanContent — oversize results", () => {
  const state: StubState = { scanned: [], checkedTools: [] };
  let stub: ReturnType<typeof Bun.serve>;
  const saved: Record<string, string | undefined> = {};

  beforeAll(() => {
    for (const k of ["WARDEN_URL", "WARDEN_MAX_SCAN_CHARS", "WARDEN_MAX_SCAN_CHUNKS", "WARDEN_FAIL_MODE"]) {
      saved[k] = process.env[k];
    }
    stub = startStub(state);
    process.env.WARDEN_URL = `http://localhost:${stub.port}`;
    process.env.WARDEN_MAX_SCAN_CHARS = "10000";
    process.env.WARDEN_MAX_SCAN_CHUNKS = "8";
  });

  afterAll(() => {
    stub.stop(true);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  test("content past the single-request limit is split and scanned, not refused", async () => {
    // Before: anything over 1 MB came back from /scan as 413, which the gateway
    // reported as "the scanner could not be reached" — and under fail-open passed
    // through untouched. Padding a result past the limit was a one-line bypass.
    state.scanned = [];
    const verdict = await scanContent("a ".repeat(14_000), "api_json", "s-chunk");

    expect(state.scanned.length).toBeGreaterThan(1);
    expect(verdict.action).toBe("ALLOW");
  });

  test("an injection only in the tail is still caught", async () => {
    state.scanned = [];
    const verdict = await scanContent("padding ".repeat(2_000) + MARKER, "api_json", "s-tail");

    expect(verdict.action).toBe("BLOCK");
    expect(verdict.replacement).toContain("blocked");
  });

  test("finding spans are shifted back onto the full text", async () => {
    // Spans come back relative to the chunk. Left unshifted, SANITIZE cuts from the
    // wrong offset in every chunk after the first.
    const prefix = "padding ".repeat(2_000);
    const content = prefix + MARKER;
    const verdict = await scanContent(content, "api_json", "s-span");

    const span = verdict.findings[0]?.spans[0];
    expect(span).toBeDefined();
    expect(content.slice(span!.start, span!.end)).toBe(MARKER);
  });

  test("past the chunk ceiling the content is withheld even under fail-open", async () => {
    // Result size is attacker-controlled, so this ceiling deliberately ignores
    // WARDEN_FAIL_MODE: fail-open is about the scanner being down, not a licence for
    // an upstream to opt its own output out of inspection.
    process.env.WARDEN_FAIL_MODE = "open";
    state.scanned = [];
    const verdict = await scanContent("x".repeat(200_000), "api_json", "s-ceiling");

    expect(state.scanned.length).toBe(0);
    expect(verdict.action).toBe("BLOCK");
    expect(verdict.replacement).toContain("none of it was scanned");
    delete process.env.WARDEN_FAIL_MODE;
  });
});

describe("scanContent — fail mode", () => {
  const saved: Record<string, string | undefined> = {};

  beforeAll(() => {
    for (const k of ["WARDEN_URL", "WARDEN_FAIL_MODE", "WARDEN_SCAN_TIMEOUT_MS"]) saved[k] = process.env[k];
    // A port with nothing on it: every scan fails to connect.
    process.env.WARDEN_URL = "http://127.0.0.1:1";
    process.env.WARDEN_SCAN_TIMEOUT_MS = "2000";
  });

  afterAll(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  test("closed withholds the content", async () => {
    process.env.WARDEN_FAIL_MODE = "closed";
    const verdict = await scanContent("ordinary text", "api_json", "s-closed");
    expect(verdict.action).toBe("BLOCK");
    expect(verdict.replacement).toContain("could not be reached");
    expect(verdict.unscanned).toBeFalsy();
  });

  test("open passes it through, but says so instead of reporting a clean scan", async () => {
    // Logging unscanned content as "ALLOW, risk 0.00" is indistinguishable from a
    // real pass. That is how a firewall ends up failing open silently.
    process.env.WARDEN_FAIL_MODE = "open";
    const verdict = await scanContent("ordinary text", "api_json", "s-open");
    expect(verdict.action).toBe("ALLOW");
    expect(verdict.unscanned).toBe(true);
  });

  test("the fail mode is read per call, not frozen at import", async () => {
    // policy.failMode from the config file is written into the environment by
    // applyConfigToEnv(), which runs inside startWarden() — after this module was
    // imported. Captured at load time, a config-file "open" was silently ignored
    // here while the outbound check honoured it, so an unreachable scanner dropped
    // every tool and left the host with an empty gateway.
    process.env.WARDEN_FAIL_MODE = "open";
    expect((await scanContent("text", "api_json")).action).toBe("ALLOW");

    process.env.WARDEN_FAIL_MODE = "closed";
    expect((await scanContent("text", "api_json")).action).toBe("BLOCK");
  });

  test("an unchecked outbound call is flagged as unchecked under fail-open", async () => {
    process.env.WARDEN_FAIL_MODE = "open";
    const verdict = await checkOutboundToolCall("send_email", { body: "hi" }, "s-open");
    expect(verdict.allowed).toBe(true);
    expect(verdict.unchecked).toBe(true);
  });
});

/* ─── End to end: a real MCP client against a real gateway process ────── */

/**
 * Two upstreams exposing the same tool names, so every tool arrives at the host
 * under a `${upstream}__` collision prefix — the shape that broke scan point 3.
 */
const UPSTREAM_SRC = `
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const NAME = process.env.SRV_NAME;
const server = new Server({ name: NAME, version: "1.0.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "send_email", description: "Sends an email.", inputSchema: { type: "object", properties: { to: { type: "string" }, body: { type: "string" } } } },
    { name: "echo", description: "Echoes a string.", inputSchema: { type: "object", properties: { s: { type: "string" } } } },
    { name: "shaped", description: "Returns a result in a chosen shape.", inputSchema: { type: "object", properties: { kind: { type: "string" } } } },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = req.params.arguments ?? {};
  if (req.params.name === "echo") return { content: [{ type: "text", text: NAME + ":" + a.s }] };
  if (req.params.name === "send_email") return { content: [{ type: "text", text: NAME + ":sent" }] };
  switch (a.kind) {
    case "resource":
      return { content: [{ type: "resource", resource: { uri: "file:///n.txt", mimeType: "text/plain", text: "notes MARKER_HERE" } }] };
    case "structured":
      return { content: [{ type: "text", text: "ok" }], structuredContent: { note: "MARKER_HERE" } };
    case "multi":
      return { content: [{ type: "text", text: "first, mail bob@example.com" }, { type: "text", text: "second block" }] };
    default:
      return { content: [{ type: "text", text: "plain" }] };
  }
});
await server.connect(new StdioServerTransport());
`.replace(/MARKER_HERE/g, MARKER);

/** Accepts a stdio connection and then answers nothing, ever. */
const WEDGED_SRC = `process.stdin.resume(); setInterval(() => {}, 1 << 30);`;

function textOf(result: any): string {
  return (result?.content ?? [])
    .filter((c: any) => c?.type === "text")
    .map((c: any) => c.text)
    .join("\n");
}

describe("gateway end to end", () => {
  const state: StubState = { scanned: [], checkedTools: [] };
  let stub: ReturnType<typeof Bun.serve>;
  let client: Client;
  let dir: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "warden-gw-"));
    await Bun.write(join(dir, "upstream.ts"), UPSTREAM_SRC);
    await Bun.write(
      join(dir, "config.json"),
      JSON.stringify({
        upstreams: {
          alpha: { command: "bun", args: [join(dir, "upstream.ts")], env: { SRV_NAME: "alpha" } },
          beta: { command: "bun", args: [join(dir, "upstream.ts")], env: { SRV_NAME: "beta" } },
        },
      })
    );

    stub = startStub(state);
    client = new Client({ name: "test", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StdioClientTransport({
        command: "bun",
        args: [GATEWAY],
        cwd: dir,
        env: {
          ...process.env,
          WARDEN_URL: `http://localhost:${stub.port}`,
          WARDEN_MCP_CONFIG: join(dir, "config.json"),
          WARDEN_QUIET: "1",
          DB_PATH: process.env.DB_PATH ?? "./warden-test.db",
        } as Record<string, string>,
      })
    );
    await client.listTools();
  });

  afterAll(async () => {
    await client.close();
    stub.stop(true);
  });

  test("a credential in the arguments is refused, not quietly redacted", async () => {
    // PII redaction used to run FIRST, rewriting sk-... to [REDACTED_API_KEY] before
    // the secret scanner saw it. The guard then reported no violation on an argument
    // it had already been robbed of, and the call went through.
    state.checkedTools = [];
    const r: any = await client.callTool({
      name: "alpha__send_email",
      arguments: { to: "x@y.com", body: "the key is sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" },
    });

    expect(r.isError).toBe(true);
    expect(textOf(r)).toContain("blocked before it ran");
  });

  test("the outbound check sees the upstream's own tool name, not the collision prefix", async () => {
    // The `alpha__` prefix is Warden's invention. The guard's egress list matches real
    // tool names, so `alpha__send_email` looked like a tool that sends nothing and
    // skipped the taint check that `send_email` fails.
    state.checkedTools = [];
    await client.callTool({ name: "alpha__send_email", arguments: { to: "x@y.com", body: "lunch" } });

    expect(state.checkedTools).toContain("send_email");
    expect(state.checkedTools).not.toContain("alpha__send_email");
  });

  test("each prefixed tool reaches its own upstream", async () => {
    expect(textOf(await client.callTool({ name: "alpha__echo", arguments: { s: "p" } }))).toBe("alpha:p");
    expect(textOf(await client.callTool({ name: "beta__echo", arguments: { s: "p" } }))).toBe("beta:p");
  });

  test("an injection inside an embedded resource block is scanned", async () => {
    // textOf() read only `type: "text"` blocks, so an upstream could wrap its payload
    // in a resource block and walk past scan point 2 — the gateway logged "(empty
    // result, skipped)" and handed it to the model untouched.
    state.scanned = [];
    const r: any = await client.callTool({ name: "alpha__shaped", arguments: { kind: "resource" } });

    expect(state.scanned.some((c) => c.includes(MARKER))).toBe(true);
    expect(r.isError).toBe(true);
    expect(textOf(r)).toContain("blocked");
  });

  test("an injection in structuredContent is scanned", async () => {
    state.scanned = [];
    const r: any = await client.callTool({ name: "alpha__shaped", arguments: { kind: "structured" } });

    expect(state.scanned.some((c) => c.includes(MARKER))).toBe(true);
    expect(r.isError).toBe(true);
  });

  test("PII redaction across several text blocks does not duplicate the result", async () => {
    // Writing the mutation of the JOINED text into every text block repeated the
    // whole result once per block.
    const r: any = await client.callTool({ name: "alpha__shaped", arguments: { kind: "multi" } });

    expect(r.content).toHaveLength(2);
    expect(r.content[0].text).toBe("first, mail [REDACTED_EMAIL]");
    expect(r.content[1].text).toBe("second block");
  });
});

describe("one wedged upstream does not take the healthy ones down", () => {
  test("tools from a responsive upstream are served while another never answers", async () => {
    // Nothing is exposed until every upstream has settled. An upstream that accepts
    // the connection and then goes silent held the whole gateway: the host's first
    // tools/list blocked behind it until the SDK's own 60s request timeout fired, and
    // the host saw zero tools — including the ones that were up in milliseconds.
    const dir = mkdtempSync(join(tmpdir(), "warden-gw-wedged-"));
    await Bun.write(join(dir, "upstream.ts"), UPSTREAM_SRC);
    await Bun.write(join(dir, "wedged.ts"), WEDGED_SRC);
    await Bun.write(
      join(dir, "config.json"),
      JSON.stringify({
        upstreams: {
          healthy: { command: "bun", args: [join(dir, "upstream.ts")], env: { SRV_NAME: "healthy" } },
          wedged: { command: "bun", args: [join(dir, "wedged.ts")] },
        },
      })
    );

    const state: StubState = { scanned: [], checkedTools: [] };
    const stub = startStub(state);
    const client = new Client({ name: "test", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StdioClientTransport({
        command: "bun",
        args: [GATEWAY],
        cwd: dir,
        env: {
          ...process.env,
          WARDEN_URL: `http://localhost:${stub.port}`,
          WARDEN_MCP_CONFIG: join(dir, "config.json"),
          WARDEN_UPSTREAM_TIMEOUT_MS: "1500",
          WARDEN_QUIET: "1",
          DB_PATH: process.env.DB_PATH ?? "./warden-test.db",
        } as Record<string, string>,
      })
    );

    try {
      const listed = await client.listTools(undefined, { timeout: 20_000 });
      expect(listed.tools.map((t) => t.name).sort()).toEqual(["echo", "send_email", "shaped"]);
      expect(textOf(await client.callTool({ name: "echo", arguments: { s: "p" } }))).toBe("healthy:p");
    } finally {
      await client.close();
      stub.stop(true);
    }
  }, 60_000);
});
