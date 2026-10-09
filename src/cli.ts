#!/usr/bin/env bun
/**
 * Warden CLI entry point.
 *
 * Parses command-line arguments and launches Warden in the requested mode.
 */
import { loadConfig } from "./gateway/config.ts";
import { startWarden } from "./mcp.ts";

const USAGE = `
Usage: agent-warden [options]

  Warden MCP security gateway — scans content flowing between MCP hosts and
  upstream MCP servers for prompt injection, data exfiltration, and tool abuse.

Options:
  --help                 Show this help message and exit
  --config <path>        Path to .warden.json config file (auto-discovers
                         .warden.json and warden-mcp.json if omitted)
  --upstream-cmd <cmd>   Upstream MCP server command (repeatable)
  --quiet                 Suppress per-scan logging (only startup banner and
                         blocks print). Also: WARDEN_QUIET=1
  --api-only             Run the HTTP API server only (no MCP gateway)
  --port <n>             API server port (default: 0 for MCP mode, 3000 for
                         --api-only)

Environment variables:
  OPENAI_API_KEY         API key for the LLM judge stage (optional)
  WARDEN_FAIL_MODE       "closed" (default) or "open" — what happens when a
                         detection stage errors
  JUDGE_MODE             "sync" (default) or "async" — whether the judge runs
                         on the request path
  JUDGE_MODEL            Model name for the judge (e.g. gpt-4o)
  DB_PATH                Path to the SQLite database (default: ./warden.db)

Example config (.warden.json):
  {
    "upstreams": {
      "fetch": { "command": "npx", "args": ["-y", "@anthropic/fetch-mcp"] }
    },
    "policy": { "failMode": "closed", "judgeMode": "async" },
    "judge": { "model": "gpt-4o" }
  }

Kiro config (~/.kiro/settings.json):
  {
    "mcpServers": {
      "warden": {
        "command": "bunx",
        "args": ["agent-warden", "--upstream-cmd", "npx -y @anthropic/fetch-mcp"]
      }
    }
  }

Claude Desktop config:
  {
    "mcpServers": {
      "warden": {
        "command": "bunx",
        "args": ["agent-warden", "--config", "/path/to/.warden.json"]
      }
    }
  }
`.trimStart();

function printHelp() {
  console.error(USAGE);
  process.exit(0);
}

// --- Argument parsing (no external deps) ---

const args = process.argv.slice(2);
let configPath: string | undefined;
let apiOnly = false;
let quiet = process.env.WARDEN_QUIET === "1";
let port: number | undefined;
const upstreamCmds: string[] = [];

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  switch (arg) {
    case "--help":
    case "-h":
      printHelp();
      break;
    case "--config":
      configPath = args[++i];
      if (!configPath) {
        console.error("Error: --config requires a path argument");
        process.exit(1);
      }
      break;
    case "--upstream-cmd":
      const cmd = args[++i];
      if (!cmd) {
        console.error("Error: --upstream-cmd requires a command argument");
        process.exit(1);
      }
      upstreamCmds.push(cmd);
      break;
    case "--api-only":
      apiOnly = true;
      break;
    case "--quiet":
      quiet = true;
      break;
    case "--port":
      const p = args[++i];
      if (!p || isNaN(Number(p))) {
        console.error("Error: --port requires a numeric argument");
        process.exit(1);
      }
      port = Number(p);
      break;
    default:
      console.error(`Unknown option: ${arg}`);
      console.error("Run with --help for usage information.");
      process.exit(1);
  }
}

// Default port: 0 for MCP mode (OS-assigned), 3000 for api-only.
if (port === undefined) {
  port = apiOnly ? 3000 : 0;
}

const config = await loadConfig(configPath);

await startWarden({
  mode: apiOnly ? "api-only" : "mcp",
  port,
  config,
  upstreamCmds: upstreamCmds.length ? upstreamCmds : undefined,
  quiet,
});
