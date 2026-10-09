#!/usr/bin/env bun
/**
 * Warden CLI entry point.
 *
 * Parses command-line arguments and launches Warden in the requested mode.
 */
import { loadConfig } from "./gateway/config.ts";
import { startWarden } from "./mcp.ts";

const USAGE = `
Usage: agent-warden [command] [options]

Commands:
  (default)              Run the MCP gateway
  intel                  Fetch new attack examples from public threat feeds and
                         seed the ones this install misses into memory
  redteam                Probe this install for gaps with generated attacks
                         (source repo only; needs an LLM key)

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

// --- Subcommands ---------------------------------------------------------
//
// The intel and redteam agents were previously reachable only as package.json
// scripts, which work inside a checkout and nowhere else — so anyone who
// installed Warden from npm had the code on disk with no way to run it. Routing
// them through the CLI makes them part of the product rather than repo tooling.

const args = process.argv.slice(2);

async function runSubcommand(relPath: string, label: string): Promise<never> {
  // These modules guard their entry point with `import.meta.main`, so importing
  // them does nothing. Spawning the file keeps that guard true and lets each
  // module parse its own flags.
  const target = new URL(relPath, import.meta.url).pathname;
  if (!(await Bun.file(target).exists())) {
    console.error(`The ${label} agent is not available in this install.`);
    console.error("It ships with the source repo: https://github.com/shivdev/agent-warden");
    process.exit(1);
  }
  const proc = Bun.spawn(["bun", target, ...args.slice(1)], {
    stdout: "inherit",
    stderr: "inherit",
    stdin: "inherit",
  });
  process.exit(await proc.exited);
}

if (args[0] === "intel") {
  // Pulls fresh prompt-injection examples from public datasets, checks each
  // against this install, and seeds the misses into memory.
  await runSubcommand("./intel/agent.ts", "intel");
}

if (args[0] === "redteam") {
  // Generates adversarial variants and probes this install for gaps. Requires an
  // LLM key; it is a testing tool, not part of the serving path.
  await runSubcommand("../redteam/runner.ts", "redteam");
}

// --- Argument parsing (no external deps) ---

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
