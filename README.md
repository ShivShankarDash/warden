# warden-mcp

MCP security gateway that scans every tool call for prompt injection attacks.

## Quick Start

Install globally:

```bash
bun add -g warden-mcp
# or
npm i -g warden-mcp
```

### Kiro

Add to `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "warden": {
      "command": "bunx",
      "args": ["warden-mcp", "--upstream-cmd", "uvx mcp-server-fetch"],
      "env": {
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "warden": {
      "command": "bunx",
      "args": ["warden-mcp", "--config", "/path/to/.warden.json"],
      "env": {
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

## What It Does

Warden sits between an AI host (Kiro, Claude Desktop, or any MCP client) and
upstream MCP servers. It scans every tool description and tool result through a
multi-stage detection pipeline — rules, classifier, similarity, and an LLM
judge — before content reaches the AI model. When a prompt injection or data
exfiltration attempt is detected, the malicious content is blocked and replaced
with a safe message.

## Configuration

### Environment Variables

| Variable                | Default          | Description                                      |
| ----------------------- | ---------------- | ------------------------------------------------ |
| `OPENAI_API_KEY`        | —                | API key for the LLM judge stage (optional)       |
| `WARDEN_FAIL_MODE`      | `closed`         | `closed` or `open` — behavior when a stage errors |
| `JUDGE_MODE`            | `sync`           | `sync` or `async` — whether the judge blocks     |
| `JUDGE_MODEL`           | `gpt-4o`         | Model name for the LLM judge                     |
| `CLASSIFIER_THRESHOLD`  | `0.85`           | Prompt Guard 2 confidence threshold              |
| `SIMILARITY_THRESHOLD`  | `0.82`           | Embedding similarity threshold                   |
| `DB_PATH`               | `./warden.db`    | Path to the SQLite database                      |

### .warden.json

```json
{
  "upstreams": {
    "fetch": { "command": "npx", "args": ["-y", "@anthropic/fetch-mcp"] },
    "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] }
  },
  "policy": {
    "failMode": "closed",
    "judgeMode": "async",
    "thresholds": {
      "classifier": 0.85,
      "similarity": 0.82
    }
  },
  "judge": {
    "model": "gpt-4o"
  }
}
```

## CLI Flags

```
--help                 Show help message and exit
--config <path>        Path to .warden.json config file
--upstream-cmd <cmd>   Upstream MCP server command (repeatable)
--api-only             Run the HTTP API server only (no MCP gateway)
--port <n>             API server port (default: 0 for MCP, 3000 for --api-only)
```

## Architecture

Warden runs a 7-stage detection pipeline on every piece of content:

1. **Extract** — pull text from HTML, PDF, email, and other formats
2. **Decode** — detect and unpack obfuscation (base64, hex, unicode tricks)
3. **Rules** — fast pattern matching for known injection signatures
4. **Classifier** — Prompt Guard 2 neural classifier for injection detection
5. **Similarity** — embedding-based comparison against known attack patterns
6. **Judge** — LLM-based analysis for sophisticated attacks that evade earlier stages
7. **Session** — cross-turn memory tracking for multi-step attack patterns

Each stage produces findings with a confidence score. The final verdict is
determined by the highest-confidence finding across all stages, compared against
configurable thresholds.

## Without a Judge LLM

Warden works without an `OPENAI_API_KEY`. The rules engine, Prompt Guard 2
classifier, and similarity stages all run locally — no external API calls needed.
Only the LLM judge stage is skipped when no key is configured. This gives you
solid baseline protection out of the box.

## Development

```bash
# Start the API server with hot reload
bun run dev

# Run the test suite
bun run test

# Run the evaluation suite
bun run eval
```
