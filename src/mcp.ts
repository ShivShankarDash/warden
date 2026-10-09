/**
 * Warden self-contained orchestrator.
 *
 * Runs the API server (detection engine) and the MCP gateway in a single process.
 * In MCP mode, stdout is the protocol wire — nothing may be written to it except
 * MCP frames. The console.log redirect below prevents model-loading messages from
 * corrupting the stream.
 */

// Redirect console.log to stderr BEFORE importing anything that loads models.
const _origLog = console.log;
console.log = (...args: unknown[]) => console.error(...args);

import { applyConfigToEnv, type GatewayConfig } from "./gateway/config.ts";
import { startApiServer, stopApiServer } from "./api/index.ts";
import { startGateway, getGatewayStats } from "./gateway/index.ts";
import { rule, bold, dim, green, red, yellow, emoji } from "./gateway/colors.ts";

export interface WardenOptions {
  mode: "mcp" | "api-only";
  port?: number;
  config?: GatewayConfig;
  upstreamCmds?: string[];
  quiet?: boolean;
}

export async function startWarden(options: WardenOptions) {
  const { mode, config, upstreamCmds } = options;

  // Apply policy/judge env vars from config before models load.
  if (config) {
    applyConfigToEnv(config);
  }

  // When WARDEN_URL is already set (pointing at a remote server), skip the local
  // API server entirely — the gateway will send scans to the remote instance.
  const remoteUrl = process.env.WARDEN_URL;
  let apiServer: Awaited<ReturnType<typeof startApiServer>> | null = null;
  let actualPort: number | undefined;

  if (remoteUrl) {
    console.error(`[warden] Using remote API at ${remoteUrl} (skipping local server)`);
  } else {
    // Start the API server (initialises DB, loads models).
    apiServer = await startApiServer(options.port ?? 0);
    actualPort = apiServer.port;
    // Point the gateway's HTTP scan client at the in-process API server.
    process.env.WARDEN_URL = `http://localhost:${actualPort}`;
    console.error(`[warden] API server on port ${actualPort}`);
  }

  if (mode === "api-only") {
    return { apiServer, port: actualPort };
  }

  // MCP mode: merge --upstream-cmd entries into config upstreams.
  const mergedConfig: GatewayConfig = {
    upstreams: { ...(config?.upstreams ?? {}) },
    policy: config?.policy,
    judge: config?.judge,
    quiet: options.quiet || process.env.WARDEN_QUIET === "1",
  };

  if (upstreamCmds?.length) {
    for (let i = 0; i < upstreamCmds.length; i++) {
      const parts = upstreamCmds[i].split(/\s+/);
      const [command, ...args] = parts;
      mergedConfig.upstreams[`upstream-${i + 1}`] = { command, args };
    }
  }

  const gateway = await startGateway(mergedConfig);

  // Graceful shutdown on signals.
  const shutdown = () => {
    // Print session summary before exiting.
    const s = getGatewayStats();
    console.error("");
    console.error(rule());
    console.error(`${emoji.shield}  ${bold("WARDEN SESSION SUMMARY")}`);
    console.error(`   Total scans:  ${s.totalScans}`);
    console.error(`   Allowed:      ${green(String(s.allowed))}`);
    const blockedLine = s.attackTypes.length
      ? `${red(String(s.blocked))} — ${s.attackTypes.join(", ")}`
      : red(String(s.blocked));
    console.error(`   Blocked:      ${blockedLine}`);
    console.error(`   Spotlighted:  ${yellow(String(s.spotlighted))}`);
    console.error(`   Avg latency:  ${dim(`${s.avgLatencyMs}ms`)}`);
    console.error(rule());

    gateway.server.close().catch(() => {});
    stopApiServer();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  return { apiServer, gateway, port: actualPort };
}
