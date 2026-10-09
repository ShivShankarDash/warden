import { describe, expect, test, afterEach } from "bun:test";

const CLI = ["bun", "src/cli.ts"];
const spawned: ReturnType<typeof Bun.spawn>[] = [];

/** Spawn a CLI process and track it for cleanup. */
function spawnCli(args: string[], env?: Record<string, string>) {
  const proc = Bun.spawn([...CLI, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, DB_PATH: "./warden-test.db", ...env },
  });
  spawned.push(proc);
  return proc;
}

afterEach(() => {
  for (const proc of spawned) {
    try {
      proc.kill();
    } catch {}
  }
  spawned.length = 0;
});

describe("cli", () => {
  test("--help prints usage and exits 0", async () => {
    const proc = spawnCli(["--help"]);
    const exitCode = await proc.exited;
    const stderr = await new Response(proc.stderr).text();
    const stdout = await new Response(proc.stdout).text();

    expect(exitCode).toBe(0);
    expect(stderr).toContain("warden-mcp");
    expect(stderr).toContain("Usage");
    expect(stdout).toBe("");
  });

  test("unknown flag exits with non-zero code", async () => {
    const proc = spawnCli(["--unknown-flag"]);
    const exitCode = await proc.exited;

    expect(exitCode).not.toBe(0);
  });

  test("--api-only starts HTTP server", async () => {
    const proc = spawnCli(["--api-only", "--port", "0"]);

    // Read stderr incrementally to find the port line.
    const reader = proc.stderr.getReader();
    let stderrText = "";
    const decoder = new TextDecoder();
    const deadline = Date.now() + 10_000;

    while (Date.now() < deadline) {
      const { done, value } = await reader.read();
      if (done) break;
      stderrText += decoder.decode(value, { stream: true });
      if (stderrText.includes("[warden] API server on port")) break;
    }
    reader.releaseLock();

    const portMatch = stderrText.match(/API server on port (\d+)/);
    expect(portMatch).not.toBeNull();
    const port = Number(portMatch![1]);

    const res = await fetch(`http://localhost:${port}/metrics`);
    expect(res.status).toBe(200);

    proc.kill();
    await proc.exited;
  });

  test("multiple --upstream-cmd flags are accepted", async () => {
    // Verify the CLI parses multiple --upstream-cmd flags without error
    // by combining them with --help (which exits before starting servers).
    const proc = spawnCli([
      "--upstream-cmd",
      "echo server1",
      "--upstream-cmd",
      "echo server2",
      "--help",
    ]);
    const exitCode = await proc.exited;
    const stderr = await new Response(proc.stderr).text();

    expect(exitCode).toBe(0);
    expect(stderr).toContain("Usage");
  });
});
