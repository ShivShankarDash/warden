/**
 * Laya sidecar lifecycle.
 *
 * Laya is the primary classifier. Measured on the 253-case eval suite it is worth
 * 6.7 points of detection (83.8% vs 77.1%) and it nearly halves how often the
 * expensive LLM judge has to run (18.6% vs 34.0% of scans) — so running without it
 * is both less accurate and more costly per scan.
 *
 * It is a Python process rather than part of the Bun server, so it has to be
 * started and supervised separately. Everything here is best-effort: if Python is
 * missing, the install fails, or the model cannot be fetched, Warden still runs on
 * the bundled Prompt Guard 2 classifier. The user is told what is missing and what
 * it costs rather than silently getting the weaker path.
 */
import { spawn, spawnSync, type Subprocess } from "bun";
import { bold, dim, green, yellow, cyan, emoji } from "./gateway/colors.ts";

const PORT = Number(process.env.LAYA_PORT ?? 8111);
const HEALTH_URL = `http://localhost:${PORT}/health`;

/** Model download on first run is large and slow; the server is useless until it lands. */
const STARTUP_TIMEOUT_MS = Number(process.env.LAYA_STARTUP_TIMEOUT ?? 300_000);

let child: Subprocess | null = null;

async function isUp(timeoutMs = 1500): Promise<boolean> {
  try {
    const res = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(timeoutMs) });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * spawnSync throws ENOENT when the executable does not exist rather than returning
 * a failed result, so every probe here has to be guarded. Checking for an
 * interpreter that is not installed yet is the normal first-run path, not an error.
 */
function probe(cmd: string[]): boolean {
  try {
    return spawnSync(cmd, { stdout: "pipe", stderr: "pipe" }).success;
  } catch {
    return false;
  }
}

function findPython(): string | null {
  for (const candidate of [process.env.LAYA_PYTHON, "python3", "python"]) {
    if (!candidate) continue;
    if (probe([candidate, "--version"])) return candidate;
  }
  return null;
}

function hasLaya(python: string): boolean {
  return probe([python, "-c", "import laya"]);
}

/** Warden's own virtualenv, so nothing is installed into the user's Python. */
function venvPython(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? ".";
  return `${home}/.warden/venv/bin/python`;
}

/**
 * Creates the managed virtualenv.
 *
 * Installing into the system Python is not an option: since PEP 668 most
 * distributions mark it externally-managed and pip refuses outright. The documented
 * escape hatch, --break-system-packages, does exactly what it says and is not
 * something a security tool should do to someone's machine on first run. An isolated
 * venv under ~/.warden costs a few seconds, touches nothing else, and can be deleted
 * by removing one directory.
 */
function createVenv(python: string): string | null {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? ".";
  const dir = `${home}/.warden/venv`;
  if (!probe([python, "-m", "venv", dir])) return null;
  const vp = `${dir}/bin/python`;
  return probe([vp, "--version"]) ? vp : null;
}

/**
 * Installs Laya with pip.
 *
 * Announced before it runs, never silently: this fetches a package and, on first
 * model load, roughly 1.2GB of weights. A user is entitled to know that before it
 * happens, and to decline it — WARDEN_NO_LAYA_INSTALL=1 skips straight to fallback.
 */
function installLaya(python: string): string | null {
  console.error("");
  console.error(`${emoji.shield}  ${bold("Warden is setting up its detector")}`);
  console.error("");
  console.error(`   ${bold("What:")}  the ${cyan("laya")} Python package, into its own virtualenv`);
  console.error(`           at ${dim("~/.warden/venv")} — your system Python is not touched`);
  console.error(`   ${bold("Why:")}   Laya is the main detector. Without it Warden catches`);
  console.error(`           ${yellow("~7% fewer attacks")} and calls the paid LLM judge`);
  console.error(`           ${yellow("about twice as often")}.`);
  console.error(`   ${bold("Size:")}  small package now, ~1.2GB model on first scan`);
  console.error("");
  console.error(dim("   Skip with WARDEN_NO_LAYA_INSTALL=1 — Warden still works without it."));
  console.error("");
  console.error(dim("   Creating virtualenv…"));

  const vp = createVenv(python);
  if (!vp) {
    console.error(`   ${yellow("!")} could not create virtualenv — continuing without Laya`);
    return null;
  }

  console.error(dim("   Installing laya (this can take a minute)…"));
  const r = spawnSync([vp, "-m", "pip", "install", "--quiet", "laya"], {
    stdout: "inherit",
    stderr: "inherit",
  });
  if (!r.success) {
    console.error(`   ${yellow("!")} pip install failed — continuing without Laya`);
    return null;
  }

  console.error(`   ${green("✓")} Laya ready`);
  console.error("");
  return vp;
}

async function waitForHealth(deadlineMs: number): Promise<boolean> {
  const started = Date.now();
  let announced = false;
  while (Date.now() - started < deadlineMs) {
    if (await isUp()) return true;
    if (child?.exitCode !== null && child?.exitCode !== undefined) return false; // died
    if (!announced && Date.now() - started > 5000) {
      console.error(dim(`   ${emoji.shield} Laya is loading its model (first run downloads ~1.2GB)…`));
      announced = true;
    }
    await Bun.sleep(1000);
  }
  return false;
}

export interface SidecarResult {
  running: boolean;
  reason: string;
}

/**
 * Brings Laya up if it can. Returns rather than throws — a missing classifier
 * degrades accuracy, it does not stop the firewall from working.
 */
export async function ensureLayaRunning(scriptPath: string): Promise<SidecarResult> {
  if (process.env.WARDEN_NO_LAYA === "1") {
    return { running: false, reason: "disabled by WARDEN_NO_LAYA=1" };
  }

  // Someone may already be running it, or LAYA_URL may point somewhere remote.
  if (await isUp()) return { running: true, reason: "already running" };
  if (process.env.LAYA_URL && !process.env.LAYA_URL.includes("localhost")) {
    return { running: false, reason: `using remote LAYA_URL (${process.env.LAYA_URL})` };
  }

  const systemPython = findPython();
  if (!systemPython) {
    return {
      running: false,
      reason: "python3 not found — install Python 3 to enable the Laya classifier",
    };
  }

  // Prefer an interpreter that already has Laya: our managed venv first, then the
  // user's Python in case they installed it themselves.
  let python: string | null = null;
  const managed = venvPython();
  if (hasLaya(managed)) python = managed;
  else if (hasLaya(systemPython)) python = systemPython;

  if (!python) {
    if (process.env.WARDEN_NO_LAYA_INSTALL === "1") {
      return { running: false, reason: "laya not installed (auto-install disabled)" };
    }
    python = installLaya(systemPython);
    if (!python) return { running: false, reason: "laya install failed" };
  }

  child = spawn([python, scriptPath], {
    stdout: "ignore",
    // Laya logs model loading to stderr; keep it out of the operator's way but let
    // real failures surface via the health check below.
    stderr: "ignore",
    env: { ...process.env, LAYA_PORT: String(PORT) },
  });

  if (await waitForHealth(STARTUP_TIMEOUT_MS)) {
    return { running: true, reason: "started" };
  }

  child?.kill();
  child = null;
  return { running: false, reason: "sidecar failed to become healthy in time" };
}

/** Stops the sidecar if this process started it. */
export function stopLaya(): void {
  if (child) {
    child.kill();
    child = null;
  }
}

/** One line telling the operator which classifier is actually in use, and the cost. */
export function reportClassifier(result: SidecarResult): void {
  if (result.running) {
    console.error(`   Classifier  ${green("Laya")} ${dim(`(${result.reason})`)}`);
  } else {
    console.error(`   Classifier  ${yellow("Prompt Guard 2")} ${dim("— built-in fallback")}`);
    console.error(`               ${dim(result.reason)}`);
    console.error(`               ${dim("~7% fewer attacks caught, ~2x more judge calls")}`);
  }
}
