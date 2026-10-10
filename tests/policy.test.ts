import { describe, expect, test, beforeEach } from "bun:test";
import { loadPolicy, failModeFor, clearPolicyCache, DEFAULT_POLICY } from "../src/policy/loader.ts";

beforeEach(() => clearPolicyCache());

describe("policy loader", () => {
  test("an unknown agent gets the defaults", async () => {
    const p = await loadPolicy("no-such-agent");
    expect(p.thresholds.highConfidence).toBe(DEFAULT_POLICY.thresholds.highConfidence);
    expect(p.failMode).toBe("closed");
  });

  test("a policy file overrides the defaults", async () => {
    const p = await loadPolicy("strict-test");
    expect(p.thresholds.highConfidence).toBe(0.6);
    expect(p.thresholds.rules).toBe(0.5);
    expect(p.allowedTools).toEqual(["search"]);
    // Confirms it differs from the default rather than coincidentally matching it.
    expect(p.thresholds.highConfidence).not.toBe(DEFAULT_POLICY.thresholds.highConfidence);
  });

  test("defaults fill in thresholds a file omits", async () => {
    const p = await loadPolicy("default");
    for (const k of ["rules","classifier","similarity","judge","session","highConfidence","benignCertainty"] as const) {
      expect(typeof p.thresholds[k]).toBe("number");
    }
  });

  test("environment variables win over the file", async () => {
    process.env.HIGH_CONFIDENCE = "0.77";
    clearPolicyCache();
    const p = await loadPolicy("strict-test");
    expect(p.thresholds.highConfidence).toBe(0.77);
    delete process.env.HIGH_CONFIDENCE;
    clearPolicyCache();
  });

  test("source overrides fall back to the agent fail mode", async () => {
    const p = await loadPolicy("default");
    expect(failModeFor(p, "email")).toBe(p.failMode);
  });

  test("results are cached per agent", async () => {
    const a = await loadPolicy("strict-test");
    const b = await loadPolicy("strict-test");
    expect(a).toBe(b);
  });
});

describe("policy — agent id cannot select an arbitrary file", () => {
  /**
   * Regression, and a security fix. loadPolicy() interpolated the agent id straight
   * into `./policies/${agentId}.yaml`, so the id selected any .yaml on the
   * filesystem. Anything that forwards a caller-supplied id could be pointed at a
   * file the attacker controls, and a policy with failMode "open" and thresholds
   * above 1.0 is unreachable by any score — the firewall stops blocking.
   *
   * Measured before the fix, same payload, same content: agentId "normal-agent"
   * gave BLOCK 0.95, and "../../../../tmp/<planted>" gave HUMAN_REVIEW 0.95.
   */
  const TRAVERSALS = [
    "../../../../tmp/evil",
    "../../etc/passwd",
    "/etc/passwd",
    "a/b",
    "..",
    ".hidden",
    "p\u0000evil",
    "x".repeat(200),
  ];

  for (const id of TRAVERSALS) {
    test(`falls back to defaults for ${JSON.stringify(id).slice(0, 40)}`, async () => {
      const { loadPolicy } = await import("../src/policy/loader.ts");
      const p = await loadPolicy(id);
      // The defaults are what matters: a planted file would show failMode "open"
      // and a highConfidence above 1.0, which no score can reach.
      expect(p.failMode).toBe("closed");
      expect(p.thresholds.highConfidence).toBeLessThanOrEqual(1);
    });
  }

  test("ordinary agent ids are unaffected", async () => {
    const { loadPolicy } = await import("../src/policy/loader.ts");
    for (const id of ["default", "my-agent_1", "Agent.v2", "benchmark"]) {
      const p = await loadPolicy(id);
      expect(p.thresholds.highConfidence).toBeLessThanOrEqual(1);
    }
  });
});
