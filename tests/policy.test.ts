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
