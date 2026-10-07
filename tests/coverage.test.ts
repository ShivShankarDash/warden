import { describe, expect, test, beforeEach } from "bun:test";
import { recordCoverageOutcome, coverageGaps, coverageSummary } from "../src/store/coverage.ts";
import { getDb } from "../src/store/db.ts";
import { addMemory } from "../src/store/memory.ts";
import { EMBEDDING_DIMS } from "../src/detect/embeddings.ts";

/** Synthetic vectors — same pattern as memory.test.ts. */
function vec(seed: number): Float32Array {
  const v = new Float32Array(EMBEDDING_DIMS);
  let x = seed;
  for (let i = 0; i < v.length; i++) {
    x = (x * 1664525 + 1013904223) % 4294967296;
    v[i] = x / 4294967296 - 0.5;
  }
  return v;
}

const AGENT = "coveragetest";

beforeEach(() => {
  getDb().prepare("DELETE FROM coverage_stats WHERE agent_id = ?").run(AGENT);
  getDb().prepare("DELETE FROM memory WHERE agent_id = ?").run(AGENT);
});

describe("recordCoverageOutcome", () => {
  test("increments scans and detected on a detection", () => {
    recordCoverageOutcome("tool_abuse", true, AGENT);
    const rows = coverageSummary(AGENT);
    expect(rows).toHaveLength(1);
    expect(rows[0].attackType).toBe("tool_abuse");
    expect(rows[0].scans).toBe(1);
    expect(rows[0].detected).toBe(1);
    expect(rows[0].missed).toBe(0);
    expect(rows[0].lastMissedAt).toBeNull();
  });

  test("increments scans and missed on a miss, and sets last_missed_at", () => {
    recordCoverageOutcome("role_change", false, AGENT);
    const rows = coverageSummary(AGENT);
    expect(rows).toHaveLength(1);
    expect(rows[0].scans).toBe(1);
    expect(rows[0].detected).toBe(0);
    expect(rows[0].missed).toBe(1);
    expect(rows[0].lastMissedAt).toBeGreaterThan(0);
  });

  test("multiple calls accumulate correctly (upsert)", () => {
    recordCoverageOutcome("tool_abuse", true, AGENT);
    recordCoverageOutcome("tool_abuse", true, AGENT);
    recordCoverageOutcome("tool_abuse", false, AGENT);
    const rows = coverageSummary(AGENT);
    expect(rows).toHaveLength(1);
    expect(rows[0].scans).toBe(3);
    expect(rows[0].detected).toBe(2);
    expect(rows[0].missed).toBe(1);
    expect(rows[0].lastMissedAt).toBeGreaterThan(0);
  });

  test("ignores empty attack type", () => {
    recordCoverageOutcome("", true, AGENT);
    expect(coverageSummary(AGENT)).toHaveLength(0);
  });
});

describe("coverageGaps", () => {
  test("returns attack types sorted by weakness (lowest detection rate first)", () => {
    // tool_abuse: 1 detected, 1 missed → 50% rate
    recordCoverageOutcome("tool_abuse", true, AGENT);
    recordCoverageOutcome("tool_abuse", false, AGENT);

    // role_change: 3 detected, 0 missed → 100% rate
    recordCoverageOutcome("role_change", true, AGENT);
    recordCoverageOutcome("role_change", true, AGENT);
    recordCoverageOutcome("role_change", true, AGENT);

    // secret_extraction: 0 detected, 2 missed → 0% rate
    recordCoverageOutcome("secret_extraction", false, AGENT);
    recordCoverageOutcome("secret_extraction", false, AGENT);

    const gaps = coverageGaps(AGENT);
    expect(gaps).toHaveLength(3);
    // Weakest first
    expect(gaps[0].attackType).toBe("secret_extraction");
    expect(gaps[0].detectionRate).toBe(0);
    expect(gaps[1].attackType).toBe("tool_abuse");
    expect(gaps[1].detectionRate).toBe(0.5);
    expect(gaps[2].attackType).toBe("role_change");
    expect(gaps[2].detectionRate).toBe(1);
  });

  test("tiebreaks by fewest memories", () => {
    // Both at 50% detection rate
    recordCoverageOutcome("tool_abuse", true, AGENT);
    recordCoverageOutcome("tool_abuse", false, AGENT);
    recordCoverageOutcome("role_change", true, AGENT);
    recordCoverageOutcome("role_change", false, AGENT);

    // Give role_change more active memories than tool_abuse
    addMemory({ label: "attack", attackType: "role_change", vector: vec(1), text: "x".repeat(40), origin: "human", agentId: AGENT });
    addMemory({ label: "attack", attackType: "role_change", vector: vec(2), text: "y".repeat(40), origin: "human", agentId: AGENT });
    addMemory({ label: "attack", attackType: "tool_abuse", vector: vec(3), text: "z".repeat(40), origin: "human", agentId: AGENT });

    const gaps = coverageGaps(AGENT);
    expect(gaps).toHaveLength(2);
    // tool_abuse has fewer memories (1 vs 2), so it appears first as the tiebreak
    expect(gaps[0].attackType).toBe("tool_abuse");
    expect(gaps[0].memoryCount).toBe(1);
    expect(gaps[1].attackType).toBe("role_change");
    expect(gaps[1].memoryCount).toBe(2);
  });

  test("returns empty array when no coverage data exists", () => {
    expect(coverageGaps(AGENT)).toHaveLength(0);
  });

  test("does not leak data between agents", () => {
    recordCoverageOutcome("tool_abuse", true, AGENT);
    expect(coverageGaps("other-agent")).toHaveLength(0);
  });
});
