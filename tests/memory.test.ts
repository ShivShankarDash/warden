import { describe, expect, test, beforeEach } from "bun:test";
import {
  addMemory, confirmMemory, approveMemory, retireMemory,
  activeMemories, allMemories, memoryStats,
} from "../src/store/memory.ts";
import { getDb } from "../src/store/db.ts";
import { EMBEDDING_DIMS } from "../src/detect/embeddings.ts";

/** Synthetic vectors keep this suite off the ONNX runtime, which crashes bun test. */
function vec(seed: number): Float32Array {
  const v = new Float32Array(EMBEDDING_DIMS);
  let x = seed;
  for (let i = 0; i < v.length; i++) {
    x = (x * 1664525 + 1013904223) % 4294967296;
    v[i] = x / 4294967296 - 0.5;
  }
  return v;
}

const AGENT = "memtest";

beforeEach(() => {
  getDb().prepare("DELETE FROM memory WHERE agent_id = ?").run(AGENT);
});

describe("probation", () => {
  test("a judge-learned memory starts on probation and is invisible to scanning", () => {
    addMemory({ label: "attack", attackType: "tool_abuse", vector: vec(1), text: "x".repeat(40), origin: "judge", agentId: AGENT });
    expect(memoryStats(AGENT).attack.probation).toBe(1);
    expect(activeMemories({ agentId: AGENT })).toHaveLength(0);
  });

  test("a second independent sighting promotes it", () => {
    const m = addMemory({ label: "attack", attackType: "tool_abuse", vector: vec(2), text: "y".repeat(40), origin: "judge", agentId: AGENT });
    expect(confirmMemory(m.id)).toBe("active");
    expect(activeMemories({ agentId: AGENT })).toHaveLength(1);
  });

  test("human approval promotes immediately", () => {
    const m = addMemory({ label: "attack", attackType: "role_change", vector: vec(3), text: "z".repeat(40), origin: "judge", agentId: AGENT });
    approveMemory(m.id);
    const active = activeMemories({ agentId: AGENT });
    expect(active).toHaveLength(1);
    expect(active[0].origin).toBe("human");
  });

  test("human and seed origins bypass probation entirely", () => {
    for (const origin of ["human", "seed"] as const) {
      addMemory({ label: "safe", vector: vec(origin === "human" ? 4 : 5), text: "q".repeat(40), origin, agentId: AGENT });
    }
    expect(activeMemories({ agentId: AGENT })).toHaveLength(2);
    expect(memoryStats(AGENT).safe.probation).toBe(0);
  });
});

describe("temporal versioning", () => {
  test("retiring closes the window but keeps the row", () => {
    const m = addMemory({ label: "attack", attackType: "tool_abuse", vector: vec(6), text: "r".repeat(40), origin: "human", agentId: AGENT });
    expect(activeMemories({ agentId: AGENT })).toHaveLength(1);
    retireMemory(m.id);
    expect(activeMemories({ agentId: AGENT })).toHaveLength(0);
    // The row survives, so history and rollback remain possible.
    const row = getDb().query("SELECT status, valid_to FROM memory WHERE id = ?").get(m.id) as { status: string; valid_to: number | null };
    expect(row.status).toBe("retired");
    expect(row.valid_to).not.toBeNull();
  });

  test("asOf answers what was believed at a past instant", () => {
    const m = addMemory({ label: "attack", attackType: "tool_abuse", vector: vec(7), text: "s".repeat(40), origin: "human", agentId: AGENT });
    const beforeRetirement = Date.now() + 1;
    retireMemory(m.id, beforeRetirement + 10);
    expect(activeMemories({ agentId: AGENT, asOf: beforeRetirement })).toHaveLength(1);
    expect(activeMemories({ agentId: AGENT, asOf: beforeRetirement + 100 })).toHaveLength(0);
  });
});

describe("isolation", () => {
  test("memory does not leak between agents", () => {
    addMemory({ label: "attack", attackType: "tool_abuse", vector: vec(8), text: "t".repeat(40), origin: "human", agentId: AGENT });
    expect(activeMemories({ agentId: "some-other-agent" })).toHaveLength(0);
  });
});

describe("stats", () => {
  test("counts by label and status", () => {
    addMemory({ label: "attack", attackType: "tool_abuse", vector: vec(9), text: "a".repeat(40), origin: "judge", agentId: AGENT });
    addMemory({ label: "safe", vector: vec(10), text: "b".repeat(40), origin: "human", agentId: AGENT });
    const s = memoryStats(AGENT);
    expect(s.attack.probation).toBe(1);
    expect(s.safe.active).toBe(1);
    expect(allMemories({ agentId: AGENT })).toHaveLength(2);
  });
});
