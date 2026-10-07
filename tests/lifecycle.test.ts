import { describe, expect, test, beforeEach } from "bun:test";
import { getDb } from "../src/store/db.ts";
import { toBlob, EMBEDDING_DIMS } from "../src/detect/embeddings.ts";
import {
  runLifecyclePass,
  memoryHealth,
  isLoadBearing,
  ESCALATION_THRESHOLD,
  LOAD_BEARING_THRESHOLD,
  STALE_DAYS,
} from "../src/store/lifecycle.ts";

/** Synthetic vectors — avoids ONNX runtime which crashes in bun:test. */
function vec(seed: number): Float32Array {
  const v = new Float32Array(EMBEDDING_DIMS);
  let x = seed;
  for (let i = 0; i < v.length; i++) {
    x = (x * 1664525 + 1013904223) % 4294967296;
    v[i] = x / 4294967296 - 0.5;
  }
  return v;
}

const AGENT = "lifecycletest";
const STALE_MS = STALE_DAYS * 86_400_000;

function insertMemory(overrides: {
  id?: string;
  status?: string;
  matchCount?: number;
  lastMatchedAt?: number | null;
  createdAt?: number;
  label?: string;
  origin?: string;
}) {
  const now = Date.now();
  const id = overrides.id ?? crypto.randomUUID();
  getDb()
    .prepare(
      `INSERT INTO memory
        (id, label, attack_type, embedding, text, source, source_id, status, origin,
         confirmations, agent_id, valid_from, valid_to, created_at, match_count, last_matched_at)
       VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, 1, ?, ?, NULL, ?, ?, ?)`
    )
    .run(
      id,
      overrides.label ?? "attack",
      "instruction_override",
      toBlob(vec(Math.random() * 10000)),
      "test payload " + id,
      overrides.status ?? "probation",
      overrides.origin ?? "judge",
      AGENT,
      overrides.createdAt ?? now,
      overrides.createdAt ?? now,
      overrides.matchCount ?? 0,
      overrides.lastMatchedAt ?? null
    );
  return id;
}

beforeEach(() => {
  getDb().prepare("DELETE FROM memory WHERE agent_id = ?").run(AGENT);
});

describe("runLifecyclePass", () => {
  test("promotes probationary entries with match_count >= ESCALATION_THRESHOLD", () => {
    const id = insertMemory({ status: "probation", matchCount: ESCALATION_THRESHOLD });
    const stats = runLifecyclePass(AGENT);
    expect(stats.promoted).toBe(1);

    const row = getDb()
      .query("SELECT status FROM memory WHERE id = ?")
      .get(id) as { status: string };
    expect(row.status).toBe("active");
  });

  test("does NOT promote entries below ESCALATION_THRESHOLD", () => {
    insertMemory({ status: "probation", matchCount: ESCALATION_THRESHOLD - 1 });
    const stats = runLifecyclePass(AGENT);
    expect(stats.promoted).toBe(0);
  });

  test("retires active entries not matched in 30+ days", () => {
    const staleTime = Date.now() - STALE_MS - 1000;
    const id = insertMemory({
      status: "active",
      matchCount: 3,
      lastMatchedAt: staleTime,
      createdAt: staleTime - 10_000,
    });
    const stats = runLifecyclePass(AGENT);
    expect(stats.retired).toBe(1);

    const row = getDb()
      .query("SELECT status, valid_to FROM memory WHERE id = ?")
      .get(id) as { status: string; valid_to: number | null };
    expect(row.status).toBe("retired");
    expect(row.valid_to).not.toBeNull();
  });

  test("does NOT retire load-bearing entries (match_count >= LOAD_BEARING_THRESHOLD)", () => {
    const staleTime = Date.now() - STALE_MS - 1000;
    insertMemory({
      status: "active",
      matchCount: LOAD_BEARING_THRESHOLD,
      lastMatchedAt: staleTime,
      createdAt: staleTime - 10_000,
    });
    const stats = runLifecyclePass(AGENT);
    expect(stats.retired).toBe(0);
    expect(stats.loadBearing).toBe(1);
  });

  test("retires entries that were never matched and are older than STALE_DAYS", () => {
    const oldTime = Date.now() - STALE_MS - 1000;
    const id = insertMemory({
      status: "probation",
      matchCount: 0,
      lastMatchedAt: null,
      createdAt: oldTime,
    });
    const stats = runLifecyclePass(AGENT);
    expect(stats.retired).toBe(1);

    const row = getDb()
      .query("SELECT status FROM memory WHERE id = ?")
      .get(id) as { status: string };
    expect(row.status).toBe("retired");
  });

  test("does NOT retire recently created never-matched entries", () => {
    insertMemory({
      status: "probation",
      matchCount: 0,
      lastMatchedAt: null,
      createdAt: Date.now(),
    });
    const stats = runLifecyclePass(AGENT);
    expect(stats.retired).toBe(0);
  });
});

describe("memoryHealth", () => {
  test("returns correct counts", () => {
    const staleTime = Date.now() - STALE_MS - 1000;

    // 1 active, non-stale
    insertMemory({ status: "active", matchCount: 3, lastMatchedAt: Date.now() });
    // 1 active, stale
    insertMemory({ status: "active", matchCount: 2, lastMatchedAt: staleTime, createdAt: staleTime });
    // 1 active, load-bearing
    insertMemory({ status: "active", matchCount: LOAD_BEARING_THRESHOLD, lastMatchedAt: Date.now() });
    // 1 probation
    insertMemory({ status: "probation", matchCount: 1 });

    const health = memoryHealth(AGENT);
    expect(health.active).toBe(3);
    expect(health.probation).toBe(1);
    expect(health.retired).toBe(0);
    expect(health.loadBearing).toBe(1);
    expect(health.stale).toBe(1);
    expect(health.total).toBe(4);
  });
});

describe("isLoadBearing", () => {
  test("returns true for high match_count entries", () => {
    const id = insertMemory({ status: "active", matchCount: LOAD_BEARING_THRESHOLD });
    expect(isLoadBearing(id)).toBe(true);
  });

  test("returns false for low match_count entries", () => {
    const id = insertMemory({ status: "active", matchCount: 2 });
    expect(isLoadBearing(id)).toBe(false);
  });

  test("returns false for non-existent entry", () => {
    expect(isLoadBearing("nonexistent-id")).toBe(false);
  });
});
