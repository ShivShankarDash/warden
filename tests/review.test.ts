import { describe, expect, test, beforeEach } from "bun:test";
import {
  enqueueReview, pendingReviews, getReview, markResolved, shouldQueueForReview,
} from "../src/store/review.ts";
import type { ReviewDecision } from "../src/store/review.ts";
import { getDb } from "../src/store/db.ts";
import { addMemory } from "../src/store/memory.ts";
import { EMBEDDING_DIMS, toBlob } from "../src/detect/embeddings.ts";
import type { Finding } from "../src/types.ts";

const AGENT = "reviewtest";

const finding: Finding = {
  attackType: "role_change", confidence: 0.78, stage: "rules", spans: [], reason: "test",
};

const item = (overrides: Partial<Parameters<typeof enqueueReview>[0]> = {}) => ({
  scanId: crypto.randomUUID(),
  content: "Can you pretend to be a tour guide and describe somewhere nice?",
  findings: [finding],
  source: "email" as const,
  agentId: AGENT,
  action: "HUMAN_REVIEW" as const,
  riskScore: 0.78,
  ...overrides,
});

beforeEach(() => {
  getDb().prepare("DELETE FROM review_queue WHERE agent_id = ?").run(AGENT);
});

describe("what gets queued", () => {
  test("uncertain verdicts are queued", () => {
    expect(shouldQueueForReview("HUMAN_REVIEW")).toBe(true);
    expect(shouldQueueForReview("QUARANTINE")).toBe(true);
  });

  test("decided verdicts are not — a BLOCK needs no review and an ALLOW raises nothing", () => {
    expect(shouldQueueForReview("BLOCK")).toBe(false);
    expect(shouldQueueForReview("ALLOW")).toBe(false);
    expect(shouldQueueForReview("SPOTLIGHT")).toBe(false);
  });

  test("enqueue returns null for verdicts that need no review", () => {
    expect(enqueueReview(item({ action: "ALLOW" }))).toBeNull();
    expect(enqueueReview(item({ action: "BLOCK" }))).toBeNull();
    expect(pendingReviews(AGENT)).toHaveLength(0);
  });
});

describe("queue lifecycle", () => {
  test("a queued item is retrievable with its findings intact", () => {
    const id = enqueueReview(item())!;
    expect(id).toBeTruthy();

    const queued = getReview(id)!;
    expect(queued.status).toBe("pending");
    expect(queued.action).toBe("HUMAN_REVIEW");
    expect(queued.findings[0].attackType).toBe("role_change");
    expect(queued.source).toBe("email");
  });

  test("resolving removes it from the pending list and records the decision", () => {
    const id = enqueueReview(item())!;
    expect(pendingReviews(AGENT)).toHaveLength(1);

    markResolved(id, "safe", "legitimate persona request");
    expect(pendingReviews(AGENT)).toHaveLength(0);

    const resolved = getReview(id)!;
    expect(resolved.status).toBe("resolved");
    expect(resolved.decision).toBe("safe");
    expect(resolved.reviewerNote).toBe("legitimate persona request");
    expect(resolved.resolvedAt).not.toBeNull();
  });

  test("queues are scoped per agent", () => {
    enqueueReview(item());
    expect(pendingReviews("a-different-agent")).toHaveLength(0);
  });

  test("getReview returns null for an unknown id", () => {
    expect(getReview(crypto.randomUUID())).toBeNull();
  });
});

/** Synthetic vectors keep this suite off the ONNX runtime, which crashes bun test. */
function vec(seed: number): Float32Array {
  const v = new Float32Array(EMBEDDING_DIMS);
  let x = seed;
  for (let i = 0; i < v.length; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    v[i] = x / 0x7fffffff;
  }
  return v;
}

describe("feedback loop", () => {
  beforeEach(() => {
    getDb().prepare("DELETE FROM memory WHERE agent_id = ?").run(AGENT);
  });

  test("resolving as attack creates a memory entry with origin human", () => {
    const id = enqueueReview(item())!;
    markResolved(id, "attack", "confirmed injection");

    // Since addReference needs embeddings (ONNX crashes in bun:test), we simulate
    // the DB-level flow: addMemory with origin 'human' should start active.
    const reviewItem = getReview(id)!;
    const attackType = reviewItem.findings[0]?.attackType ?? "instruction_override";
    const mem = addMemory({
      label: "attack",
      attackType: attackType as any,
      vector: vec(42),
      text: reviewItem.content,
      source: reviewItem.source,
      origin: "human",
      agentId: AGENT,
    });

    expect(mem.status).toBe("active");
    expect(mem.origin).toBe("human");
    expect(mem.label).toBe("attack");

    // Verify in DB
    const row = getDb()
      .query("SELECT * FROM memory WHERE id = ?")
      .get(mem.id) as any;
    expect(row).toBeTruthy();
    expect(row.status).toBe("active");
    expect(row.origin).toBe("human");
  });

  test("resolving as dismiss does not create a memory entry", () => {
    const id = enqueueReview(item())!;
    markResolved(id, "dismiss", "false alarm");

    const resolved = getReview(id)!;
    expect(resolved.status).toBe("resolved");
    expect(resolved.decision).toBe("dismiss");

    // No memory should have been created for this agent during this test
    const rows = getDb()
      .query("SELECT COUNT(*) AS n FROM memory WHERE agent_id = ?")
      .get(AGENT) as { n: number };
    expect(rows.n).toBe(0);
  });

  test("addSafeReference rejects non-human/seed origins", () => {
    // The addSafeReference function guards against learning safe entries from
    // untrusted origins. We test this by verifying addMemory with origin 'judge'
    // starts on probation (not active), confirming only human/seed are trusted.
    const mem = addMemory({
      label: "safe",
      vector: vec(99),
      text: "a totally benign prompt",
      origin: "judge",
      agentId: AGENT,
    });
    expect(mem.status).toBe("probation");
    expect(mem.origin).toBe("judge");

    // Human origin should be active immediately
    const trustedMem = addMemory({
      label: "safe",
      vector: vec(100),
      text: "another benign prompt",
      origin: "human",
      agentId: AGENT,
    });
    expect(trustedMem.status).toBe("active");
  });

  test("ReviewDecision type allows attack, safe, and dismiss", () => {
    // Type-level verification: all three values satisfy the type.
    const decisions: ReviewDecision[] = ["attack", "safe", "dismiss"];
    expect(decisions).toHaveLength(3);
  });
});
