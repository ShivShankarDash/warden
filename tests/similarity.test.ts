import { describe, expect, test } from "bun:test";
import { cosine, toBlob, fromBlob, EMBEDDING_DIMS } from "../src/detect/embeddings.ts";

/**
 * Pure vector maths only. Loading the ONNX runtime inside `bun test` crashes Bun
 * (a C++ exception in the runner, not in this code — the same calls work under
 * `bun -e`), so the model-dependent path is verified by `bun run eval:similarity`
 * instead. Nothing here calls initEmbeddings().
 */

function unit(seed: number): Float32Array {
  const v = new Float32Array(EMBEDDING_DIMS);
  let x = seed;
  for (let i = 0; i < v.length; i++) {
    x = (x * 1664525 + 1013904223) % 4294967296;
    v[i] = x / 4294967296 - 0.5;
  }
  const norm = Math.hypot(...v);
  for (let i = 0; i < v.length; i++) v[i] /= norm;
  return v;
}

describe("embedding maths", () => {
  test("cosine of a unit vector with itself is 1", () => {
    const v = unit(42);
    expect(cosine(v, v)).toBeCloseTo(1, 5);
  });

  test("independent vectors score near zero", () => {
    expect(Math.abs(cosine(unit(1), unit(99)))).toBeLessThan(0.2);
  });

  test("cosine is symmetric", () => {
    const a = unit(7);
    const b = unit(8);
    expect(cosine(a, b)).toBeCloseTo(cosine(b, a), 6);
  });

  test("a nudged vector stays close to the original", () => {
    const a = unit(5);
    const b = Float32Array.from(a);
    for (let i = 0; i < 20; i++) b[i] += 0.01;
    expect(cosine(a, b)).toBeGreaterThan(0.9);
  });
});

describe("embedding serialisation", () => {
  test("survives a round trip through the BLOB column", () => {
    const v = unit(123);
    const back = fromBlob(toBlob(v));
    expect(back.length).toBe(v.length);
    expect(cosine(v, back)).toBeCloseTo(1, 6);
  });

  test("round trips correctly from an unaligned buffer", () => {
    // SQLite rows are not guaranteed 4-byte aligned, which is why fromBlob copies.
    const v = unit(77);
    const blob = toBlob(v);
    const padded = new Uint8Array(blob.length + 1);
    padded.set(blob, 1);
    const back = fromBlob(padded.subarray(1));
    expect(cosine(v, back)).toBeCloseTo(1, 6);
  });
});

describe("memory cache is per-agent", () => {
  /**
   * Regression. The cache was a single shared array that ignored agentId, and since
   * `cache = []` is truthy, an agent with nothing learned cached emptiness for the
   * whole process. One scan for an agent with no memories — the default agent on a
   * fresh install — left every later lookup, for every agent, matching an empty pool.
   * Attack recall and safe-memory relief both returned 0 silently: no error, and no
   * trace entry to show stage 5 had been neutered.
   */
  test("an agent with no memories does not blank out other agents", async () => {
    const { invalidateReferenceCache, referenceCount } = await import("../src/detect/similarity.ts");
    const { addMemory, confirmMemory } = await import("../src/store/memory.ts");

    invalidateReferenceCache();

    const vector = new Float32Array(384).fill(0.1);
    const m = addMemory({
      label: "attack", vector, text: "cache scoping probe — a stored attack example",
      source: "email", sourceId: null, origin: "human", agentId: "agent-with-memory",
    });
    confirmMemory(m.id);           // probation -> active
    invalidateReferenceCache();

    // The empty agent asks first; this is what used to poison the cache.
    expect(referenceCount("agent-with-nothing")).toBe(0);

    // The populated agent must still see its own memory.
    expect(referenceCount("agent-with-memory")).toBeGreaterThan(0);
  });
});
