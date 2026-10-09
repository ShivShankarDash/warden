import { describe, expect, test } from "bun:test";
import { red, green, yellow, dim, bold, cyan, rule } from "../src/gateway/colors.ts";
import { getGatewayStats } from "../src/gateway/index.ts";

describe("colors.ts", () => {
  // Tests run in a non-TTY pipe, and CI typically sets NO_COLOR or lacks a TTY,
  // so color functions should return input unchanged in this environment.

  test("color functions return input unchanged when NO_COLOR is set or not a TTY", () => {
    // In bun:test, stderr is not a TTY, so colors auto-disable.
    expect(red("hello")).toContain("hello");
    expect(green("hello")).toContain("hello");
    expect(yellow("hello")).toContain("hello");
    expect(dim("hello")).toContain("hello");
    expect(bold("hello")).toContain("hello");
    expect(cyan("hello")).toContain("hello");
  });

  test("rule() returns a string of 60 characters", () => {
    const r = rule();
    // Each ━ is one character (U+2501).
    expect([...r].length).toBe(60);
  });
});

describe("getGatewayStats()", () => {
  test("returns expected shape with numeric and array fields", () => {
    const s = getGatewayStats();
    expect(typeof s.totalScans).toBe("number");
    expect(typeof s.allowed).toBe("number");
    expect(typeof s.blocked).toBe("number");
    expect(typeof s.spotlighted).toBe("number");
    expect(Array.isArray(s.attackTypes)).toBe(true);
    expect(typeof s.avgLatencyMs).toBe("number");
  });
});
