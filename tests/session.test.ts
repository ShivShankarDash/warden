import { describe, expect, test, beforeEach } from "bun:test";
import { updateSession, getSession, resetSession } from "../src/detect/session.ts";

const THRESHOLD = 0.8;
const sid = (name: string) => `test-${name}-${Math.random().toString(36).slice(2)}`;

describe("session accumulation", () => {
  test("clean turns contribute nothing", () => {
    const id = sid("clean");
    for (let i = 0; i < 6; i++) updateSession(id, "a", 0, [], THRESHOLD);
    const s = getSession(id)!;
    expect(s.sessionRisk).toBe(0);
    expect(s.suspiciousTurns).toBe(0);
    expect(s.turnCount).toBe(6);
    resetSession(id);
  });

  test("turns below the suspicion floor do not accumulate", () => {
    const id = sid("floor");
    for (let i = 0; i < 5; i++) updateSession(id, "a", 0.2, [], THRESHOLD);
    expect(getSession(id)!.sessionRisk).toBe(0);
    resetSession(id);
  });

  // The tuning that matters: three sub-threshold probes escalate, two do not.
  // Matched to the 0.30/0.35/0.45 confidences the multi-step rules emit.
  test("two sub-threshold probes do not escalate", () => {
    const id = sid("two");
    expect(updateSession(id, "a", 0.3, [], THRESHOLD).escalate).toBe(false);
    expect(updateSession(id, "a", 0.35, [], THRESHOLD).escalate).toBe(false);
    resetSession(id);
  });

  test("three consecutive probes escalate", () => {
    const id = sid("three");
    updateSession(id, "a", 0.3, [], THRESHOLD);
    updateSession(id, "a", 0.35, [], THRESHOLD);
    const third = updateSession(id, "a", 0.45, [], THRESHOLD);
    expect(third.escalate).toBe(true);
    expect(third.sessionRisk).toBeGreaterThanOrEqual(THRESHOLD);
    resetSession(id);
  });

  test("a clean turn resets the consecutive counter", () => {
    const id = sid("reset");
    updateSession(id, "a", 0.3, [], THRESHOLD);
    updateSession(id, "a", 0.3, [], THRESHOLD);
    updateSession(id, "a", 0, [], THRESHOLD);
    expect(getSession(id)!.consecutiveSuspicious).toBe(0);
    resetSession(id);
  });

  test("sessions are isolated from one another", () => {
    const a = sid("iso-a");
    const b = sid("iso-b");
    for (let i = 0; i < 4; i++) updateSession(a, "x", 0.5, [], THRESHOLD);
    updateSession(b, "x", 0, [], THRESHOLD);
    expect(getSession(a)!.sessionRisk).toBeGreaterThan(0);
    expect(getSession(b)!.sessionRisk).toBe(0);
    resetSession(a);
    resetSession(b);
  });

  test("resetSession clears state", () => {
    const id = sid("clear");
    updateSession(id, "a", 0.9, [], THRESHOLD);
    resetSession(id);
    expect(getSession(id)).toBeNull();
  });
});
