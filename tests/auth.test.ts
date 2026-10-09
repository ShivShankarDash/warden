import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { requireAuth } from "../src/api/auth.ts";
import { checkRateLimit } from "../src/api/ratelimit.ts";

function makeReq(headers?: Record<string, string>): Request {
  return new Request("http://localhost/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("requireAuth", () => {
  let savedKeys: string | undefined;

  beforeEach(() => {
    savedKeys = process.env.WARDEN_API_KEYS;
  });
  afterEach(() => {
    if (savedKeys === undefined) delete process.env.WARDEN_API_KEYS;
    else process.env.WARDEN_API_KEYS = savedKeys;
  });

  test("auth disabled when WARDEN_API_KEYS is unset", () => {
    delete process.env.WARDEN_API_KEYS;
    expect(requireAuth(makeReq())).toBeNull();
  });

  test("auth disabled when WARDEN_API_KEYS is empty string", () => {
    process.env.WARDEN_API_KEYS = "";
    expect(requireAuth(makeReq())).toBeNull();
  });

  test("valid key passes (first key)", () => {
    process.env.WARDEN_API_KEYS = "key1,key2";
    expect(requireAuth(makeReq({ "X-API-Key": "key1" }))).toBeNull();
  });

  test("valid key passes (second key)", () => {
    process.env.WARDEN_API_KEYS = "key1,key2";
    expect(requireAuth(makeReq({ "X-API-Key": "key2" }))).toBeNull();
  });

  test("invalid key returns 401 unauthorized", async () => {
    process.env.WARDEN_API_KEYS = "key1";
    const res = requireAuth(makeReq({ "X-API-Key": "wrong" }));
    expect(res).not.toBeNull();
    expect(res!.status).toBe(401);
    const body = await res!.json();
    expect(body.error).toBe("unauthorized");
  });

  test("missing key returns 401 with hint", async () => {
    process.env.WARDEN_API_KEYS = "key1";
    const res = requireAuth(makeReq());
    expect(res).not.toBeNull();
    expect(res!.status).toBe(401);
    const body = await res!.json();
    expect(body.error).toBe("API key required");
    expect(body.hint).toBeTruthy();
  });
});

describe("checkRateLimit", () => {
  let savedRate: string | undefined;
  let savedBurst: string | undefined;

  beforeEach(() => {
    savedRate = process.env.WARDEN_RATE_LIMIT;
    savedBurst = process.env.WARDEN_RATE_BURST;
  });
  afterEach(() => {
    if (savedRate === undefined) delete process.env.WARDEN_RATE_LIMIT;
    else process.env.WARDEN_RATE_LIMIT = savedRate;
    if (savedBurst === undefined) delete process.env.WARDEN_RATE_BURST;
    else process.env.WARDEN_RATE_BURST = savedBurst;
  });

  test("first request is allowed", () => {
    const ip = `test-${crypto.randomUUID()}`;
    const req = new Request("http://localhost/scan", {
      method: "POST",
      headers: { "x-forwarded-for": ip },
    });
    expect(checkRateLimit(req)).toBeNull();
  });

  test("exceeding burst returns 429", async () => {
    process.env.WARDEN_RATE_LIMIT = "1000"; // high refill so timing doesn't matter
    process.env.WARDEN_RATE_BURST = "3";     // tiny burst

    const ip = `burst-test-${crypto.randomUUID()}`;

    let lastResult: Response | null = null;
    for (let i = 0; i < 10; i++) {
      const req = new Request("http://localhost/scan", {
        method: "POST",
        headers: { "x-forwarded-for": ip },
      });
      lastResult = checkRateLimit(req);
      if (lastResult) break;
    }

    expect(lastResult).not.toBeNull();
    expect(lastResult!.status).toBe(429);
    const body = await lastResult!.json();
    expect(body.error).toBe("rate limit exceeded");
  });
});
