/**
 * API key authentication for write routes.
 *
 * When WARDEN_API_KEYS is unset or empty, auth is disabled (local dev).
 * When set (comma-separated list), requests must send a valid key in
 * the X-API-Key header. Comparison uses crypto.timingSafeEqual.
 */

import { timingSafeEqual } from "node:crypto";

export function requireAuth(req: Request): Response | null {
  const raw = process.env.WARDEN_API_KEYS;
  if (!raw) return null; // auth disabled — local dev

  const keys = raw.split(",").map((k) => k.trim()).filter(Boolean);
  if (keys.length === 0) return null; // all entries were empty

  const supplied = req.headers.get("X-API-Key");
  if (!supplied) {
    return new Response(
      JSON.stringify({ error: "API key required", hint: "Set X-API-Key header" }),
      { status: 401, headers: { "Content-Type": "application/json" } },
    );
  }

  const suppliedBuf = Buffer.from(supplied);

  for (const key of keys) {
    const keyBuf = Buffer.from(key);
    if (keyBuf.byteLength === suppliedBuf.byteLength) {
      if (timingSafeEqual(keyBuf, suppliedBuf)) {
        return null; // match — allowed
      }
    }
    // Length mismatch: not a match, check next key. We still iterate all keys
    // to avoid leaking which index matched via timing.
  }

  return new Response(
    JSON.stringify({ error: "unauthorized" }),
    { status: 401, headers: { "Content-Type": "application/json" } },
  );
}
