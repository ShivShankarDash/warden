/**
 * API key authentication for write routes.
 *
 * When WARDEN_API_KEYS is unset or empty, auth is disabled (local dev).
 * When set (comma-separated list), requests must send a valid key in
 * the X-API-Key header. Comparison uses crypto.timingSafeEqual.
 */

import { timingSafeEqual, createHmac } from "node:crypto";

/** HMAC-hash a value so all comparisons use fixed-length buffers,
 *  eliminating the timing side-channel from key-length differences. */
function hmacKey(value: string): Buffer {
  return createHmac("sha256", "warden-auth").update(value).digest();
}

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

  const suppliedHash = hmacKey(supplied);

  for (const key of keys) {
    const keyHash = hmacKey(key);
    // Both hashes are always 32 bytes — no length leak.
    if (timingSafeEqual(keyHash, suppliedHash)) {
      return null; // match — allowed
    }
  }

  return new Response(
    JSON.stringify({ error: "unauthorized" }),
    { status: 401, headers: { "Content-Type": "application/json" } },
  );
}
