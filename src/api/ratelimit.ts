/**
 * In-memory token-bucket rate limiter, keyed by client IP.
 *
 * Config via env:
 *   WARDEN_RATE_LIMIT — tokens per second (default 20)
 *   WARDEN_RATE_BURST  — max tokens / bucket capacity (default 50)
 *
 * Returns null when the request is allowed, or a 429 Response when limited.
 */

interface Bucket {
  tokens: number;
  lastRefill: number;
}

const buckets = new Map<string, Bucket>();

function config() {
  const rate = Number(process.env.WARDEN_RATE_LIMIT) || 20;
  const burst = Number(process.env.WARDEN_RATE_BURST) || 50;
  return { rate, burst };
}

function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const first = xff.split(",")[0].trim();
    if (first) return first;
  }
  return "127.0.0.1";
}

export function checkRateLimit(req: Request): Response | null {
  const { rate, burst } = config();
  const ip = clientIp(req);
  const now = Date.now();

  let bucket = buckets.get(ip);
  if (!bucket) {
    bucket = { tokens: burst, lastRefill: now };
    buckets.set(ip, bucket);
  }

  // Refill tokens based on elapsed time
  const elapsed = (now - bucket.lastRefill) / 1000; // seconds
  bucket.tokens = Math.min(burst, bucket.tokens + elapsed * rate);
  bucket.lastRefill = now;

  if (bucket.tokens < 1) {
    return new Response(
      JSON.stringify({ error: "rate limit exceeded" }),
      { status: 429, headers: { "Content-Type": "application/json", "Retry-After": "1" } },
    );
  }

  bucket.tokens -= 1;
  return null;
}

// Cleanup stale buckets every 5 minutes
const CLEANUP_INTERVAL = 5 * 60 * 1000;
const STALE_THRESHOLD = 10 * 60 * 1000;

const cleanupTimer = setInterval(() => {
  const cutoff = Date.now() - STALE_THRESHOLD;
  for (const [ip, bucket] of buckets) {
    if (bucket.lastRefill < cutoff) buckets.delete(ip);
  }
}, CLEANUP_INTERVAL);

// Don't keep the process alive for cleanup
if (typeof cleanupTimer === "object" && "unref" in cleanupTimer) {
  cleanupTimer.unref();
} else if (typeof cleanupTimer === "number") {
  // Bun returns a number; use Bun's unref if available
  try { (globalThis as any).Bun?.sleepSync?.(0); } catch { /* no-op */ }
}
