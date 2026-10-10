/**
 * API surface probe.
 *
 * Everything else measures detection quality. This measures whether the server
 * itself holds up when the input is hostile rather than merely suspicious — a
 * firewall that can be crashed, bypassed or used as someone else's billing account
 * is not providing the protection it claims, however good its classifier is.
 *
 * A crash, a hang, a stack trace in a response body, or a scan that silently
 * succeeds when it should have been rejected are all failures here.
 */
const BASE = process.env.WARDEN_URL ?? "http://localhost:3000";

interface Case { name: string; path: string; init: RequestInit; expect: (s: number, b: string) => boolean; note: string }

const json = (body: unknown): RequestInit => ({
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
});
const rejected = (s: number) => s >= 400 && s < 500;
const ok = (s: number) => s === 200;

const big = "A".repeat(2 * 1024 * 1024);          // 2MB, over the stated 1MB cap
const deep = (() => { let o: any = "x"; for (let i = 0; i < 2000; i++) o = { a: o }; return o; })();

const CASES: Case[] = [
  { name: "missing content", path: "/scan", init: json({ source: "email", agentId: "p" }),
    expect: rejected, note: "must be rejected, not scanned as undefined" },
  { name: "missing agentId", path: "/scan", init: json({ content: "hi", source: "email" }),
    expect: rejected, note: "agentId scopes memory and policy" },
  { name: "invalid source", path: "/scan", init: json({ content: "hi", source: "../../etc/passwd", agentId: "p" }),
    expect: rejected, note: "source selects an extractor" },
  { name: "content as object", path: "/scan", init: json({ content: { a: 1 }, source: "email", agentId: "p" }),
    expect: rejected, note: "type confusion" },
  { name: "content as array", path: "/scan", init: json({ content: [1, 2, 3], source: "email", agentId: "p" }),
    expect: rejected, note: "type confusion" },
  { name: "content null", path: "/scan", init: json({ content: null, source: "email", agentId: "p" }),
    expect: rejected, note: "type confusion" },
  { name: "oversized content", path: "/scan", init: json({ content: big, source: "email", agentId: "p" }),
    expect: rejected, note: "1MB cap is documented" },
  { name: "oversized base64", path: "/scan", init: json({ contentBase64: Buffer.from(big).toString("base64"), source: "pdf", agentId: "p" }),
    expect: rejected, note: "base64 path needs its own cap" },
  { name: "bad base64", path: "/scan", init: json({ contentBase64: "!!!not base64!!!", source: "pdf", agentId: "p" }),
    expect: (s) => s === 200 || rejected(s), note: "must not throw" },
  { name: "malformed json body", path: "/scan",
    init: { method: "POST", headers: { "Content-Type": "application/json" }, body: "{not json" },
    expect: rejected, note: "must be a clean 400" },
  { name: "deeply nested json", path: "/scan", init: json({ content: "hi", source: "email", agentId: "p", extra: deep }),
    expect: (s) => s === 200 || rejected(s), note: "must not blow the stack" },
  { name: "agentId path traversal", path: "/scan", init: json({ content: "hello there", source: "email", agentId: "../../../etc/passwd" }),
    expect: (s) => s === 200 || rejected(s), note: "agentId reaches the policy loader" },
  { name: "agentId sql-ish", path: "/scan", init: json({ content: "hello there", source: "email", agentId: "p'; DROP TABLE memory;--" }),
    expect: ok, note: "must be parameterised, not rejected or executed" },
  { name: "sessionId huge", path: "/scan", init: json({ content: "hello there", source: "email", agentId: "p", sessionId: "s".repeat(100000) }),
    expect: (s) => s === 200 || rejected(s), note: "session key is stored" },
  { name: "unknown review id", path: "/review/does-not-exist", init: json({ decision: "safe" }),
    expect: rejected, note: "must 404, not 500" },
  { name: "invalid decision", path: "/review/does-not-exist", init: json({ decision: "banana" }),
    expect: rejected, note: "decision is an enum" },
  { name: "scan-output no content", path: "/scan-output", init: json({ agentId: "p" }),
    expect: rejected, note: "" },
  { name: "check-tool no args", path: "/check-tool", init: json({ agentId: "p" }),
    expect: rejected, note: "" },
];

console.log("=".repeat(74));
console.log("API SURFACE PROBE");
console.log("=".repeat(74) + "\n");

let bad = 0;
for (const c of CASES) {
  let status = 0, body = "", err = "";
  const t0 = Date.now();
  try {
    const res = await fetch(BASE + c.path, { ...c.init, signal: AbortSignal.timeout(30000) });
    status = res.status;
    body = (await res.text()).slice(0, 400);
  } catch (e) { err = (e as Error).message; }
  const ms = Date.now() - t0;
  const leaked = /\bat \/|\.ts:\d+|stack|SQLITE_|Error: ENOENT/i.test(body);
  const pass = !err && c.expect(status, body) && !leaked;
  if (!pass) bad++;
  const detail = err ? `EXCEPTION ${err}` : `${status}${leaked ? " LEAKS-INTERNALS" : ""}`;
  console.log(`  ${pass ? "ok  " : "BUG "} ${c.name.padEnd(24)} ${detail.padEnd(22)} ${ms}ms`);
  if (!pass && body) console.log(`       body: ${body.slice(0, 150).replace(/\n/g, " ")}`);
  if (!pass && c.note) console.log(`       why it matters: ${c.note}`);
}

// Auth: with no WARDEN_API_KEYS set, writes are open by design. Record which routes
// mutate state so the deployment guidance can be checked against reality.
console.log("\n  auth posture (WARDEN_API_KEYS unset in this instance)");
for (const p of ["/scan", "/scan-output", "/check-tool", "/ingest"]) {
  const res = await fetch(BASE + p, json({ content: "hello there", source: "email", agentId: "p", toolName: "x", args: {} }))
    .catch(() => null);
  console.log(`    ${p.padEnd(14)} ${res ? res.status : "ERR"}  ${res && res.status === 200 ? "open" : "closed/rejected"}`);
}

console.log(`\n  => ${bad}/${CASES.length} failures\n`);
