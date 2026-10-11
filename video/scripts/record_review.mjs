// Records a scripted tour of the live Warden dashboard as a crisp 1920x1080 MP4.
// Uses the CDP screencast (JPEG q=92) rather than Playwright's low-bitrate recordVideo,
// then rebuilds a constant-30fps video from timestamped frames with ffmpeg.
//
// Usage: node scripts/record_dashboard.mjs <baseUrl> <out.mp4>
import { chromium } from "playwright";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";

const [base = "http://localhost:3777", out = "build/footage/review.mp4"] = process.argv.slice(2);
const frameDir = join("build", "footage", "review_frames");
rmSync(frameDir, { recursive: true, force: true });
mkdirSync(frameDir, { recursive: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
const page = await ctx.newPage();

// Visible cursor + click ripple, so viewers can follow the tour.
await page.addInitScript(() => {
  addEventListener("DOMContentLoaded", () => {
    const c = document.createElement("div");
    c.id = "__cursor";
    c.style.cssText = "position:fixed;z-index:99999;left:0;top:0;width:22px;height:22px;pointer-events:none;transform:translate(960px,540px);transition:none";
    c.innerHTML = `<svg width="22" height="22" viewBox="0 0 24 24"><path d="M3 2l7.5 19 2.6-7.9L21 10.5z" fill="#111" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>`;
    document.body.appendChild(c);
    addEventListener("mousemove", (e) => { c.style.transform = `translate(${e.clientX - 3}px,${e.clientY - 2}px)`; });
    addEventListener("mousedown", (e) => {
      const r = document.createElement("div");
      r.style.cssText = `position:fixed;z-index:99998;left:${e.clientX - 18}px;top:${e.clientY - 18}px;width:36px;height:36px;border-radius:50%;border:2px solid #2a78d6;pointer-events:none;opacity:.9;transition:transform .45s ease-out,opacity .45s ease-out`;
      document.body.appendChild(r);
      requestAnimationFrame(() => { r.style.transform = "scale(1.8)"; r.style.opacity = "0"; });
      setTimeout(() => r.remove(), 600);
    });
  });
});

const cdp = await ctx.newCDPSession(page);
const frames = [];
cdp.on("Page.screencastFrame", async ({ data, metadata, sessionId }) => {
  const f = join(frameDir, `f${String(frames.length).padStart(5, "0")}.jpg`);
  writeFileSync(f, Buffer.from(data, "base64"));
  frames.push({ f, t: metadata.timestamp });
  await cdp.send("Page.screencastFrameAck", { sessionId }).catch(() => {});
});

let mouse = { x: 960, y: 540 };
const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
async function glide(x, y, ms = 700) {
  const steps = Math.max(8, Math.round(ms / 16));
  const from = { ...mouse };
  for (let i = 1; i <= steps; i++) {
    const k = ease(i / steps);
    await page.mouse.move(from.x + (x - from.x) * k, from.y + (y - from.y) * k);
    await page.waitForTimeout(ms / steps);
  }
  mouse = { x, y };
}
async function glideTo(sel, ms = 700, dx = 0.5, dy = 0.5) {
  const b = await page.locator(sel).first().boundingBox();
  if (!b) return;
  await glide(b.x + b.width * dx, b.y + b.height * dy, ms);
}
async function scrollTo(y, ms = 1400) {
  await page.evaluate(async ([y, ms]) => {
    const y0 = scrollY, t0 = performance.now();
    const e = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
    await new Promise((res) => {
      const step = (now) => {
        const k = Math.min(1, (now - t0) / ms);
        scrollTo(0, y0 + (y - y0) * e(k));
        k < 1 ? requestAnimationFrame(step) : res();
      };
      requestAnimationFrame(step);
    });
  }, [y, ms]);
}
const topOf = (sel) => page.locator(sel).first().evaluate((el) => el.getBoundingClientRect().top + scrollY);
const scan = (content, source) =>
  fetch(`${base}/scan`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content, source, agentId: "demo-tour" }) });

await page.goto(base, { waitUntil: "networkidle" });
await page.waitForTimeout(1500);
await page.evaluate(() => { scrollTo(0, 0); const d = document.getElementById("review-card"); if (d) d.open = false; });
await cdp.send("Page.startScreencast", { format: "jpeg", quality: 92, maxWidth: 1920, maxHeight: 1080, everyNthFrame: 1 });
const t0 = Date.now();
const mark = (label) => console.log(`${label}\t${((Date.now() - t0) / 1000).toFixed(2)}`);
mark("top");
await page.waitForTimeout(800);
await glideTo("#queue-link", 900);
await page.waitForTimeout(500);
await page.evaluate(() => { const d = document.getElementById("review-card"); if (d) d.open = true; });
await page.waitForTimeout(900);
mark("open");
await scrollTo((await topOf("#review-card")) - 120, 1200);
await page.waitForTimeout(1200);
await glideTo("#review-body", 1000, 0.35, 0.18);
await page.waitForTimeout(1400);
const btns = page.locator("#review-body button");
const n = await btns.count();
let safe = null;
for (let i = 0; i < n; i++) { const t = (await btns.nth(i).innerText()).trim(); if (/mark safe/i.test(t)) { safe = btns.nth(i); break; } }
if (safe) {
  const b = await safe.boundingBox();
  await glide(b.x + b.width / 2, b.y + b.height / 2, 800);
  await page.waitForTimeout(500);
  mark("click");
  await page.mouse.down(); await page.mouse.up();
}
await page.waitForTimeout(2500);
mark("end");
await cdp.send("Page.stopScreencast");
await page.waitForTimeout(300);
await browser.close();

// Constant-fps rebuild: each frame lasts until the next one arrives.
const list = frames.map((fr, i) => {
  const next = frames[i + 1]?.t ?? fr.t + 0.5;
  return `file '${fr.f.split("/").pop()}'\nduration ${(next - fr.t).toFixed(4)}`;
}).join("\n") + `\nfile '${frames.at(-1).f.split("/").pop()}'\n`;
writeFileSync(join(frameDir, "list.txt"), list);
mkdirSync("build/footage", { recursive: true });
execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", join(frameDir, "list.txt"),
  "-vf", "fps=30,format=yuv420p", "-c:v", "libx264", "-crf", "16", "-preset", "slow", out], { stdio: "inherit" });
console.log(`frames=${frames.length} -> ${out}`);
