// Headless Motion Canvas render: start vite, open the editor with ?render, wait for the ffmpeg exporter.
// Usage (from video/): node tools/render_mc.mjs [out=build/scenes/impact.mp4]
import { spawn } from "node:child_process";
import { existsSync, statSync, copyFileSync, mkdirSync, rmSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { chromium } from "playwright";

const out = resolve(process.argv[2] ?? "build/scenes/impact.mp4");
const mc = resolve("motion/mc");
const outDir = join(mc, "output");
rmSync(outDir, { recursive: true, force: true });

const vite = spawn(join(mc, "node_modules/.bin/vite"), ["--port", "9001", "--strictPort"], { cwd: mc, stdio: ["ignore", "pipe", "pipe"] });
let ready = false;
vite.stdout.on("data", (d) => { if (/Local:|ready in/i.test(String(d))) ready = true; });
vite.stderr.on("data", (d) => process.stderr.write(String(d)));
for (let i = 0; i < 120 && !ready; i++) await new Promise((r) => setTimeout(r, 250));

const browser = await chromium.launch({ args: ["--autoplay-policy=no-user-gesture-required"] });
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
page.on("console", (m) => { const t = m.text(); if (/error|render/i.test(t)) console.log("[mc]", t.slice(0, 200)); });
page.on("pageerror", (e) => console.log("[mc pageerror]", e.message));
await page.goto("http://localhost:9001/?render", { waitUntil: "load" });

const t0 = Date.now();
let last = -1, stable = 0, file = null;
while (Date.now() - t0 < 10 * 60 * 1000) {
  await page.waitForTimeout(1500);
  if (!existsSync(outDir)) continue;
  const mp4 = readdirSync(outDir).filter((f) => f.endsWith(".mp4"));
  if (!mp4.length) continue;
  file = join(outDir, mp4[0]);
  const sz = statSync(file).size;
  stable = sz === last && sz > 0 ? stable + 1 : 0;
  last = sz;
  if (stable >= 4) break;
}
await browser.close();
vite.kill("SIGTERM");
if (!file) { console.error("no output produced"); process.exit(1); }
mkdirSync(resolve(out, ".."), { recursive: true });
copyFileSync(file, out);
console.log(`-> ${out} (${(statSync(out).size / 1e6).toFixed(1)} MB, ${((Date.now() - t0) / 1000).toFixed(0)}s)`);
