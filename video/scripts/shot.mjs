// Full-page screenshot of a URL. Usage: node scripts/shot.mjs <url> <out.png> [dark]
import { chromium } from "playwright";
const [url, out, theme] = process.argv.slice(2);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, colorScheme: theme === "dark" ? "dark" : "light" });
await page.goto(url, { waitUntil: "networkidle" });
await page.waitForTimeout(2500);
await page.screenshot({ path: out, fullPage: true });
await browser.close();
