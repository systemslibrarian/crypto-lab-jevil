// Focused Part A verification: anti-flash default, toggle flip, persistence,
// emoji + aria-label sync. Against dev server at localhost:5173.
import { chromium } from "playwright";
const URL = "http://localhost:5173/";
let fails = 0;
const check = (n, c) => { console.log(`${c ? "  ok  " : " FAIL "} ${n}`); if (!c) fails++; };

const browser = await chromium.launch();
const ctx = await browser.newContext();
const page = await ctx.newPage();
const errors = [];
page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
page.on("pageerror", (e) => errors.push(String(e)));

// 1. First load, empty localStorage → dark.
await page.goto(URL, { waitUntil: "networkidle" });
check("default theme dark on empty localStorage", (await page.getAttribute("html", "data-theme")) === "dark");
check("button shows moon when dark", (await page.textContent("#theme-toggle")).trim() === "🌙");
check("aria-label = Switch to light mode when dark", (await page.getAttribute("#theme-toggle", "aria-label")) === "Switch to light mode");

// 2. Button is top-right inside header.
const box = await page.locator("#theme-toggle").boundingBox();
const hdr = await page.locator("header.hero").boundingBox();
check("toggle near header top-right", box.y < hdr.y + 80 && box.x > hdr.x + hdr.width - 120);

// 3. Click → light, persists to localStorage, emoji + label update.
await page.click("#theme-toggle");
check("theme flips to light", (await page.getAttribute("html", "data-theme")) === "light");
check("button shows sun when light", (await page.textContent("#theme-toggle")).trim() === "☀️");
check("aria-label = Switch to dark mode when light", (await page.getAttribute("#theme-toggle", "aria-label")) === "Switch to dark mode");
check("localStorage theme=light", (await page.evaluate(() => localStorage.getItem("theme"))) === "light");

// 4. Hard refresh → still light, no flash (data-theme set before paint).
await page.reload({ waitUntil: "commit" });
const earlyTheme = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
check("no flash: data-theme=light immediately after reload", earlyTheme === "light");
await page.waitForLoadState("networkidle");
check("persists light across refresh", (await page.getAttribute("html", "data-theme")) === "light");
check("button resynced to sun after refresh", (await page.textContent("#theme-toggle")).trim() === "☀️");

check("no console/page errors", errors.length === 0);
if (errors.length) console.log("  errors:", errors);

await browser.close();
console.log(fails === 0 ? "\nPART A PASS" : `\n${fails} FAILURE(S)`);
process.exit(fails === 0 ? 0 : 1);
