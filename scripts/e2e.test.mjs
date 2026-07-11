// Browser-level regression suite for the Jevil demo.
//
//   npm run test:e2e                 # against the dev server (localhost:5173)
//   BASE_URL=… npm run test:e2e      # against any base URL (CI uses preview)
//
// Covers the load-bearing states: honest recovery, the grind, duplicate-point
// handling, the malicious escape, the tower field, K=16 security grade, the
// export/verify round-trip, theme persistence, accessibility (axe-core, WCAG
// 2.1 AA), and mobile layout. The crypto correctness itself lives in
// `npm test` (scripts/core.test.ts); this guards the wiring and the UI.
import { chromium, devices } from "playwright";
import { AxeBuilder } from "@axe-core/playwright";

const URL = process.env.BASE_URL || "http://localhost:5173/crypto-lab-jevil/";
let fails = 0;
const check = (n, c, x = "") => {
  console.log(`${c ? "  ok  " : " FAIL "} ${n}${x ? " — " + x : ""}`);
  if (!c) fails++;
};
async function scan(page, label) {
  const r = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"])
    .analyze();
  check(`axe: ${label} — ${r.violations.length} violation(s)`, r.violations.length === 0);
  r.violations.forEach((v) => console.log(`     • ${v.id}: ${v.help}`));
}
async function gen(p, { nStar, K, field = "base", signer = "honest" }) {
  await p.selectOption("#sel-nstar", String(nStar));
  await p.selectOption("#sel-k", String(K));
  await p.selectOption("#sel-field", field);
  await p.selectOption("#sel-signer", signer);
  await p.click("#btn-gen");
  await p.waitForTimeout(120);
}
async function grindToCliff(p, max = 24) {
  for (let i = 0; i < max; i++) {
    if (await p.isDisabled("#btn-grind")) break;
    await p.click("#btn-grind");
    await p.waitForTimeout(110);
  }
}

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1000, height: 1500 } });
const page = await ctx.newPage();
const errs = [];
page.on("console", (m) => m.type() === "error" && errs.push(m.text()));
page.on("pageerror", (e) => errs.push(String(e)));
await page.goto(URL, { waitUntil: "networkidle" });

// --- boot + a11y baseline ---
check("auto-generates a key on load", !(await page.locator("#key-out").getAttribute("class")).includes("hidden"));
await scan(page, "fresh/dark");

// --- honest recovery (base) ---
await gen(page, { nStar: 1, K: 2 });
check("below cliff: secret undetermined", /undetermined/i.test(await page.textContent("#cliff-status")));
check("recovery panel hidden below cliff", await page.isHidden("#panel-recover"));
await grindToCliff(page);
check("honest: EXACT MATCH", /EXACT MATCH/.test(await page.textContent(".verdict")));
check("honest: all coeff rows match", (await page.locator(".coeff-table tr.mismatch").count()) === 0);
check("honest: grind disabled at cliff", await page.isDisabled("#btn-grind"));
await scan(page, "honest/cliff");

// --- export + verify round-trip (honest → verified) ---
await page.click("#btn-export");
await page.waitForTimeout(150);
check("export verifies in-browser", /Verified/i.test(await page.textContent("#export-result")));

// --- duplicate-point handling (honest sign same message twice) ---
await gen(page, { nStar: 3, K: 3 });
await page.fill("#msg", "same-message");
await page.click("#btn-sign"); await page.waitForTimeout(120);
const after1 = await page.textContent("#meter-count");
await page.click("#btn-sign"); await page.waitForTimeout(120);
const after2 = await page.textContent("#meter-count");
check("duplicate positions do not advance the cliff", after1 === after2, `${after1} -> ${after2}`);
const dupCount = await page.locator(".led-pt.dup").count();
check("duplicate points are marked", dupCount >= 1, `dup spans=${dupCount}`);

// --- malicious escape ---
await gen(page, { nStar: 2, K: 3, signer: "malicious" });
await grindToCliff(page);
check("malicious: SIGNER ESCAPED", /SIGNER ESCAPED/.test(await page.textContent(".verdict")));
check("malicious: panel title adapts", /escaped/i.test(await page.textContent("#panel-recover h2")));
check("malicious: no coeff table", (await page.locator(".coeff-table").count()) === 0);
await page.click("#btn-export"); await page.waitForTimeout(150);
check("malicious export does NOT verify", /Not verified/i.test(await page.textContent("#export-result")));
await scan(page, "malicious/cliff");

// --- tower field ---
await gen(page, { nStar: 2, K: 3, field: "tower" });
check("tower: OOD shown as tuple", /⟨/.test(await page.textContent(".ood-pt")));
await grindToCliff(page);
check("tower: EXACT MATCH", /EXACT MATCH/.test(await page.textContent(".verdict")));
await scan(page, "tower/cliff");

// --- K=16 security grade ---
await gen(page, { nStar: 1, K: 16 });
check("K=16: D=31", (await page.textContent(".kv:nth-child(4) code")).includes("31"));
await grindToCliff(page, 6);
check("K=16: EXACT MATCH", /EXACT MATCH/.test(await page.textContent(".verdict")));
check("K=16: table capped ≤24 rows", (await page.locator(".coeff-table tbody tr:not(.more-row)").count()) <= 24);
check("K=16: plot omits high-degree curves", /curves omitted/.test(await page.textContent("#plot")));

// --- theme toggle persistence ---
const t0 = await page.getAttribute("html", "data-theme");
await page.click("#cl-theme-toggle");
const t1 = await page.getAttribute("html", "data-theme");
check("theme toggles", t0 !== t1);
await page.reload({ waitUntil: "networkidle" });
check("theme persists across reload", (await page.getAttribute("html", "data-theme")) === t1);

check("no console/page errors", errs.length === 0, errs.join("; "));
await ctx.close();

// --- mobile ---
const mctx = await browser.newContext({ ...devices["iPhone 12"] });
const mp = await mctx.newPage();
await mp.goto(URL, { waitUntil: "networkidle" });
const ov = await mp.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
check("no horizontal scroll on mobile", ov.sw <= ov.cw + 1, `sw=${ov.sw} cw=${ov.cw}`);
await scan(mp, "mobile/fresh");
await mctx.close();

await browser.close();
console.log(fails === 0 ? "\nE2E ALL PASS" : `\n${fails} FAILURE(S)`);
process.exit(fails === 0 ? 0 : 1);
