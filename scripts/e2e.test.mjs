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
//
// Beyond "the right words appeared", the accounting sections below assert the
// numbers the page COMPUTES against each other — the parameter identities
// (M=(n*+1)K, D=M-1, T=2M, cliff=n*+1), the meter against the ledger against
// the plot against the sign-hint arithmetic, the verdict's coefficient count
// against M, and the exported transcript against the on-screen ledger — plus
// every failure path the page offers (below-cliff export, malicious escape,
// tampered transcript) and the README-promised offline `npm run verify` CLI.
import { chromium, devices } from "playwright";
import { AxeBuilder } from "@axe-core/playwright";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TSX = join(REPO, "node_modules", ".bin", "tsx");
const WORK = mkdtempSync(join(tmpdir(), "jevil-e2e-"));

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
  let clicks = 0;
  for (let i = 0; i < max; i++) {
    if (await p.isDisabled("#btn-grind")) break;
    await p.click("#btn-grind");
    clicks++;
    await p.waitForTimeout(110);
  }
  return clicks;
}

// ---------------------------------------------------------- page state ----
// One snapshot of every number the page currently claims, parsed out of the
// live DOM. Nothing here is hardcoded: each value is what the page computed,
// so the assertions below can cross-check the page against itself.
async function st(p) {
  return p.evaluate(() => {
    const t = (s) => document.querySelector(s)?.textContent?.replace(/\s+/g, " ").trim() ?? "";
    const n = (re, s, i = 1) => {
      const m = re.exec(s);
      return m ? Number(m[i]) : NaN;
    };
    // Key params, read by label prefix so a wording tweak doesn't silently
    // turn a real comparison into NaN-vs-NaN.
    const kv = {};
    for (const e of document.querySelectorAll("#key-out .kv")) {
      const label = e.querySelector("span").textContent.trim();
      const value = e.querySelector("code").textContent.trim();
      if (label.startsWith("budget")) kv.nStar = Number(value);
      else if (label.startsWith("positions")) kv.K = Number(value);
      else if (label.startsWith("coefficients")) kv.M = Number(value);
      else if (label.startsWith("degree")) kv.D = Number(value);
      else if (label.startsWith("domain")) kv.T = Number(value);
      else if (label.startsWith("cliff fires")) kv.nCliff = Number(/(\d+)\s*$/.exec(value)?.[1]);
    }

    const meterEl = document.querySelector("#meter");
    const meterTxt = t("#meter-count");
    const mm = /(\d+)\s*\/\s*(\d+)/.exec(meterTxt) ?? [];

    const cliffTxt = t("#cliff-status");
    const hintTxt = t("#sign-hint");
    const verdictTxt = t(".verdict");
    const exportTxt = t("#export-result");
    const escapeTxt = [...document.querySelectorAll(".escape-note")]
      .map((e) => e.textContent.replace(/\s+/g, " "))
      .join(" ");
    const secretTxt = t(".secret-line");

    const ledTags = [...document.querySelectorAll(".led-tag")].map((e) =>
      e.textContent.replace(/\s+/g, " ").trim(),
    );
    const sigTags = ledTags.filter((s) => /signature #\d+/.test(s));

    return {
      ...kv,
      // meter
      meterTxt,
      distinct: Number(mm[1]),
      needed: Number(mm[2]),
      ariaMax: Number(meterEl?.getAttribute("aria-valuemax")),
      ariaNow: Number(meterEl?.getAttribute("aria-valuenow")),
      ariaText: meterEl?.getAttribute("aria-valuetext") ?? "",
      fillPct: parseFloat(document.querySelector("#meter-fill")?.style.width ?? "NaN"),
      fillClass: document.querySelector("#meter-fill")?.className ?? "",
      // cliff callout
      cliffTxt,
      cliffSafeHave: n(/(\d+) of (\d+) points/, cliffTxt, 1),
      cliffSafeNeed: n(/(\d+) of (\d+) points/, cliffTxt, 2),
      cliffSafeShort: n(/(\d+) short/, cliffTxt),
      cliffHitHave: n(/(\d+) distinct points\D+D\+1 = (\d+)/, cliffTxt, 1),
      cliffHitNeed: n(/(\d+) distinct points\D+D\+1 = (\d+)/, cliffTxt, 2),
      escHave: n(/(\d+) points reached D\+1 = (\d+)/, cliffTxt, 1),
      escNeed: n(/(\d+) points reached D\+1 = (\d+)/, cliffTxt, 2),
      escShownDeg: n(/degree-(\d+) polynomial/, cliffTxt),
      escRealDeg: n(/secretly degree (\d+)/, cliffTxt),
      // sign hint arithmetic
      hintTxt,
      hintFresh: n(/\+(\d+) distinct/, hintTxt),
      hintBefore: n(/\((\d+)\s*→\s*(\d+)\)/, hintTxt, 1),
      hintAfter: n(/\((\d+)\s*→\s*(\d+)\)/, hintTxt, 2),
      hintRemaining: n(/(\d+) more distinct point/, hintTxt),
      hintAllFresh: n(/all (\d+) positions fresh/, hintTxt),
      hintReachedHave: n(/cliff reached: (\d+)\D+(\d+)/, hintTxt, 1),
      hintReachedNeed: n(/cliff reached: (\d+)\D+(\d+)/, hintTxt, 2),
      // verdict + coefficient table
      verdictTxt,
      verdictCoeffs: n(/all (\d+) coefficients/, verdictTxt),
      rowsShown: document.querySelectorAll(".coeff-table tbody tr:not(.more-row)").length,
      rowsMatch: document.querySelectorAll(".coeff-table tbody tr.match").length,
      rowsMore: n(/and (\d+) more coefficients/, t(".coeff-table .more-row")),
      // the true-secret column, used to prove it never reaches the transcript
      trueCoeffs: [...document.querySelectorAll(".coeff-table tbody tr:not(.more-row)")].map(
        (r) => r.querySelectorAll("td")[2]?.textContent.trim() ?? "",
      ),
      // ledger accounting
      sigCount: sigTags.length,
      lastSigNo: sigTags.length ? n(/signature #(\d+)/, sigTags[sigTags.length - 1]) : 0,
      freshSum: sigTags.reduce((a, s) => a + (n(/\+(\d+) distinct/, s) || 0), 0),
      ledPts: document.querySelectorAll(".led-pt").length,
      ledDup: document.querySelectorAll(".led-pt.dup").length,
      // plot accounting
      oodDots: document.querySelectorAll(".ood-dot").length,
      revealDots: document.querySelectorAll(".reveal-dot").length,
      emptySlots: document.querySelectorAll(".empty-slot").length,
      plotAria: document.querySelector(".cliff-svg")?.getAttribute("aria-label") ?? "",
      // export result
      exportTxt,
      exportClass: document.querySelector("#export-result")?.className ?? "",
      expOkPts: n(/reconstructed from (\d+) public points/, exportTxt),
      expShortHave: n(/insufficient points: (\d+) distinct of (\d+) needed/, exportTxt, 1),
      expShortNeed: n(/insufficient points: (\d+) distinct of (\d+) needed/, exportTxt, 2),
      // malicious panel
      escapeTxt,
      escNoteNeeded: n(/D\+1 = (\d+) points/, escapeTxt),
      escNoteRealDeg: n(/real key is degree (\d+)/, escapeTxt),
      escNoteWouldTake: n(/would take (\d+) points/, escapeTxt),
      secretTxt,
      malAdvertisedDeg: n(/advertises degree (\d+)/, secretTxt),
      malRealDeg: n(/actually degree (\d+)/, secretTxt),
      malRealCoeffs: n(/\((\d+) coefficients\)/, secretTxt),
      // soft-vs-cliff comparison chart
      cmpAria: document.querySelector(".cmp-svg")?.getAttribute("aria-label") ?? "",
    };
  });
}

/** Capture the transcript the export button downloads. */
async function exportTranscript(p, name) {
  const [dl] = await Promise.all([p.waitForEvent("download"), p.click("#btn-export")]);
  const file = join(WORK, name);
  await dl.saveAs(file);
  await p.waitForTimeout(150);
  return { file, suggested: dl.suggestedFilename(), json: JSON.parse(readFileSync(file, "utf8")) };
}

/**
 * Run the README's offline auditor: `npm run verify <file> [--expected-fingerprint <fp>]`.
 * Without the anchor it can only report internal consistency.
 */
function runVerifyCli(file, expectedFingerprint) {
  const args = [join(REPO, "scripts", "verify.ts"), file];
  if (expectedFingerprint) args.push("--expected-fingerprint", expectedFingerprint);
  const r = spawnSync(TSX, args, { cwd: REPO, encoding: "utf8" });
  return { code: r.status, out: (r.stdout ?? "") + (r.stderr ?? "") };
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
check("below cliff: algebraically underdetermined", /underdetermined/i.test(await page.textContent("#cliff-status")));
check("recovery panel hidden below cliff", await page.isHidden("#panel-recover"));
await grindToCliff(page);
check("honest: EXACT MATCH", /EXACT MATCH/.test(await page.textContent(".verdict")));
check("honest: all coeff rows match", (await page.locator(".coeff-table tr.mismatch").count()) === 0);
check("honest: grind disabled at cliff", await page.isDisabled("#btn-grind"));
await scan(page, "honest/cliff");

// --- export + verify round-trip (honest → verified) ---
await page.click("#btn-export");
await page.waitForTimeout(150);
check("export reports internal consistency in-browser",
  /internally consistent/i.test(await page.textContent("#export-result")));

// --- duplicate-point handling (honest sign same message twice) ---
await gen(page, { nStar: 3, K: 3 });
await page.fill("#msg", "same-message");
await page.click("#btn-sign"); await page.waitForTimeout(120);
const after1 = await page.textContent("#meter-count");
const s1 = await st(page);
await page.click("#btn-sign"); await page.waitForTimeout(120);
const after2 = await page.textContent("#meter-count");
check("duplicate positions do not advance the cliff", after1 === after2, `${after1} -> ${after2}`);
const dupCount = await page.locator(".led-pt.dup").count();
check("duplicate points are marked", dupCount >= 1, `dup spans=${dupCount}`);

// The second signature reveals K points that are ALL repeats, so the hint must
// report zero fresh and the ledger must gain K duplicate-marked spans while the
// distinct count stands still.
const s2 = await st(page);
check("honest sign: hint arithmetic adds up (before + fresh = after)",
  s1.hintBefore + s1.hintFresh === s1.hintAfter,
  `${s1.hintBefore} + ${s1.hintFresh} = ${s1.hintAfter}`);
check("honest sign: hint's 'after' is the meter's distinct count",
  s1.hintAfter === s1.distinct, `hint=${s1.hintAfter} meter=${s1.distinct}`);
check("honest sign: hint's remaining = needed - distinct",
  s1.hintRemaining === s1.needed - s1.distinct,
  `${s1.hintRemaining} vs ${s1.needed} - ${s1.distinct}`);
check("re-signing the same message adds 0 fresh points", s2.hintFresh === 0, s2.hintTxt);
check("duplicate re-sign marks exactly K dup spans", s2.ledDup === s2.K,
  `dup=${s2.ledDup} K=${s2.K}`);
check("ledger accounting: spans = 1 OOD + K per signature",
  s2.ledPts === 1 + s2.K * s2.sigCount, `${s2.ledPts} vs 1 + ${s2.K}*${s2.sigCount}`);
check("ledger accounting: distinct = spans - duplicates",
  s2.distinct === s2.ledPts - s2.ledDup, `${s2.distinct} vs ${s2.ledPts} - ${s2.ledDup}`);
check("ledger accounting: per-signature '+N distinct' sums to distinct - OOD",
  s2.freshSum === s2.distinct - 1, `${s2.freshSum} vs ${s2.distinct} - 1`);

// --- malicious escape ---
await gen(page, { nStar: 2, K: 3, signer: "malicious" });
await grindToCliff(page);
check("malicious: SIGNER ESCAPED", /SIGNER ESCAPED/.test(await page.textContent(".verdict")));
check("malicious: panel title adapts", /escaped/i.test(await page.textContent("#panel-recover h2")));
check("malicious: no coeff table", (await page.locator(".coeff-table").count()) === 0);
const mal = await exportTranscript(page, "malicious.json");
check("malicious export does NOT verify", /Not verified/i.test(await page.textContent("#export-result")));

// The escape is only meaningful if the page says WHY, with numbers that agree
// across the key panel, the cliff callout and the recovery panel.
const sm = await st(page);
check("malicious: cliff fired (points reached the advertised D+1)",
  sm.escHave >= sm.escNeed && sm.escNeed === sm.D + 1,
  `${sm.escHave} >= D+1 = ${sm.escNeed}`);
check("malicious: advertised degree matches the published D",
  sm.malAdvertisedDeg === sm.D && sm.escShownDeg === sm.D,
  `advertised=${sm.malAdvertisedDeg} shown=${sm.escShownDeg} D=${sm.D}`);
check("malicious: real degree is one above the advertised one, everywhere",
  sm.malRealDeg === sm.D + 1 && sm.escRealDeg === sm.D + 1 && sm.escNoteRealDeg === sm.D + 1,
  `${sm.malRealDeg}/${sm.escRealDeg}/${sm.escNoteRealDeg} vs ${sm.D + 1}`);
check("malicious: real key has realDegree+1 coefficients",
  sm.malRealCoeffs === sm.malRealDeg + 1, `${sm.malRealCoeffs} vs ${sm.malRealDeg} + 1`);
check("malicious: escape note's advertised cliff equals the meter's needed",
  sm.escNoteNeeded === sm.needed, `${sm.escNoteNeeded} vs ${sm.needed}`);
check("malicious: 'would take N points' = real degree + 1 (beyond the budget)",
  sm.escNoteWouldTake === sm.escNoteRealDeg + 1 && sm.escNoteWouldTake > sm.needed,
  `${sm.escNoteWouldTake} vs ${sm.escNoteRealDeg} + 1, needed=${sm.needed}`);
check("malicious: meter aria says the key escaped", /escaped/i.test(sm.ariaText), sm.ariaText);

// Same transcript, audited offline by the README's CLI: must refuse it.
const malCli = runVerifyCli(mal.file);
check("malicious transcript: `npm run verify` reports NOT VERIFIED",
  malCli.code === 1 && /NOT VERIFIED/.test(malCli.out),
  `exit=${malCli.code}`);
check("malicious transcript: CLI names the over-degree cause",
  /over-degree \/ malicious key, or tampered transcript/.test(malCli.out));
check("malicious transcript: CLI's recovered fingerprint differs from the published one",
  /fingerprint published: ([0-9a-f]+)/.exec(malCli.out)?.[1] !==
    /fingerprint recovered: ([0-9a-f]+)/.exec(malCli.out)?.[1]);
await scan(page, "malicious/cliff");

// --- tower field ---
await gen(page, { nStar: 2, K: 3, field: "tower" });
check("tower: OOD shown as tuple", /⟨/.test(await page.textContent(".ood-pt")));
await grindToCliff(page);
check("tower: EXACT MATCH", /EXACT MATCH/.test(await page.textContent(".verdict")));
await scan(page, "tower/cliff");

// --- K=16, the paper's parameter value ---
await gen(page, { nStar: 1, K: 16 });
check("K=16: D=31", (await page.textContent(".kv:nth-child(4) code")).includes("31"));
await grindToCliff(page, 6);
check("K=16: EXACT MATCH", /EXACT MATCH/.test(await page.textContent(".verdict")));
check("K=16: table capped ≤24 rows", (await page.locator(".coeff-table tbody tr:not(.more-row)").count()) <= 24);
check("K=16: plot omits high-degree curves", /curves omitted/.test(await page.textContent("#plot")));
// The table is truncated, so the rows shown plus the "and N more" tail must
// still account for every coefficient the verdict claims to have recovered.
const s16 = await st(page);
check("K=16: shown rows + 'and N more' = M coefficients",
  s16.rowsShown + s16.rowsMore === s16.M && s16.rowsShown === 24,
  `${s16.rowsShown} + ${s16.rowsMore} = ${s16.M}`);
check("K=16: verdict's coefficient count is M, not a fixed string",
  s16.verdictCoeffs === s16.M, `${s16.verdictCoeffs} vs ${s16.M}`);
check("K=16: every shown row is a match",
  s16.rowsMatch === s16.rowsShown, `${s16.rowsMatch}/${s16.rowsShown}`);
check("K=16: plot note counts agree with the meter",
  new RegExp(`degree ${s16.D} — curves omitted; ${Math.min(s16.distinct, s16.needed)} of ${s16.needed} points shown`)
    .test(await page.textContent("#plot")));

// --- parameter identities, at every offered (n*, K) ---
// The key panel publishes M, D, T and the cliff signature. They are not
// independent facts: M = (n*+1)·K, D = M−1, T = 2M, cliff = n*+1. Checking the
// page's own numbers against those identities catches a derivation regression
// that a "the panel rendered" assertion would sail past.
for (const [nStar, K] of [[1, 2], [3, 3], [5, 4], [1, 16], [7, 2]]) {
  await gen(page, { nStar, K });
  const s = await st(page);
  const tag = `n*=${nStar} K=${K}`;
  check(`${tag}: panel echoes the chosen params`, s.nStar === nStar && s.K === K);
  check(`${tag}: M = (n*+1)·K`, s.M === (nStar + 1) * K, `M=${s.M}`);
  check(`${tag}: D = M−1`, s.D === s.M - 1, `D=${s.D}`);
  check(`${tag}: T = 2M`, s.T === 2 * s.M, `T=${s.T}`);
  check(`${tag}: cliff fires at n*+1`, s.nCliff === nStar + 1, `nCliff=${s.nCliff}`);
  check(`${tag}: meter needs D+1 points`, s.needed === s.D + 1, `needed=${s.needed}`);
  check(`${tag}: a fresh key already holds the 1 free OOD point`, s.distinct === 1);
  check(`${tag}: comparison chart is drawn against the same n*`,
    new RegExp(`through signature ${nStar},.*signature ${nStar + 1}\\.`).test(s.cmpAria),
    s.cmpAria.slice(-70));
}

// --- full counter accounting through a grind to the cliff ---
await gen(page, { nStar: 2, K: 3 });
const fresh = await st(page);
check("fresh key: meter reads 1 / D+1", fresh.meterTxt.replace(/\s/g, "") === `1/${fresh.needed}`, fresh.meterTxt);
check("fresh key: progressbar max = needed, now = distinct",
  fresh.ariaMax === fresh.needed && fresh.ariaNow === fresh.distinct);
check("fresh key: fill width tracks distinct/needed",
  Math.abs(fresh.fillPct - (fresh.distinct / fresh.needed) * 100) < 0.2,
  `${fresh.fillPct}% vs ${((fresh.distinct / fresh.needed) * 100).toFixed(1)}%`);
check("fresh key: callout counts agree with the meter",
  fresh.cliffSafeHave === fresh.distinct && fresh.cliffSafeNeed === fresh.needed);
check("fresh key: 'N short' = needed − distinct",
  fresh.cliffSafeShort === fresh.needed - fresh.distinct, `${fresh.cliffSafeShort}`);
check("fresh key: plot slots = revealed + OOD + empty = D+1",
  fresh.oodDots + fresh.revealDots + fresh.emptySlots === fresh.needed,
  `${fresh.oodDots}+${fresh.revealDots}+${fresh.emptySlots} vs ${fresh.needed}`);

// Failure path: exporting before the cliff cannot verify — there is not enough
// public data to reconstruct anything, and the page must say exactly that.
const early = await exportTranscript(page, "below-cliff.json");
const se = await st(page);
check("below cliff: export is marked NOT verified", /export-bad/.test(se.exportClass), se.exportClass);
check("below cliff: refusal cites the real shortfall",
  se.expShortHave === se.distinct && se.expShortNeed === se.needed,
  `${se.expShortHave}/${se.expShortNeed} vs ${se.distinct}/${se.needed}`);
check("below cliff: transcript carries only the points on screen",
  early.json.points.length === se.distinct, `${early.json.points.length} vs ${se.distinct}`);
const earlyCli = runVerifyCli(early.file);
check("below cliff: `npm run verify` also refuses it",
  earlyCli.code === 1 && /NOT VERIFIED/.test(earlyCli.out) && /insufficient points/.test(earlyCli.out),
  `exit=${earlyCli.code}`);

// The grind is the adversarial worst case the budget is sized for: every
// signature is all-fresh, so the cliff must land on signature n*+1 exactly.
const clicks = await grindToCliff(page);
const hit = await st(page);
check("grind: cliff reached in exactly n*+1 signatures",
  clicks === hit.nCliff && hit.sigCount === hit.nCliff && hit.lastSigNo === hit.nCliff,
  `clicks=${clicks} sigs=${hit.sigCount} last=#${hit.lastSigNo} nCliff=${hit.nCliff}`);
check("grind: the last signature reported all K positions fresh",
  hit.hintAllFresh === hit.K && hit.hintFresh === hit.K, hit.hintTxt);
check("grind: distinct = 1 OOD + K per signature",
  hit.distinct === 1 + hit.K * hit.sigCount, `${hit.distinct} vs 1 + ${hit.K}*${hit.sigCount}`);
check("grind: per-signature fresh counts sum to distinct − OOD",
  hit.freshSum === hit.distinct - 1, `${hit.freshSum} vs ${hit.distinct} - 1`);
check("grind: no duplicate points were revealed", hit.ledDup === 0);
check("grind: distinct crossed the cliff", hit.distinct >= hit.needed, `${hit.distinct} >= ${hit.needed}`);
check("at cliff: hint's own 'cliff reached: a ≥ b' matches the meter",
  hit.hintReachedHave === hit.distinct && hit.hintReachedNeed === hit.needed);
check("at cliff: callout counts agree with the meter",
  hit.cliffHitHave === hit.distinct && hit.cliffHitNeed === hit.needed);
check("at cliff: progressbar is clamped to needed and full",
  hit.ariaNow === Math.min(hit.distinct, hit.needed) && hit.fillPct === 100 &&
    /danger/.test(hit.fillClass));
check("at cliff: meter aria says the secret was recovered",
  /cliff reached, secret recovered/.test(hit.ariaText), hit.ariaText);
check("at cliff: plot shows min(distinct, needed) of needed points",
  hit.oodDots + hit.revealDots === Math.min(hit.distinct, hit.needed) &&
    hit.emptySlots === 0 &&
    hit.plotAria === `Cliff plot: ${Math.min(hit.distinct, hit.needed)} of ${hit.needed} points revealed`,
  hit.plotAria);

// The headline verdict, checked against M rather than against a fixed string.
check("verdict: coefficient count equals the published M",
  hit.verdictCoeffs === hit.M, `${hit.verdictCoeffs} vs M=${hit.M}`);
check("verdict: one table row per coefficient, all matching",
  hit.rowsShown === hit.M && hit.rowsMatch === hit.M && Number.isNaN(hit.rowsMore),
  `${hit.rowsShown} rows, ${hit.rowsMatch} match, M=${hit.M}`);

// --- the exported transcript is public-only, and audits offline ---
const good = await exportTranscript(page, "honest.json");
const sg = await st(page);
check("export filename is keyed to the public root hint",
  /^jevil-transcript-jv-[0-9a-f]+\.json$/.test(good.suggested), good.suggested);
check("export: in-browser result counts the same points as the meter",
  sg.expOkPts === sg.distinct && /export-ok/.test(sg.exportClass),
  `${sg.expOkPts} vs ${sg.distinct}`);
check("export: transcript params match the key panel",
  good.json.params.nStar === sg.nStar && good.json.params.K === sg.K &&
    good.json.params.M === sg.M && good.json.params.D === sg.D &&
    good.json.params.T === sg.T && good.json.params.nCliff === sg.nCliff);
check("export: transcript point count matches the on-screen distinct count",
  good.json.points.length === sg.distinct, `${good.json.points.length} vs ${sg.distinct}`);
check("export: transcript declares the field in use", good.json.field === "base");
// "Only public data — no secret": the true coefficients are on screen in the
// recovery table, so assert none of them appears anywhere in the file.
const words = new Set([
  ...good.json.ood.x, ...good.json.ood.y,
  ...good.json.points.flatMap((p) => [...p.x, ...p.y]),
]);
const secretDecimals = sg.trueCoeffs
  .filter((h) => /^0x[0-9a-f]+$/.test(h))
  .map((h) => BigInt(h).toString());
check("export: every true coefficient was read off the recovery table",
  secretDecimals.length === sg.M, `${secretDecimals.length} vs ${sg.M}`);
check("export: no secret coefficient appears in the transcript",
  secretDecimals.every((d) => !words.has(d)));
check("export: transcript has no coefficient or seed field",
  !/"coeffs"|"seed"/.test(readFileSync(good.file, "utf8")));

const goodCli = runVerifyCli(good.file);
// WITHOUT an anchor the CLI must NOT say "VERIFIED": the only fingerprint it can
// compare against lives in the same file, so the claim is internal consistency.
check("`npm run verify` unanchored reports INTERNALLY CONSISTENT, not VERIFIED",
  goodCli.code === 0
    && /~ INTERNALLY CONSISTENT/.test(goodCli.out)
    && !/✓ VERIFIED/.test(goodCli.out),
  `exit=${goodCli.code}`);
check("…and says outright that this is not proof of provenance",
  /NOT proof the transcript belongs to any particular key/.test(goodCli.out));
check("CLI recovers the file's fingerprint from public data alone",
  /fingerprint in file:  ([0-9a-f]+)/.exec(goodCli.out)?.[1] ===
    /fingerprint recovered: ([0-9a-f]+)/.exec(goodCli.out)?.[1]);

// WITH the fingerprint read off the KEY PANEL — not out of the file — it becomes
// a statement about which key this transcript belongs to.
const panelFingerprint = (await page.textContent("#key-fingerprint")).trim();
check("the key panel shows the full 64-hex public fingerprint",
  /^[0-9a-f]{64}$/.test(panelFingerprint), panelFingerprint.slice(0, 20));
const anchoredCli = runVerifyCli(good.file, panelFingerprint);
check("`npm run verify --expected-fingerprint` (from the panel) reports VERIFIED",
  anchoredCli.code === 0 && /✓ VERIFIED against the expected public key/.test(anchoredCli.out),
  `exit=${anchoredCli.code}`);
// …and a wrong anchor must be refused, or the flag would be decoration.
const wrongAnchor = "0".repeat(64);
const badAnchorCli = runVerifyCli(good.file, wrongAnchor);
check("a WRONG expected fingerprint is refused [ANCHOR_MISMATCH]",
  badAnchorCli.code === 1 && /ANCHOR_MISMATCH/.test(badAnchorCli.out),
  `exit=${badAnchorCli.code}`);
check("CLI reports the same point counts the page did",
  new RegExp(`points:\\s+${sg.distinct} distinct / ${sg.needed} needed`).test(goodCli.out));

// Tamper path: flip one revealed evaluation and the fingerprint no longer
// reproduces — the transcript is not a stored answer, it is recomputed.
const tampered = JSON.parse(readFileSync(good.file, "utf8"));
tampered.points[0].y[0] = (BigInt(tampered.points[0].y[0]) + 1n).toString();
const tamperFile = join(WORK, "tampered.json");
writeFileSync(tamperFile, JSON.stringify(tampered));
const tamperCli = runVerifyCli(tamperFile);
check("tampered transcript: `npm run verify` reports NOT VERIFIED",
  tamperCli.code === 1 && /NOT VERIFIED/.test(tamperCli.out), `exit=${tamperCli.code}`);
check("tampered transcript: recovered fingerprint diverges from the file's",
  /fingerprint in file:  ([0-9a-f]+)/.exec(tamperCli.out)?.[1] !==
    /fingerprint recovered: ([0-9a-f]+)/.exec(tamperCli.out)?.[1]);
// A transcript of the wrong shape is refused before any interpolation happens.
const alienFile = join(WORK, "alien.json");
writeFileSync(alienFile, JSON.stringify({ ...tampered, scheme: "not-jevil" }));
const alienCli = runVerifyCli(alienFile);
check("foreign transcript: CLI refuses it as not a jevil transcript",
  alienCli.code === 1 && /not a crypto-lab-jevil transcript/.test(alienCli.out),
  `exit=${alienCli.code}`);

// ------------------------------------------------------------------------
// What the page CLAIMS about what is hidden. Each of these was false as
// rendered: the count is finite in a finite field, and "unlimited computing
// power" is defeated by the page's own published fingerprint plus a
// deterministic key derivation.
// ------------------------------------------------------------------------
await gen(page, { nStar: 3, K: 3 });
const cliffPanel = (await page.textContent("#panel-cliff")).replace(/\s+/g, " ");
// "infinitely many" may appear ONLY as something the page denies. Asserting the
// substring is absent would be satisfied by deleting the correction too.
const infinitelyClaims = [...cliffPanel.matchAll(/(.{0,12})infinitely many/gi)]
  .filter((m) => !/not\s*[\u201c"']?$/i.test(m[1]));
check("the cliff panel never ASSERTS 'infinitely many' in a finite field",
  infinitelyClaims.length === 0, JSON.stringify(infinitelyClaims.map((m) => m[0])));
check("…and it does say the phrase, as a correction",
  /not [\u201c"']?infinitely many/i.test(cliffPanel));
check("…and states the actual finite count |F|^(D+1-m)",
  /\|F\|/.test(cliffPanel) && /D\+1.{0,3}m/.test(cliffPanel));
check("…and scopes the claim to the evaluations alone",
  /from the revealed evaluations alone/i.test(cliffPanel));
check("…and names what the whole public key still leaks to an unbounded adversary",
  /binding fingerprint/i.test(cliffPanel)
    && /unbounded|unlimited/i.test(cliffPanel)
    && /enumerate/i.test(cliffPanel));
check("no panel still promises unlimited computing power cannot tell which is f",
  !/unlimited computing power can't tell/i.test(await page.textContent("main")));

// The live status must PRINT the computed count, and that count must fall as
// points accumulate — not a fixed word.
const countOf = async () => {
  const m = /Exactly 2\^(\d+) degree-\d+/.exec(await page.textContent("#cliff-status"));
  return m ? Number(m[1]) : null;
};
const c0 = await countOf();
check("below cliff the status prints a concrete candidate count", c0 !== null, String(c0));
await page.fill("#msg", "count-shrink-probe");
await page.click("#btn-sign");
await page.waitForTimeout(150);
const c1 = await countOf();
check("the candidate count SHRINKS as distinct points accumulate",
  c0 !== null && c1 !== null && c1 < c0, `${c0} -> ${c1}`);
// q0 = 2^64 - 2^32 + 1 is just under 2^64, so floor(log2(q0^k)) is 64k - 1.
// The count must therefore land on that lattice, and drop by ~64 bits per point.
check("…and the count is floor(log2(q0^k)) = 64k-1 for an integer k",
  c1 !== null && (c1 + 1) % 64 === 0, String(c1));
check("…and one extra distinct point costs about one field element of freedom",
  c0 !== null && c1 !== null && (c0 - c1) % 64 === 0 && c0 - c1 >= 64,
  `${c0} - ${c1} = ${c0 - c1}`);
await grindToCliff(page);
check("at the cliff the status stops offering alternatives",
  !/Exactly 2\^/.test(await page.textContent("#cliff-status")));

// The K selector must not call a single parameter a security grade.
const keyPanel = (await page.textContent("#panel-key")).replace(/\s+/g, " ");
check("K=16 is labelled the paper's parameter value, not a 'security grade'",
  !/security grade/i.test(keyPanel) && /parameter value/i.test(keyPanel));
check("…and the panel says K alone does not make a configuration secure",
  /K.{0,20}alone does not make/i.test(keyPanel));

// The ~124-bit figure belongs to the paper's full construction, not this page.
const hero = (await page.textContent(".cl-hero-why-text")).replace(/\s+/g, " ");
check("the 124-bit claim is scoped to the paper's full construction",
  /124/.test(hero) && /paper's full construction/i.test(hero));

// The same scoping applies to the social-preview metadata: og:description said
// "the key is ~124-bit safe" with nothing to hang the number on, and outlived
// the hero correction. Dropping the number entirely would also pass — what must
// not ship is an unscoped 124.
const ogDesc = (await page.getAttribute('meta[property="og:description"]', "content")) ?? "";
check("the social-preview description scopes any 124-bit claim to the paper",
  !/124/.test(ogDesc) || /paper/i.test(ogDesc), ogDesc);

// The priority claim is the paper's, and knowledge-scoped.
const claim = (await page.textContent(".claim")).replace(/\s+/g, " ");
check("the 'first FTS' priority claim is attributed and knowledge-scoped",
  /to the author's knowledge/i.test(claim) && /paper's, not this lab's/i.test(claim));

// The comparison chart must not read as a measurement.
const cmpNote = (await page.textContent(".cmp-note")).replace(/\s+/g, " ");
check("the soft-vs-sharp chart is labelled schematic, not measured",
  /schematic, not measured/i.test(cmpNote)
    && /negligible, not zero/i.test(cmpNote)
    && /does not measure a forgery probability/i.test(cmpNote));

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
