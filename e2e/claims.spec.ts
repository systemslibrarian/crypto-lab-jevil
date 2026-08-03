import { expect, test, type Page } from '@playwright/test';

/**
 * Functional claims gate — the states `scripts/e2e.test.mjs` does not reach.
 *
 * That harness is thorough on one axis: it drives a run to completion and
 * cross-checks every number the page prints against every other number it
 * prints. What it never does is *change its mind mid-run* — every scenario
 * begins with a fresh `Generate key`. So the states it cannot see are the ones
 * where a verdict outlives the thing it described:
 *
 *   - the export panel still reporting on a ledger that has since advanced;
 *   - the four key selectors moved without pressing Generate, leaving every
 *     panel below describing a key those settings no longer produce.
 *
 * Both were real when this file was written, and both are pinned below,
 * alongside the headline verdict and the failure paths asserted against values
 * the page computed rather than literals.
 */

const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(({ page }) => {
  const errs: string[] = [];
  pageErrors.set(page, errs);
  page.on('pageerror', (err) => errs.push(err.message));
});

test.afterEach(({ page }) => {
  expect(pageErrors.get(page) ?? [], 'uncaught page exceptions').toEqual([]);
});

// ─── helpers ─────────────────────────────────────────────────────────────────

async function text(page: Page, sel: string): Promise<string> {
  return ((await page.textContent(sel)) ?? '').replace(/\s+/g, ' ').trim();
}

/** The key panel's published parameters, read off the page. */
async function params(page: Page): Promise<Record<string, number>> {
  return page.$$eval('#key-out .kv', (kvs) => {
    const out: Record<string, number> = {};
    for (const kv of kvs) {
      const label = kv.querySelector('span')?.textContent?.trim() ?? '';
      const value = kv.querySelector('code')?.textContent?.trim() ?? '';
      const n = Number(/(\d+)\s*$/.exec(value)?.[1]);
      if (label.startsWith('budget')) out.nStar = n;
      else if (label.startsWith('positions')) out.K = n;
      else if (label.startsWith('coefficients')) out.M = n;
      else if (label.startsWith('degree')) out.D = n;
      else if (label.startsWith('domain')) out.T = n;
      else if (label.startsWith('cliff fires')) out.nCliff = n;
    }
    return out;
  });
}

/** The distinct / needed pair the meter is showing. */
async function meter(page: Page): Promise<{ distinct: number; needed: number }> {
  const m = /(\d+)\s*\/\s*(\d+)/.exec(await text(page, '#meter-count'));
  expect(m, 'meter should read "distinct / needed"').not.toBeNull();
  return { distinct: Number(m![1]), needed: Number(m![2]) };
}

async function generate(
  page: Page,
  opts: { nStar: number; K: number; field?: string; signer?: string },
): Promise<void> {
  await page.selectOption('#sel-nstar', String(opts.nStar));
  await page.selectOption('#sel-k', String(opts.K));
  await page.selectOption('#sel-field', opts.field ?? 'base');
  await page.selectOption('#sel-signer', opts.signer ?? 'honest');
  await page.click('#btn-gen');
  await expect(page.locator('#key-out')).not.toHaveClass(/hidden/);
  await expect
    .poll(async () => (await params(page)).nStar, { timeout: 15_000 })
    .toBe(opts.nStar);
  await expect(page.locator('#param-pending')).toHaveClass(/hidden/);
}

/** Click grind once and wait for the ledger to actually advance. */
async function grindOnce(page: Page): Promise<void> {
  const before = await text(page, '#meter-count');
  await page.click('#btn-grind');
  await expect.poll(() => text(page, '#meter-count'), { timeout: 20_000 }).not.toBe(before);
}

/** Grind until the cliff fires; returns how many signatures it took. */
async function grindToCliff(page: Page, max = 24): Promise<number> {
  let clicks = 0;
  for (let i = 0; i < max; i++) {
    if (await page.locator('#btn-grind').isDisabled()) break;
    await grindOnce(page);
    clicks++;
  }
  return clicks;
}

async function signOnce(page: Page, message: string): Promise<void> {
  await page.fill('#msg', message);
  const before = await text(page, '#sign-hint');
  await page.click('#btn-sign');
  await expect.poll(() => text(page, '#sign-hint'), { timeout: 20_000 }).not.toBe(before);
}

/** Export, swallowing the download, and hand back the resulting banner. */
async function exportTranscript(page: Page): Promise<{ text: string; cls: string }> {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('#btn-export'),
  ]);
  expect(download.suggestedFilename()).toMatch(/^jevil-transcript-jv-[0-9a-f]+\.json$/);
  return {
    text: await text(page, '#export-result'),
    cls: (await page.getAttribute('#export-result', 'class')) ?? '',
  };
}

// ─── 1. The headline verdict, anchored to numbers the page computed ──────────

test('the cliff fires at n*+1 and recovers exactly the published number of coefficients', async ({ page }) => {
  await page.goto('.');
  await generate(page, { nStar: 2, K: 3 });

  const p = await params(page);
  // The published parameters are not independent facts.
  expect(p.M).toBe((p.nStar + 1) * p.K);
  expect(p.D).toBe(p.M - 1);
  expect(p.T).toBe(2 * p.M);
  expect(p.nCliff).toBe(p.nStar + 1);

  const fresh = await meter(page);
  expect(fresh.needed).toBe(p.D + 1);
  expect(fresh.distinct, 'a fresh key already holds the free OOD point').toBe(1);
  expect(await text(page, '#cliff-status')).toMatch(/Secret undetermined/i);
  await expect(page.locator('#panel-recover')).toHaveClass(/hidden/);

  const signatures = await grindToCliff(page);
  expect(signatures, 'the grind is the worst case the budget is sized for').toBe(p.nCliff);

  const hit = await meter(page);
  expect(hit.distinct).toBeGreaterThanOrEqual(hit.needed);
  expect(hit.distinct, 'every grind signature is all-fresh').toBe(1 + p.K * signatures);

  // Headline verdict: the coefficient count comes from the page's own M.
  const verdict = await text(page, '.verdict');
  expect(verdict).toContain('EXACT MATCH');
  expect(verdict).toContain(`all ${p.M} coefficients`);
  expect(await page.locator('.coeff-table tbody tr.match').count()).toBe(p.M);
  expect(await page.locator('.coeff-table tbody tr.mismatch').count()).toBe(0);

  // Sighted and screen-reader surfaces must agree about the same run.
  expect(await page.getAttribute('#meter', 'aria-valuetext')).toBe(
    `${hit.distinct} of ${hit.needed} distinct points — cliff reached, secret recovered`,
  );
  expect(await page.getAttribute('#meter', 'aria-valuemax')).toBe(String(hit.needed));
  expect(await text(page, '#cliff-status')).toContain(
    `${hit.distinct} distinct points ≥ D+1 = ${hit.needed}`,
  );
});

// ─── 2. Failure paths name their cause ───────────────────────────────────────

test('a malicious signer escapes the cliff, and the page says why with its own numbers', async ({ page }) => {
  await page.goto('.');
  await generate(page, { nStar: 2, K: 3, signer: 'malicious' });
  const p = await params(page);

  await grindToCliff(page);
  const hit = await meter(page);

  expect(await text(page, '.verdict')).toContain('SIGNER ESCAPED');
  expect(await page.locator('.coeff-table').count(), 'nothing was recovered to tabulate').toBe(0);

  const status = await text(page, '#cliff-status');
  expect(status).toContain(`${hit.distinct} points reached D+1 = ${hit.needed}`);
  expect(status).toContain(`degree-${p.D} polynomial`);
  expect(status).toContain(`secretly degree ${p.D + 1}`);

  const note = await text(page, '#panel-recover');
  expect(note).toContain(`real key is degree ${p.D + 1}`);
  expect(note).toContain(`would take ${p.D + 2} points`);
  expect(note).toContain('zk-WHIR commitment');

  // The announcement must not tell a screen-reader user the secret was recovered.
  const ariaText = await page.getAttribute('#meter', 'aria-valuetext');
  expect(ariaText).toContain('the malicious key escaped');
  expect(ariaText).not.toContain('secret recovered');

  // And the transcript of an escaped run must refuse to verify.
  const banner = await exportTranscript(page);
  expect(banner.cls).toContain('export-bad');
  expect(banner.text).toMatch(/Not verified/i);
});

test('exporting below the cliff is refused, quoting the shortfall the meter shows', async ({ page }) => {
  await page.goto('.');
  await generate(page, { nStar: 3, K: 3 });
  await grindOnce(page);

  const m = await meter(page);
  expect(m.distinct).toBeLessThan(m.needed);

  const banner = await exportTranscript(page);
  expect(banner.cls).toContain('export-bad');
  expect(banner.text).toContain('Not verified');
  expect(banner.text).toContain(`${m.distinct} distinct of ${m.needed} needed`);
});

// ─── 3. Regression: the export verdict must not outlive its ledger ───────────

test('the export verdict retires when the ledger advances past it', async ({ page }) => {
  await page.goto('.');
  await generate(page, { nStar: 2, K: 3 });

  // Refusal below the cliff…
  const early = await exportTranscript(page);
  expect(early.cls).toContain('export-bad');
  const shortfall = (await meter(page)).distinct;

  // …must not still be on screen once the cliff has fired. The page used to
  // show "Not verified: insufficient points" directly beneath "EXACT MATCH".
  await grindToCliff(page);
  expect(await text(page, '.verdict')).toContain('EXACT MATCH');

  const stale = await text(page, '#export-result');
  expect(stale).not.toContain('Not verified');
  expect(stale).not.toContain(`${shortfall} distinct`);
  expect(stale).toContain('ledger has changed since that export');
  expect(await page.getAttribute('#export-result', 'class')).not.toContain('export-bad');

  // Exporting again reports on the ledger that is actually on screen.
  const now = await meter(page);
  const fresh = await exportTranscript(page);
  expect(fresh.cls).toContain('export-ok');
  expect(fresh.text).toContain(`reconstructed from ${now.distinct} public points`);

  // Signing again retires that verdict too — its point count is now wrong.
  await signOnce(page, 'one more after the export');
  const after = await meter(page);
  const post = await text(page, '#export-result');
  if (after.distinct !== now.distinct) {
    expect(post).not.toContain(`reconstructed from ${now.distinct} public points`);
    expect(post).toContain('ledger has changed since that export');
  }
  // …and a fresh key clears the line outright.
  await generate(page, { nStar: 1, K: 2 });
  expect(await text(page, '#export-result')).toBe('');
});

// ─── 4. Regression: the panels must not claim to describe unapplied settings ─

test('changing a selector without pressing Generate is flagged, not silently ignored', async ({ page }) => {
  await page.goto('.');
  await generate(page, { nStar: 2, K: 3 });
  const applied = await params(page);
  await grindToCliff(page);
  expect(await text(page, '.verdict')).toContain('EXACT MATCH');

  for (const [selector, value] of [
    ['#sel-nstar', '7'],
    ['#sel-k', '4'],
    ['#sel-field', 'tower'],
    ['#sel-signer', 'malicious'],
  ] as const) {
    await page.selectOption(selector, value);
    await expect(page.locator('#param-pending')).not.toHaveClass(/hidden/);

    const pending = await text(page, '#param-pending');
    expect(pending).toContain('press Generate key to apply');
    // It must name the key actually in play, not the selection.
    expect(pending).toContain(`n*=${applied.nStar}`);
    expect(pending).toContain(`K=${applied.K}`);
    expect(pending).toContain('base field');
    expect(pending).toContain('honest signer');

    // The panels below are unchanged — still the applied key.
    expect(await params(page)).toEqual(applied);

    // Reverting the selector clears the flag again.
    await page.selectOption(
      selector,
      selector === '#sel-nstar'
        ? String(applied.nStar)
        : selector === '#sel-k'
          ? String(applied.K)
          : selector === '#sel-field'
            ? 'base'
            : 'honest',
    );
    await expect(page.locator('#param-pending')).toHaveClass(/hidden/);
  }

  // Applying them for real clears the flag and rebuilds every panel.
  await generate(page, { nStar: 7, K: 4 });
  const next = await params(page);
  expect(next.nStar).toBe(7);
  expect(next.K).toBe(4);
  expect(next.M).toBe(8 * 4);
  await expect(page.locator('#panel-recover')).toHaveClass(/hidden/);
  expect(await text(page, '#cliff-status')).toMatch(/Secret undetermined/i);
});

// ─── 5. Controls stay alive ──────────────────────────────────────────────────

test('the grind stops at the cliff but nothing is left permanently dead', async ({ page }) => {
  await page.goto('.');
  await generate(page, { nStar: 1, K: 2 });
  await grindToCliff(page);

  // Grinding stops because the secret is already public — and says so.
  await expect(page.locator('#btn-grind')).toBeDisabled();
  expect(await page.getAttribute('#btn-grind', 'aria-disabled')).toBe('true');
  const atCliff = await meter(page);

  // Honest signing still works after the cliff; a repeat position adds nothing.
  await signOnce(page, 'after the cliff');
  const hint = await text(page, '#sign-hint');
  expect(hint).toMatch(/\+\d+ distinct/);
  expect(hint).toContain(`cliff reached: ${(await meter(page)).distinct} ≥ ${atCliff.needed}`);
  expect(await text(page, '.verdict')).toContain('EXACT MATCH');
  // The progressbar stays a valid one even past the cliff.
  expect(Number(await page.getAttribute('#meter', 'aria-valuenow'))).toBe(atCliff.needed);

  // A new key re-arms the grind.
  await generate(page, { nStar: 2, K: 3 });
  await expect(page.locator('#btn-grind')).toBeEnabled();
  expect((await meter(page)).distinct).toBe(1);
  await expect(page.locator('#btn-sign')).toBeEnabled();
  await expect(page.locator('#btn-export')).toBeEnabled();
});
