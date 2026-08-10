import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this file
 *     replaces called `revealAll`, which stripped `.hidden` and `[hidden]` off
 *     every element and force-opened every `<details>`. On this lab that
 *     fabricates a page no visitor can reach: `#key-out`, `#param-pending` and
 *     the whole `#panel-recover` are `.hidden` until the run that fills them,
 *     so un-hiding them scans EMPTY containers dressed as populated ones —
 *     `#recover-out` is literally `innerHTML = ""` until the cliff fires. It
 *     never pressed a button, so it scanned one theme, one width, and a page
 *     with no key, no signature and no recovered secret on it.
 *
 *     It also carried a `checkGradientContrast` helper that read
 *     `getComputedStyle(body).color` against `getComputedStyle(body)
 *     .backgroundColor` — the flat token, with the two radial gradients it was
 *     named for explicitly reasoned away in its own comments — and a `scan`
 *     that computed an `incomplete` array and then never asserted on it. Both
 *     are gone; `auditContrast` samples the real gradient at the text's own
 *     position, and `incomplete` is asserted below.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Soft-gate collection mode.
 *
 * A gate that throws on the first finding tells you about one defect per run,
 * and a run of this suite is four full drives. With `A11Y_COLLECT=1` every
 * assertion in `scan` records its failure and continues, so one pass enumerates
 * everything wrong in all four configurations.
 *
 * The dangerous version of this idea is a check that merely logs. This one
 * cannot be mistaken for a passing gate: `reportCollected()` runs at the end of
 * every test and FAILS if a collecting run recorded anything at all. So the
 * only way a collecting run goes green is if there was nothing to collect, and
 * the only way to get a green gate is with the env var unset, where every
 * assertion is strict and throws where it stands.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

async function soft(fn: () => void | Promise<void>): Promise<void> {
  if (!COLLECTING) {
    await fn();
    return;
  }
  try {
    await fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    collected.push(message);
    console.log(`\n=== COLLECTED #${collected.length} ===\n${message}\n`);
  }
}

/**
 * Fail the test if a collecting run recorded anything. Call at the end of every
 * test — this is what stops a collection pass from ever reading as a pass.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(
    collected.length,
    `A11Y_COLLECT run recorded ${collected.length} findings (printed above). ` +
      'This mode never passes with findings; fix them and re-run without the env var.'
  ).toBe(0);
}

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead. This lab needs it: the meter fill
 * animates its width over 450ms and the cliff callout runs a 500ms `shake`, so
 * a scan fired straight after a signature reads a half-drawn meter.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * reduced-motion block collapses `animation-duration` to 0.001ms rather than
 * setting `animation: none`, so the `.shake` callout depends on its `both` fill
 * mode landing on a visible final keyframe. That is a real thing to check, not
 * a formality.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  // `index.html`'s anti-flash script stamps `data-theme` for both themes, so
  // the attribute is asserted directly either way.
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // ASSERT THE LAB'S DEFAULTS rather than assuming them, and they are not the
  // ones the markup suggests. `shell()` ships `#key-out` with `.hidden`,
  // `#ledger-out` reading "No signatures yet." and `#cliff-status` reading
  // "Generate a key to begin." — and none of those three states is ever on
  // screen, because `boot()` ends by calling `generate()`. A visitor's first
  // paint already has a random degree-11 key, an OOD freebie in the ledger and
  // the meter at 1/12. (The `flash("Generate a key first.")` branch in
  // `doSignHonest` is unreachable for the same reason: `key` is never null by
  // the time a button can be pressed. That is dead code, not a state, so this
  // drive does not pretend to scan it.)
  //
  // Which half of this lab a single-configuration gate scans depends entirely
  // on these, and the interesting branches — malicious signer, tower field,
  // K=16 — are all NOT the default, so the replaced gate never saw any of them.
  await expect(page.locator('h1')).toBeVisible();
  await expect(page.locator('#sel-nstar')).toHaveValue('3');
  await expect(page.locator('#sel-k')).toHaveValue('3');
  await expect(page.locator('#sel-field')).toHaveValue('base');
  await expect(page.locator('#sel-signer')).toHaveValue('honest');
  await expect(page.locator('#msg')).toHaveValue('release v1.0');
  await expect(page.locator('#key-out')).toBeVisible();
  await expect(page.locator('#key-out')).toContainText('budget n*');
  await expect(page.locator('#ledger-out')).toContainText('OOD freebie');
  await expect(page.locator('#cliff-status')).toContainText('Secret undetermined');
  await expect(page.locator('#meter-count')).toHaveText('1 / 12');
  await expect(page.locator('#sign-hint')).toBeEmpty();
  // These two really are hidden until something produces them.
  await expect(page.locator('#param-pending')).toBeHidden();
  await expect(page.locator('#panel-recover')).toBeHidden();
  await expect(page.locator('#btn-grind')).toBeEnabled();
  await expect(page.locator('.glossary')).not.toHaveAttribute('open', /.*/);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: the tower field prints 78-digit coefficients, the ledger
 * chips carry two field elements each, and the coefficient table is four
 * columns of them.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. This lab does not have
    // that rule today; the check detects the clipping directly anyway, so
    // adding one later cannot turn this oracle permanently green.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. The
    // coefficient table is 4 columns of 20-digit field elements inside
    // `.table-scroll { overflow-x: auto }`: it has a huge bounding rect and
    // contributes nothing to the document's scroll width, so naming it would
    // send you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll. `.table-scroll` already carries one;
 * this asserts that stays true, and catches any new scroller that does not.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Six assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `expectNotBlank` — nothing visible may render at effective opacity 0. This
 *    is the reduced-motion end-state check.
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all. The replaced gate built this array
 *    and then dropped it on the floor.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node,
 *    gradients and opacity groups included.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await soft(() => expectNotBlank(page, label));
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  await soft(() => expect(violations, `axe violations in state: ${label}`).toEqual([]));

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  await soft(() =>
    expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([])
  );

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  await soft(() => expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]));

  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

/** Generate a key with the selectors as they currently stand, and wait for it. */
async function generate(page: Page): Promise<void> {
  await page.locator('#btn-gen').click();
  await expect(page.locator('#key-out')).toBeVisible();
  await expect(page.locator('#key-out')).toContainText('budget n*');
  await expect(page.locator('#param-pending')).toBeHidden();
}

/**
 * Grind until the cliff fires, scanning every step.
 *
 * The number of grinds is not hard-coded: the meter's own `aria-valuetext` is
 * the completion signal, which is the point — a fixed count would silently stop
 * short if the arithmetic changed. Bounded so a bug cannot hang the suite.
 */
async function grindToCliff(page: Page, theme: string, tag: string): Promise<void> {
  const grind = page.locator('#btn-grind');
  for (let i = 0; i < 12; i++) {
    if (!(await grind.isEnabled())) break;
    const before = await page.locator('#meter-count').textContent();
    await grind.click();
    // `guard()` drops a click that lands while the previous run is in flight,
    // so wait for the ledger to actually move rather than for a duration.
    await expect(page.locator('#meter-count')).not.toHaveText(before ?? '');
    await scan(page, `${theme} / ${tag} / grind ${i + 1}`);
  }
  expect(await grind.isEnabled(), `${tag}: the grind must disable itself at the cliff`).toBe(false);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * The shape of the drive follows the shape of the lab: four selectors that are
 * INPUTS to Generate (not live controls), then a signing loop, then a cliff
 * that reveals a panel. The branches that matter are the ones off the default
 * path — a malicious signer escapes the cliff and renders a completely
 * different panel 04; the tower field swaps 20-digit numbers for 78-digit ones,
 * which is the reflow case; K=16 with n*=7 is the largest coefficient table the
 * page can produce and the only state that reaches the "… and N more" row.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint`);

  // --- Skip link: parked off-screen until focused. The focused rendering is a
  // real state and the contrast walk deliberately skips the parked one.
  await page.keyboard.press('Tab');
  await expect(page.locator('.cl-skip-link')).toBeFocused();
  await scan(page, `${theme} / skip link focused`);

  // --- Glossary <details>. Opened by clicking its summary, never by script:
  // forcing `open` skips the toggle the visitor actually performs.
  const glossary = page.locator('.glossary');
  await glossary.locator('summary').click();
  await expect(glossary).toHaveAttribute('open', /.*/);
  await scan(page, `${theme} / glossary open`);
  await glossary.locator('summary').click();
  await expect(glossary).not.toHaveAttribute('open', /.*/);
  await scan(page, `${theme} / glossary closed`);

  // --- Regenerate at the defaults. The page already booted with a key (see
  // `boot`), so this is the second key of the session and exercises the reset
  // path in `doGenerate` — the one that clears `#recover-out`, the export
  // verdict and `#sign-hint` — rather than the first-render path.
  await generate(page);
  await expect(page.locator('#cliff-status')).toContainText('Secret undetermined');
  await scan(page, `${theme} / key regenerated (defaults)`);

  // Honest signing, which may or may not add distinct points — either is a
  // state worth scanning, and the hint reports which happened.
  await page.locator('#btn-sign').click();
  await expect(page.locator('#sign-hint')).toContainText('Honest sign');
  await scan(page, `${theme} / one honest signature`);

  // An empty message: the lab substitutes "(empty)" rather than refusing.
  await page.locator('#msg').fill('');
  await page.locator('#btn-sign').click();
  await expect(page.locator('#sign-hint')).toContainText('Honest sign');
  await scan(page, `${theme} / honest signature, empty message`);

  // A long message, which is what stresses the hint line and the ledger tag at
  // 380px — the ledger prints the message back verbatim.
  await page.locator('#msg').fill('a'.repeat(120));
  await page.locator('#btn-sign').click();
  await expect(page.locator('#ledger-out')).toContainText('aaaaaaaaaa');
  await scan(page, `${theme} / honest signature, 120-char message`);
  await page.locator('#msg').fill('release v1.0');

  // --- The pending-parameters note: a `.hidden` `role="status"` that exists
  // only after a selector is moved away from the key in play.
  await page.locator('#sel-nstar').selectOption('1');
  await expect(page.locator('#param-pending')).toBeVisible();
  await expect(page.locator('#param-pending')).toContainText('Parameters changed');
  await scan(page, `${theme} / parameters pending`);

  // Moving it back must retract the note — the other half of the branch.
  await page.locator('#sel-nstar').selectOption('3');
  await expect(page.locator('#param-pending')).toBeHidden();
  await scan(page, `${theme} / parameters back in sync`);

  // --- Drive to the cliff, scanning every grind, then the revealed panel 04.
  await grindToCliff(page, theme, 'defaults');
  await expect(page.locator('#panel-recover')).toBeVisible();
  await expect(page.locator('#recover-out')).toContainText('EXACT MATCH');
  await expect(page.locator('.table-scroll')).toBeVisible();
  await scan(page, `${theme} / cliff reached, secret recovered`);

  // The grind is now disabled: a distinct rendering (opacity .45) that only
  // exists past the cliff.
  await expect(page.locator('#btn-grind')).toBeDisabled();
  await page.locator('#btn-sign').click();
  await expect(page.locator('#sign-hint')).toContainText('Honest sign');
  await scan(page, `${theme} / honest signature past the cliff`);

  // --- Export: verifies the transcript in-page and writes a verdict.
  const download = page.waitForEvent('download');
  await page.locator('#btn-export').click();
  await download;
  await expect(page.locator('#export-result')).toContainText('Verified');
  await scan(page, `${theme} / transcript exported and verified`);

  // Signing again retires that verdict — a third state of the same element.
  await page.locator('#btn-sign').click();
  await expect(page.locator('#export-result')).toContainText('ledger has changed');
  await scan(page, `${theme} / export verdict retired`);

  // --- Malicious signer: the cliff fires and recovers the WRONG polynomial, so
  // panel 04 renders an entirely different subtree (no table, an "escaped"
  // verdict) and the meter's own aria-valuetext changes. None of this is
  // reachable from the shipped defaults.
  await page.locator('#sel-signer').selectOption('malicious');
  await generate(page);
  await expect(page.locator('#key-out')).toContainText('Malicious signer');
  await scan(page, `${theme} / malicious key generated`);
  await grindToCliff(page, theme, 'malicious');
  await expect(page.locator('#recover-out')).toContainText('SIGNER ESCAPED');
  await expect(page.locator('#cliff-status')).toContainText('the key escaped');
  await scan(page, `${theme} / malicious signer escaped the cliff`);

  // --- Tower field: 78-digit coefficients everywhere. This is the reflow case.
  await page.locator('#sel-signer').selectOption('honest');
  await page.locator('#sel-field').selectOption('tower');
  await generate(page);
  await expect(page.locator('#key-out')).toContainText('tower');
  await scan(page, `${theme} / tower field key`);
  await grindToCliff(page, theme, 'tower');
  await expect(page.locator('#recover-out')).toContainText('EXACT MATCH');
  await scan(page, `${theme} / tower field, secret recovered`);

  // --- The extremes of both numeric selectors together: n*=7, K=16 is the
  // largest key this page can build (M = 128 coefficients), the only state that
  // reaches the coefficient table's "… and N more" row, and the longest grind.
  await page.locator('#sel-field').selectOption('base');
  await page.locator('#sel-nstar').selectOption('7');
  await page.locator('#sel-k').selectOption('16');
  await generate(page);
  await expect(page.locator('#key-out')).toContainText('128');
  await scan(page, `${theme} / n*=7 K=16 (largest key)`);

  // --- And the smallest: n*=1, K=2, the paper's Figure 1.
  await page.locator('#sel-nstar').selectOption('1');
  await page.locator('#sel-k').selectOption('2');
  await generate(page);
  await scan(page, `${theme} / n*=1 K=2 (paper Figure 1)`);
  await grindToCliff(page, theme, 'minimal');
  await scan(page, `${theme} / minimal params, secret recovered`);
}
