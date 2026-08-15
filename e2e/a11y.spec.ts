import { test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
} from './gate';

/**
 * WCAG A/AA regression gate. Deploys are already gated on the crypto KATs; this
 * gates them on accessibility the same way.
 *
 * Four configurations — {dark, light} x {1280, 380} — because a single-theme,
 * single-viewport scan covers one quarter of what ships, and which quarter
 * depends on defaults nobody asserted. Each configuration generates keys,
 * signs, grinds to the cliff, exports, and walks the malicious-signer and
 * tower-field branches, scanning after every step. See `gate.ts` for why
 * nothing is injected into the page, why each scan asserts its content first,
 * and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(600_000);
    page.setDefaultTimeout(20_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(600_000);
    page.setDefaultTimeout(20_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
    reportCollected();
  });
}
