import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG A/AA regression gate. Deploys are already gated on the crypto
 * KATs; this gates them on accessibility the same way. Scans the full page in
 * both themes, with every collapsible/hidden region revealed so axe sees the
 * content it would otherwise skip.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animations/transitions/opacity so nothing is mid-fade when axe
// samples colors (a half-faded element reads as a contrast failure).
const STATIC_STYLE = `
  *, *::before, *::after {
    animation-duration: 0s !important;
    animation-delay: 0s !important;
    transition-duration: 0s !important;
    transition-delay: 0s !important;
  }
`;

async function revealAll(page: Page): Promise<void> {
  await page.addStyleTag({ content: STATIC_STYLE });
  await page.evaluate(() => {
    // Expand every <details>.
    for (const d of Array.from(document.querySelectorAll('details'))) {
      (d as HTMLDetailsElement).open = true;
    }
    // Reveal class/attribute-hidden panels so their content is scannable.
    for (const el of Array.from(document.querySelectorAll<HTMLElement>('.hidden, [hidden]'))) {
      el.classList.remove('hidden');
      el.removeAttribute('hidden');
      if (el.style.display === 'none') el.style.display = '';
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await scan(page);
});
