import { expect, test, type Page } from '@playwright/test';

// Serve local built assets at an exact public hostname; never submit a hosted transaction.
async function localPreview(page: Page, host: string) {
  await page.route(`https://${host}/**`, async (route) => {
    const url = new URL(route.request().url());
    const upstream = await route.fetch({
      url: `http://127.0.0.1:4180${url.pathname}${url.search}`,
    });
    await route.fulfill({ response: upstream });
  });
  await page.route('https://platform.twitter.com/**', (route) => route.abort());
}

for (const host of ['bunker-wallet-pq-sepolia-test.pages.dev', 'bunker.supplies']) {
  test(`production build enables exact-host testnet UI at ${host}`, async ({ page }) => {
    await localPreview(page, host);
    await page.goto(`https://${host}/`);
    await expect(page.getByRole('button', { name: 'Create wallet (Testnet)' })).toBeVisible();
    await expect(page.getByText('Sepolia testnet · Unaudited · Test ETH only')).toBeVisible();
    await page.getByRole('button', { name: 'Create wallet (Testnet)' }).click();
    for (const mode of ['Standard', 'Quantum Shield', 'Maximum'] as const)
      await expect(page.getByRole('button', { name: `Select ${mode}` })).toBeVisible();
    await page.getByRole('button', { name: 'Recover wallet' }).click();
    await expect(page.getByRole('heading', { name: 'Recover your wallet.' })).toBeVisible();
  });

  for (const [kind, key] of [
    ['Standard', 'bunker-vault'],
    ['PQ', 'bunker-experimental-wallet-v1'],
  ] as const)
    test(`production build opens ${kind} recovery at ${host}`, async ({ page }) => {
      await localPreview(page, host);
      await page.addInitScript(
        ([hostname, storageKey]) => {
          if (location.hostname === hostname)
            localStorage.setItem(storageKey, '{"synthetic":true}');
        },
        [host, key] as const,
      );
      await page.goto(`https://${host}/`);
      await expect(page.getByRole('heading', { name: 'Recover your wallet.' })).toBeVisible();
      expect(await page.evaluate((storageKey) => localStorage.getItem(storageKey), key)).toBe(
        '{"synthetic":true}',
      );
    });
}

for (const host of ['sub.bunker.supplies', 'bunker.supplies.evil.example'])
  test(`production build rejects ${host}`, async ({ page }) => {
    await localPreview(page, host);
    await page.goto(`https://${host}/`);
    await expect(page.getByRole('button', { name: 'Try It (Simulation)' }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create wallet (Testnet)' })).toHaveCount(0);
  });
