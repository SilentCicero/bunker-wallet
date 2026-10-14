import { test, expect, type Page } from '@playwright/test';
import {
  createPublicClient,
  createWalletClient,
  http,
  parseEther,
  parseAbi,
  keccak256,
  type Address,
  type Hex,
} from 'viem';
import { mnemonicToAccount, privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';
import {
  bunkerGuardAbi as standardGuardABI,
  bunkerGuardRuntimeHash,
} from '../../apps/web/src/safeArtifactsV3';
import fixture from '../fixtures/sepolia-safe-1.4.1.json';

// Transactional browser QA is disposable Anvil only. Never publish phrases or run against public Sepolia.
const enabled = process.env.BROWSER_V3_LIFECYCLE === '1',
  rpc = 'http://127.0.0.1:18545';
const client = createPublicClient({ chain: sepolia, transport: http(rpc), pollingInterval: 100 });
const safeABI = parseAbi([
  'function getOwners() view returns(address[])',
  'function getThreshold() view returns(uint256)',
  'function getModulesPaginated(address,uint256) view returns(address[],address)',
]);
const factoryABI = parseAbi([
  'function guard() view returns(address)',
  'function factoryVersion() view returns(uint256)',
]);
const pqGuardABI = parseAbi([
  'function state(address) view returns(address,address,uint8,bool,address,address,bytes32,uint8)',
]);
const sentinel = '0x0000000000000000000000000000000000000001' as Address;
let faucet: ReturnType<typeof privateKeyToAccount>, v3Factory: Address, v3Guard: Address;
test.use({ trace: 'off' });
test.describe.configure({ mode: 'serial' });
test.setTimeout(180000);
test.beforeAll(async () => {
  if (!enabled) return;
  expect(await client.getChainId()).toBe(11155111);
  const key = process.env.LOCAL_FAUCET_PRIVATE_KEY as Hex | undefined;
  if (!key || !/^0x[0-9a-fA-F]{64}$/.test(key))
    throw new Error('Use ephemeral Anvil faucet key only');
  faucet = privateKeyToAccount(key);
  for (const code of Object.values(fixture.codes))
    await client.request({
      method: 'anvil_setCode' as never,
      params: [code.address, code.runtime] as never,
    });
  v3Factory = process.env.VITE_EXPERIMENTAL_V3_LOCAL_FACTORY as Address;
  if (!v3Factory || !(await client.getCode({ address: v3Factory })))
    throw new Error('Missing disposable V3 factory');
  expect(
    await client.readContract({
      address: v3Factory,
      abi: factoryABI,
      functionName: 'factoryVersion',
    }),
  ).toBe(3n);
  v3Guard = await client.readContract({
    address: v3Factory,
    abi: factoryABI,
    functionName: 'guard',
  });
});

async function create(page: Page, mode: 'Standard' | 'Quantum Shield' | 'Maximum') {
  await page.goto('/');
  await page.getByRole('button', { name: 'Create wallet (Testnet)' }).click();
  await page.getByRole('button', { name: `Select ${mode}` }).click();
  await page.getByRole('button', { name: 'Create wallet', exact: true }).click();
  const phrase = (await page.locator('.words li').allTextContents())
    .map((word) => word.replace(/^\d+/, ''))
    .join(' ');
  await page.getByRole('checkbox', { name: 'I saved the phrase offline.' }).check();
  await page.getByRole('button', { name: 'Skip check' }).click();
  if (mode === 'Standard')
    await page.getByRole('button', { name: 'Continue without password' }).click();
  else {
    await page.getByLabel('Password · 12 characters minimum').fill('public-test-password');
    await page.getByRole('button', { name: 'Encrypt and save this browser' }).click();
  }
  const panel =
    mode === 'Standard'
      ? page.locator('.setup')
      : page.getByRole('region', { name: 'Experimental PQ wallet' });
  const setup = (await panel
    .getByText('Setup address', { exact: true })
    .locator('..')
    .locator('code')
    .textContent()) as Address;
  expect(setup).toMatch(/^0x[0-9a-fA-F]{40}$/);
  const receipt = await client.waitForTransactionReceipt({
    hash: await createWalletClient({
      account: faucet,
      chain: sepolia,
      transport: http(rpc),
    }).sendTransaction({ to: setup, value: parseEther('0.08') }),
  });
  expect(receipt.status).toBe('success');
  await panel.getByRole('button', { name: 'I funded it — check balance' }).click();
  await panel.getByRole('button', { name: 'Create Safe wallet' }).click();
  if (mode === 'Standard')
    await expect(page.getByText('Ethereum Sepolia Safe · live')).toBeVisible({ timeout: 90000 });
  else
    await expect(panel.getByRole('button', { name: 'Send + rotate key' })).toBeEnabled({
      timeout: 90000,
    });
  const safe = (
    mode === 'Standard'
      ? await page
          .getByRole('button', { name: 'Copy stable Safe address' })
          .locator('code')
          .textContent()
      : await page.evaluate(
          () => JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!).safe,
        )
  ) as Address;
  expect(safe).toMatch(/^0x[0-9a-fA-F]{40}$/);
  if (mode !== 'Standard') {
    const record = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!),
    );
    expect(record.parts.ExperimentalSharedFactoryV3?.toLowerCase()).toBe(v3Factory.toLowerCase());
    expect(record.parts.ExperimentalSharedFactoryV2).toBeUndefined();
  }
  return { phrase, safe };
}
async function onchain(
  safe: Address,
  mode: 'Standard' | 'Quantum Shield' | 'Maximum',
  index: number,
  phrase: string,
) {
  const owners = await client.readContract({
    address: safe,
    abi: safeABI,
    functionName: 'getOwners',
  });
  const threshold = await client.readContract({
    address: safe,
    abi: safeABI,
    functionName: 'getThreshold',
  });
  const [modules, cursor] = await client.readContract({
    address: safe,
    abi: safeABI,
    functionName: 'getModulesPaginated',
    args: [sentinel, 1n],
  });
  expect(modules).toHaveLength(0);
  expect(cursor.toLowerCase()).toBe(sentinel.toLowerCase());
  expect(owners[0]?.toLowerCase()).toBe(
    mnemonicToAccount(phrase, { path: `m/44'/60'/7331'/0/${index}` }).address.toLowerCase(),
  );
  expect(owners).toHaveLength(mode === 'Standard' ? 1 : 2);
  expect(threshold).toBe(mode === 'Standard' ? 1n : 2n);
  const slot = await client.getStorageAt({
    address: safe,
    slot: '0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8',
  });
  expect(slot).toBeTruthy();
  const guard = `0x${slot!.slice(-40)}` as Address;
  if (mode === 'Standard') {
    expect(keccak256((await client.getCode({ address: guard }))!)).toBe(bunkerGuardRuntimeHash);
    const state = await client.readContract({
      address: guard,
      abi: standardGuardABI,
      functionName: 'state',
      args: [safe],
    });
    expect(Number(state[1])).toBe(index);
  } else {
    expect(guard.toLowerCase()).toBe(v3Guard.toLowerCase());
    const state = (await client.readContract({
      address: guard,
      abi: pqGuardABI,
      functionName: 'state',
      args: [safe],
    })) as unknown as readonly unknown[];
    expect(Number(state[2])).toBe(index);
  }
  return owners;
}
async function send(
  page: Page,
  mode: 'Standard' | 'Quantum Shield' | 'Maximum',
  safe: Address,
  phrase: string,
  index: number,
  pqOwner?: Address,
) {
  // Any local test broadcaster may need extra gas at higher simulated fee estimates.
  const broadcaster = mnemonicToAccount(phrase, { path: `m/44'/60'/7331'/0/${index}` }).address;
  await client.request({
    method: 'anvil_setBalance' as never,
    params: [broadcaster, '0x2386f26fc10000'] as never,
  });
  const panel =
    mode === 'Standard'
      ? page.locator('.wallet')
      : page.getByRole('region', { name: 'Experimental PQ wallet' });
  await panel
    .getByLabel(mode === 'Standard' ? 'Recipient' : 'Recipient address')
    .fill('0x000000000000000000000000000000000000cafe');
  await panel.getByLabel(mode === 'Standard' ? 'Amount' : 'Test ETH amount').fill('0.0001');
  const before = await client.getBalance({ address: safe });
  await panel.getByRole('button', { name: 'Send + rotate key' }).click();
  if (mode === 'Standard')
    await expect(panel.locator('.rotation-card strong')).toContainText(`Key ${index + 2}`, {
      timeout: 60000,
    });
  else
    await expect(panel.getByText(`Key ${index + 2} → Key ${index + 3}`)).toBeVisible({
      timeout: 60000,
    });
  const owners = await onchain(safe, mode, index + 1, phrase);
  if (pqOwner) expect(owners[1]?.toLowerCase()).toBe(pqOwner.toLowerCase());
  expect(await client.getBalance({ address: safe })).toBe(before - parseEther('0.0011'));
  return owners[1];
}
async function recover(
  page: Page,
  mode: 'Standard' | 'Quantum Shield' | 'Maximum',
  safe: Address,
  phrase: string,
) {
  // A fresh browser-local state exercises phrase + on-chain Safe recovery, not saved-vault unlock.
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
  await page.reload();
  await page.getByRole('button', { name: 'Recover wallet' }).click();
  const screen = page.locator('.recover-screen');
  await screen.getByLabel('24-word recovery phrase').fill(phrase);
  await screen.getByLabel('Existing Safe address').fill(safe);
  await screen.getByLabel('Browser password · 12–256 characters').fill('public-test-password');
  await screen.getByRole('button', { name: 'Recover and save wallet' }).click();
  if (mode === 'Standard')
    await expect(page.getByText('Ethereum Sepolia Safe · live')).toBeVisible({ timeout: 90000 });
  else {
    const panel = page.getByRole('region', { name: 'Experimental PQ wallet' });
    await expect(panel.getByRole('button', { name: 'Send + rotate key' })).toBeEnabled({
      timeout: 90000,
    });
    const record = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!),
    );
    expect(record.parts.ExperimentalSharedFactoryV3?.toLowerCase()).toBe(v3Factory.toLowerCase());
  }
}
for (const mode of ['Standard', 'Quantum Shield', 'Maximum'] as const)
  test(`V3 ${mode}: create → send twice → phrase recovery → send twice`, async ({ page }) => {
    test.skip(!enabled);
    const { phrase, safe } = await create(page, mode);
    const initial = await onchain(safe, mode, 0, phrase);
    const pq = mode === 'Standard' ? undefined : initial[1];
    for (let index = 0; index < 2; index++) await send(page, mode, safe, phrase, index, pq);
    await recover(page, mode, safe, phrase);
    await onchain(safe, mode, 2, phrase);
    for (let index = 2; index < 4; index++) await send(page, mode, safe, phrase, index, pq);
    expect((await onchain(safe, mode, 4, phrase))[0]).toBeTruthy();
    const slot = '0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8' as Hex;
    const installed = await client.getStorageAt({ address: safe, slot });
    expect(installed).toBeTruthy();
    await client.request({
      method: 'anvil_setStorageAt' as never,
      params: [safe, slot, `0x${'00'.repeat(32)}`] as never,
    });
    try {
      await page.evaluate(() => {
        localStorage.clear();
        sessionStorage.clear();
      });
      await page.reload();
      await page.getByRole('button', { name: 'Recover wallet' }).click();
      const screen = page.locator('.recover-screen');
      await screen.getByLabel('24-word recovery phrase').fill(phrase);
      await screen.getByLabel('Existing Safe address').fill(safe);
      await screen.getByLabel('Browser password · 12–256 characters').fill('public-test-password');
      await screen.getByRole('button', { name: 'Recover and save wallet' }).click();
      await expect(page.getByRole('status')).toContainText('Safe has no supported guard', {
        timeout: 30000,
      });
      expect(
        await page.evaluate(() => [
          localStorage.getItem('bunker-safe-wallet'),
          localStorage.getItem('bunker-experimental-wallet-v1'),
        ]),
      ).toEqual([null, null]);
    } finally {
      await client.request({
        method: 'anvil_setStorageAt' as never,
        params: [safe, slot, installed!] as never,
      });
    }
    await onchain(safe, mode, 4, phrase);
    if (mode === 'Quantum Shield') {
      const original = (await client.getCode({ address: v3Factory }))!;
      await client.request({
        method: 'anvil_setCode' as never,
        params: [v3Factory, '0x6000'] as never,
      });
      try {
        await page.reload();
        await page.getByRole('button', { name: 'Recover wallet' }).click();
        const screen = page.locator('.recover-screen');
        await screen.getByLabel('24-word recovery phrase').fill(phrase);
        await screen.getByLabel('Existing Safe address').fill(safe);
        await screen
          .getByLabel('Browser password · 12–256 characters')
          .fill('public-test-password');
        await screen.getByRole('button', { name: 'Recover and save wallet' }).click();
        await expect(page.getByRole('status')).toBeVisible({ timeout: 30000 });
        expect(
          await page.evaluate(() => localStorage.getItem('bunker-experimental-wallet-v1')),
        ).toBeNull();
      } finally {
        await client.request({
          method: 'anvil_setCode' as never,
          params: [v3Factory, original] as never,
        });
      }
      await recover(page, mode, safe, phrase);
      await onchain(safe, mode, 4, phrase);
    }
  });

async function lock(page: Page, mode: 'Standard' | 'Quantum Shield' | 'Maximum', reload = true) {
  await (
    mode === 'Standard'
      ? page.getByRole('button', { name: 'Lock', exact: true })
      : page
          .getByRole('region', { name: 'Experimental PQ wallet' })
          .getByRole('button', { name: 'Lock / cancel' })
  ).click();
  await expect(page.getByRole('heading', { name: 'One address. Fresh keys.' })).toBeVisible();
  if (reload) await page.reload();
}
async function savedOption(page: Page, mode: 'Standard' | 'Quantum Shield' | 'Maximum') {
  await page.getByRole('button', { name: 'Setup options' }).click();
  await page.getByRole('button', { name: `Select ${mode}` }).click();
  return page.getByRole('group', {
    name: mode === 'Standard' ? 'Saved Standard setup' : 'Replace saved test wallet',
  });
}
for (const mode of ['Standard', 'Quantum Shield', 'Maximum'] as const)
  test(`V3 ${mode}: exit → cancel → recover → delete locally → create new`, async ({ page }) => {
    test.skip(!enabled);
    const { phrase, safe } = await create(page, mode),
      oldCode = await client.getCode({ address: safe });
    await onchain(safe, mode, 0, phrase);
    await lock(page, mode);
    const oldStorage = await page.evaluate(() =>
      [
        'bunker-vault',
        'bunker-safe-wallet',
        'bunker-standard-setup-v1',
        'bunker-experimental-wallet-v1',
        'bunker-experimental-vault-v1',
      ].map((key) => localStorage.getItem(key)),
    );
    let broadcasts = 0;
    await page.context().route(
      (url) => url.origin === rpc,
      async (route) => {
        if (route.request().postDataJSON()?.method === 'eth_sendRawTransaction') broadcasts++;
        await route.continue();
      },
    );
    let option = await savedOption(page, mode);
    await expect(option).toBeVisible({ timeout: 30000 });
    if (mode === 'Standard')
      await option.getByRole('button', { name: 'Delete local Standard data & create new' }).click();
    await option.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('heading', { name: 'One address. Fresh keys.' })).toBeVisible();
    expect(
      await page.evaluate(() =>
        [
          'bunker-vault',
          'bunker-safe-wallet',
          'bunker-standard-setup-v1',
          'bunker-experimental-wallet-v1',
          'bunker-experimental-vault-v1',
        ].map((key) => localStorage.getItem(key)),
      ),
    ).toEqual(oldStorage);
    option = await savedOption(page, mode);
    await option.getByRole('button', { name: 'Recover wallet' }).click();
    const screen = page.locator('.recover-screen');
    await screen.getByLabel('24-word recovery phrase').fill(phrase);
    await screen.getByLabel('Existing Safe address').fill(safe);
    await screen.getByLabel('Browser password · 12–256 characters').fill('public-test-password');
    await screen.getByRole('button', { name: 'Recover and save wallet' }).click();
    if (mode === 'Standard')
      await expect(page.getByText('Ethereum Sepolia Safe · live')).toBeVisible({ timeout: 90000 });
    else
      await expect(
        page
          .getByRole('region', { name: 'Experimental PQ wallet' })
          .getByRole('button', { name: 'Send + rotate key' }),
      ).toBeEnabled({ timeout: 90000 });
    await onchain(safe, mode, 0, phrase);
    await lock(page, mode, false); // Exercise immediate exit → replacement without a reload.
    option = await savedOption(page, mode);
    await expect(option).toBeVisible({ timeout: 30000 });
    if (mode === 'Standard')
      await option.getByRole('button', { name: 'Delete local Standard data & create new' }).click();
    const confirmation =
      mode === 'Standard' ? option : page.getByRole('group', { name: 'Replace saved test wallet' });
    if (mode === 'Standard') {
      await page.setViewportSize({ width: 320, height: 700 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(320);
      await page.setViewportSize({ width: 1366, height: 768 });
    }
    await confirmation.getByRole('checkbox').check();
    await confirmation
      .getByRole('button', {
        name:
          mode === 'Standard'
            ? 'Delete local data & create new'
            : 'Continue — replace local wallet',
      })
      .click();
    await expect(page.getByRole('heading', { name: 'Write down these 24 words.' })).toBeVisible();
    if (mode === 'Standard')
      expect(
        await page.evaluate(() => sessionStorage.getItem('bunker-unlocked-wallet') === null),
      ).toBe(true);
    const nextPhrase = (await page.locator('.words li').allTextContents())
      .map((word) => word.replace(/^\d+/, ''))
      .join(' ');
    expect(nextPhrase).not.toBe(phrase);
    expect(await client.getCode({ address: safe })).toBe(oldCode);
    await onchain(safe, mode, 0, phrase);
    expect(broadcasts).toBe(0);
    await page.getByRole('checkbox', { name: 'I saved the phrase offline.' }).check();
    await page.getByRole('button', { name: 'Skip check' }).click();
    await page.getByLabel('Password · 12 characters minimum').fill('public-test-password');
    await page.getByRole('button', { name: 'Encrypt and save this browser' }).click();
    const newSetup = (await (
      mode === 'Standard'
        ? page.locator('.setup')
        : page.getByRole('region', { name: 'Experimental PQ wallet' })
    )
      .getByText('Setup address', { exact: true })
      .locator('..')
      .locator('code')
      .textContent()) as Address;
    expect(newSetup.toLowerCase()).not.toBe(
      mnemonicToAccount(phrase, { path: "m/44'/60'/7331'/0/0" }).address.toLowerCase(),
    );
    await page.reload();
    if (mode === 'Standard')
      await expect(page.locator('.setup').getByText('Setup address', { exact: true })).toBeVisible({
        timeout: 30000,
      });
    else {
      await page.getByLabel('Experimental vault password').fill('public-test-password');
      await page.getByRole('button', { name: 'Recover saved wallet' }).click();
      await expect(
        page
          .getByRole('region', { name: 'Experimental PQ wallet' })
          .getByText('Setup address', { exact: true }),
      ).toBeVisible({ timeout: 30000 });
    }
    expect(broadcasts).toBe(0);
    expect(await client.getCode({ address: safe })).toBe(oldCode);
  });

test('V3 unfinished Standard setup can be cancelled, resumed, then locally replaced', async ({
  page,
}) => {
  test.skip(!enabled);
  await page.goto('/');
  await page.getByRole('button', { name: 'Create wallet (Testnet)' }).click();
  await page.getByRole('button', { name: 'Create wallet', exact: true }).click();
  await page.getByRole('checkbox', { name: 'I saved the phrase offline.' }).check();
  await page.getByRole('button', { name: 'Skip check' }).click();
  await page.getByLabel('Password · 12 characters minimum').fill('public-test-password');
  await page.getByRole('button', { name: 'Encrypt and save this browser' }).click();
  const first = await page
    .locator('.setup')
    .getByText('Setup address', { exact: true })
    .locator('..')
    .locator('code')
    .textContent();
  let broadcasts = 0;
  await page.context().route(
    (url) => url.origin === rpc,
    async (route) => {
      if (route.request().postDataJSON()?.method === 'eth_sendRawTransaction') broadcasts++;
      await route.continue();
    },
  );
  await lock(page, 'Standard');
  let option = await savedOption(page, 'Standard');
  await option.getByRole('button', { name: 'Cancel' }).click();
  option = await savedOption(page, 'Standard');
  await option.getByRole('button', { name: 'Recover wallet' }).click();
  await page.getByLabel('Standard vault password').fill('public-test-password');
  await page.getByRole('button', { name: 'Recover saved wallet' }).click();
  await expect(page.locator('.setup').getByText('Setup address', { exact: true })).toBeVisible();
  await lock(page, 'Standard', false);
  option = await savedOption(page, 'Standard');
  await option.getByRole('button', { name: 'Delete local Standard data & create new' }).click();
  await option.getByRole('checkbox').check();
  await option.getByRole('button', { name: 'Delete local data & create new' }).click();
  await expect(page.getByRole('heading', { name: 'Write down these 24 words.' })).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('bunker-standard-setup-v1') === null)).toBe(
    true,
  );
  await page.getByRole('checkbox', { name: 'I saved the phrase offline.' }).check();
  await page.getByRole('button', { name: 'Skip check' }).click();
  await page.getByLabel('Password · 12 characters minimum').fill('public-test-password');
  await page.getByRole('button', { name: 'Encrypt and save this browser' }).click();
  const second = await page
    .locator('.setup')
    .getByText('Setup address', { exact: true })
    .locator('..')
    .locator('code')
    .textContent();
  expect(second).not.toBe(first);
  expect(broadcasts).toBe(0);
});

test('V3 uncertain Standard deployment and pending PQ intent refuse replacement', async ({
  page,
}) => {
  test.skip(!enabled);
  const { phrase, safe } = await create(page, 'Standard');
  await lock(page, 'Standard');
  await page.evaluate(
    (address) =>
      localStorage.setItem(
        'bunker-standard-setup-v1',
        JSON.stringify({ version: 1, state: 'deploying', address }),
      ),
    mnemonicToAccount(phrase, { path: "m/44'/60'/7331'/0/0" }).address,
  );
  await page.reload();
  const standard = await savedOption(page, 'Standard');
  await expect(standard).toContainText('outcome uncertain');
  await expect(standard.getByRole('button', { name: /Delete local/ })).toHaveCount(0);
  await standard.getByRole('button', { name: 'Cancel' }).click();
  await onchain(safe, 'Standard', 0, phrase);
  await page.evaluate(() => localStorage.removeItem('bunker-standard-setup-v1')); // Remove only the synthetic uncertain journal.
  const pq = await create(page, 'Quantum Shield');
  await lock(page, 'Quantum Shield');
  const original = await page.evaluate(() => {
    const record = JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!);
    record.pending = {
      kind: 'send',
      hash: '0x' + 'ab'.repeat(32),
      sealed: { ciphertext: 'test-only' },
    };
    const raw = JSON.stringify(record);
    localStorage.setItem('bunker-experimental-wallet-v1', raw);
    return raw;
  });
  await page.reload();
  await savedOption(page, 'Quantum Shield');
  await expect(page.getByRole('group', { name: 'Pending saved experimental setup' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Continue — replace local wallet' })).toHaveCount(
    0,
  );
  expect(await page.evaluate(() => localStorage.getItem('bunker-experimental-wallet-v1'))).toBe(
    original,
  );
  await onchain(pq.safe, 'Quantum Shield', 0, pq.phrase);
});
