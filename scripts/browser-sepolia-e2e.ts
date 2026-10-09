import { chmod } from "node:fs/promises";
import { chromium, expect } from "@playwright/test";
import { isAddress } from "viem";
import { generatePrivateKey, mnemonicToAccount } from "viem/accounts";
import { createBurnerSession } from "../apps/web/src/burner";
const { readSafeWallet } = createBurnerSession();

let stage = "startup";
async function main() {
  if (process.env.BUNKER_E2E_LIVE !== "1" || process.env.BUNKER_BROWSER_E2E_LIVE !== "1" || process.env.BUNKER_SEPOLIA_CHAIN_ID !== "11155111") throw new Error("Browser Sepolia E2E is disabled.");
  const mnemonic = process.env.BUNKER_SEPOLIA_MNEMONIC;
  const manifestPath = process.env.BUNKER_SEPOLIA_MANIFEST;
  const url = process.env.BUNKER_BROWSER_E2E_URL ?? "http://127.0.0.1:4173";
  if (!mnemonic || !manifestPath || !/^http:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?$/.test(url)) throw new Error("Browser E2E configuration is invalid.");

  const vaultPassword = generatePrivateKey();
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.route("https://platform.twitter.com/**", route => route.abort());
  const forbiddenRequests: string[] = [];
  page.on("request", request => { if (!request.url().startsWith(url) && !request.url().startsWith("https://ethereum-sepolia-rpc.publicnode.com") && !/^(?:https:\/\/)?(?:platform\.twitter\.com|x\.com)\//.test(request.url())) forbiddenRequests.push(request.url()); });
  try {
    stage = "open-app";
    await page.goto(url, { waitUntil: "networkidle" });
    stage = "create-browser-mnemonic";
    await page.getByRole("button", { name: "Setup options" }).click();
    await page.getByRole("button", { name: /Recovery phrase/ }).click();
    await expect(page.getByRole("heading", { name: "Write down these 24 words." })).toBeVisible();
    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: "Skip check" }).click();
    await page.getByLabel(/Password · 12 characters minimum/).fill(vaultPassword);
    await page.getByRole("button", { name: "Encrypt and continue" }).click();
    await expect(page.getByRole("heading", { name: "Add Ethereum Sepolia test ETH." })).toBeVisible();
    const setupAddress = (await page.locator(".setup-address code").innerText()).trim();
    if (!isAddress(setupAddress)) throw new Error("Browser setup address is invalid.");

    stage = "fund-browser-setup";
    const funding = Bun.spawn(["bun", "run", "safe:sepolia:fund-browser"], {
      cwd: process.cwd(),
      env: { ...process.env, BUNKER_BROWSER_SETUP_ADDRESS: setupAddress },
      stdout: "pipe",
      stderr: "pipe",
    });
    if (await funding.exited !== 0) throw new Error("Protected setup funding failed.");

    stage = "verify-browser-funding";
    await page.getByRole("button", { name: "I funded it — check balance" }).click();
    await expect(page.getByRole("heading", { name: "Create your Safe wallet." })).toBeVisible({ timeout: 30_000 });
    stage = "deploy-browser-safe";
    await page.getByRole("button", { name: "Create guarded Safe" }).click();
    await expect(page.getByText("Ethereum Sepolia Safe · live")).toBeVisible({ timeout: 300_000 });
    const stableAddress = (await page.getByRole("button", { name: "Copy stable Safe address" }).locator("code").innerText()).trim();
    if (!isAddress(stableAddress)) throw new Error("Created Safe address is invalid.");
    await expect(page.getByText("Key 1", { exact: true })).toBeVisible();

    stage = "rotate-browser-safe";
    const recipient = mnemonicToAccount(mnemonic, { path: "m/44'/60'/7331'/0/101" }).address;
    for (const key of [2, 3]) {
      stage = `rotate-browser-safe-key-${key}`;
      await page.getByLabel("Recipient").fill(recipient);
      await page.getByLabel("Amount").fill("0.0001");
      await page.getByRole("button", { name: "Send + rotate key" }).click();
      await expect(page.getByText(`Key ${key}`, { exact: true })).toBeVisible({ timeout: 180_000 });
      const currentStable = (await page.getByRole("button", { name: "Copy stable Safe address" }).locator("code").innerText()).trim();
      if (currentStable.toLowerCase() !== stableAddress.toLowerCase()) throw new Error("Safe address changed during rotation.");
    }

    stage = "verify-encrypted-browser-storage";
    const vault = await page.evaluate(() => localStorage.getItem("bunker-vault"));
    if (!vault) throw new Error("Encrypted browser vault was not stored.");
    const envelope = JSON.parse(vault) as { kdf?: { name?: string }; cipher?: { name?: string; ciphertext?: string } };
    if (envelope.kdf?.name !== "argon2id" || envelope.cipher?.name !== "AES-256-GCM" || !/^[0-9a-f]+$/.test(envelope.cipher.ciphertext ?? "") || /\b(?:[a-z]+\s+){23}[a-z]+\b/.test(vault)) throw new Error("Stored browser vault is invalid.");

    stage = "reload-and-unlock-browser-vault";
    await page.reload({ waitUntil: "networkidle" });
    await page.getByRole("button", { name: "Setup options" }).click();
    await page.getByRole("button", { name: /Load existing wallet/ }).click();
    await page.getByLabel("Vault password").fill(vaultPassword);
    await page.getByRole("button", { name: "Load wallet" }).click();
    await expect(page.getByText("Ethereum Sepolia Safe · live")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText("Key 3", { exact: true })).toBeVisible();
    const restoredStable = (await page.getByRole("button", { name: "Copy stable Safe address" }).locator("code").innerText()).trim();
    if (restoredStable.toLowerCase() !== stableAddress.toLowerCase()) throw new Error("Restored Safe address mismatch.");

    stage = "rotate-restored-browser-safe";
    await page.getByLabel("Recipient").fill(recipient);
    await page.getByLabel("Amount").fill("0.0001");
    await page.getByRole("button", { name: "Send + rotate key" }).click();
    await expect(page.getByText("Key 4", { exact: true })).toBeVisible({ timeout: 180_000 });

    stage = "verify-browser-safe-chain";
    const state = await readSafeWallet(stableAddress);
    if (state.index !== 3) throw new Error("On-chain browser Safe rotation index mismatch.");
    stage = "verify-browser-origins";
    if (forbiddenRequests.length) throw new Error("Browser contacted an unexpected origin.");

    stage = "write-browser-evidence";
    const manifest = await Bun.file(manifestPath).json() as Record<string, unknown>;
    await Bun.write(manifestPath, JSON.stringify({ ...manifest, browserLifecycleCompletedAt: new Date().toISOString(), browserLifecycleResult: "pass", browserSafe: stableAddress, browserSafeRotationIndex: state.index, browserActions: 3, encryptedVaultRestored: true }, null, 2) + "\n");
    await chmod(manifestPath, 0o600);
    console.log("Browser Ethereum Sepolia Safe E2E passed.");
  } finally {
    await browser.close();
  }
}

main().catch(() => {
  console.error(`Browser Ethereum Sepolia Safe E2E failed at ${stage}.`);
  process.exit(1);
});
