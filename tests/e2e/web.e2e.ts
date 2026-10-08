import { mkdirSync } from "node:fs";
import { expect, test } from "@playwright/test";

const views = [
  ["desktop", 1440, 900],
  ["wide", 1920, 1080],
  ["tablet", 768, 1024],
  ["mobile", 390, 844],
  ["mobile-small", 360, 800],
] as const;

test.beforeAll(() => mkdirSync(".impeccable/review", { recursive: true }));
test.beforeEach(async ({ page }) => {
  await page.route("https://platform.twitter.com/widgets.js", route => route.fulfill({ contentType: "application/javascript", body: "" }));
});

for (const [name, width, height] of views) {
  test(`${name} landing renders in both themes`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /One address.*Fresh keys/s })).toBeVisible();
    await expect(page.getByRole("button", { name: "Try it" }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: "Use Ethereum Sepolia (Soon)" })).toBeDisabled();
    await expect(page.getByText(/reducing exposure to future quantum attacks/)).toBeVisible();
    await expect(page.getByText("Rotate the keys.")).toBeVisible();
    await expect(page.locator(".roadmap h2")).toBeVisible();
    await expect(page.getByText("MIT open source")).toBeVisible();
    await expect(page.getByText("External perspective")).toBeVisible();
    await expect(page.getByRole("link", { name: "Open directly on X →" })).toHaveAttribute("href", "https://x.com/drakefjustin/status/2107837081313505768");
    await expect(page.getByRole("link", { name: /View the source/ })).toHaveAttribute("href", "https://github.com/SilentCicero/bunker-wallet");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: `.impeccable/review/${name}-light.png`, fullPage: true });
    await page.getByRole("button", { name: "Use dark mode" }).click();
    await page.screenshot({ path: `.impeccable/review/${name}-dark.png`, fullPage: true });
  });
}

test("local preview rotates without blockchain access", async ({ page }) => {
  const blockchainRequests: string[] = [];
  page.on("request", request => { if (/ethereum-sepolia-rpc|cloud\.google\.com\/application\/web3\/faucet/.test(request.url())) blockchainRequests.push(request.url()); });
  await page.goto("/");
  await page.getByRole("button", { name: "Try it" }).first().click();
  await expect(page.getByText("Local preview · simulated, not broadcast")).toBeVisible();
  await expect(page.getByText(/BIP-39 → hardened BIP-32/)).toBeVisible();
  expect(await page.evaluate(() => Object.keys(localStorage).every(key => !/mnemonic|seed|phrase/i.test(key)))).toBe(true);
  await expect(page.getByRole("button", { name: "Copy stable Safe address" })).toBeVisible();
  await expect(page.locator(".address-copy")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Token" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Wall", exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Recipient")).toHaveValue("justindrake.eth");
  await expect(page.getByLabel("Amount")).toHaveValue("0.001");
  await expect(page.getByRole("heading", { name: "1.0000 ETH" })).toBeVisible();
  const previousSigner = await page.locator(".signer-steps .current code").innerText();
  await page.getByRole("button", { name: "Send + rotate key" }).click();
  await expect(page.getByRole("status")).toContainText("Simulated locally — not broadcast");
  await expect(page.getByRole("heading", { name: "0.9990 ETH" })).toBeVisible();
  await expect(page.locator(".activity-row").first()).toContainText("Sent 0.001 ETH");
  await expect(page.getByText("Key 2", { exact: true })).toBeVisible();
  await expect(page.locator(".signer-steps .current code")).not.toHaveText(previousSigner);
  await expect(page.locator(".activity-row code").first()).toContainText(previousSigner);
  expect(blockchainRequests).toEqual([]);
  await page.getByRole("button", { name: "B Bunker" }).click();
  await expect(page.getByRole("heading", { name: "One address. Fresh keys." })).toBeVisible();
});

test("Ethereum Sepolia remains disabled", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Use Ethereum Sepolia (Soon)" })).toBeDisabled();
  await page.getByRole("button", { name: "Setup options" }).click();
  await expect(page.getByRole("button", { name: /Use Ethereum Sepolia/ })).toBeDisabled();
  await expect(page.getByRole("button", { name: /Recovery phrase/ })).toBeDisabled();
  await expect(page.getByRole("button", { name: /Load existing wallet/ })).toBeDisabled();
});

test("X post loads automatically", async ({ page }) => {
  let widgetRequests = 0;
  page.on("request", request => { if (request.url()==="https://platform.twitter.com/widgets.js") widgetRequests++; });
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Read the post by Justin Drake on X" })).toHaveAttribute("href", "https://x.com/drakefjustin/status/2107837081313505768");
  expect(widgetRequests).toBe(1);
});
