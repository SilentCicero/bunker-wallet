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

for (const [name, width, height] of views) {
  test(`${name} landing renders in both themes`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /One address.*Fresh keys/s })).toBeVisible();
    await expect(page.getByRole("button", { name: "Try local preview" }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: "Use Ethereum Sepolia" })).toBeVisible();
    await expect(page.getByText(/reducing exposure to future quantum attacks/)).toBeVisible();
    await expect(page.getByText("Rotate the keys.")).toBeVisible();
    await expect(page.getByText("Less exposure.")).toBeVisible();
    await expect(page.getByText("MIT open source")).toBeVisible();
    await expect(page.getByRole("link", { name: /View the source/ })).toHaveAttribute("href", "https://github.com/SilentCicero/bunker-wallet");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: `.impeccable/review/${name}-light.png`, fullPage: true });
    await page.getByRole("button", { name: "Dark" }).click();
    await page.screenshot({ path: `.impeccable/review/${name}-dark.png`, fullPage: true });
  });
}

test("local preview creates a wallet and rotates without network funding", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Try local preview" }).first().click();
  await expect(page.getByRole("heading", { name: "Your local preview is ready." })).toBeVisible();
  await page.getByRole("button", { name: "Create stable wallet" }).click();
  await expect(page.getByText("Local preview · simulated, not broadcast")).toBeVisible();
  await page.getByRole("button", { name: "Wall", exact: true }).click();
  await page.getByPlaceholder("Hello from my rotating wallet").fill("Local rotation demo");
  await page.getByRole("button", { name: "Post + rotate key" }).click();
  await expect(page.getByRole("status")).toContainText("Simulated locally — not broadcast");
  await expect(page.getByText("Key 2", { exact: true })).toBeVisible();
});

test("optional Ethereum Sepolia flow opens the Google Cloud faucet", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Use Ethereum Sepolia" }).click();
  await expect(page.getByRole("heading", { name: "Add Ethereum Sepolia test ETH." })).toBeVisible();
  const address = await page.locator(".setup-address code").innerText();
  expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  expect(await page.evaluate(() => Object.keys(localStorage).every(key => !key.includes("burner")))).toBe(true);
  const popupPromise = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Open Google Cloud faucet" }).click();
  const popup = await popupPromise;
  expect(popup.url()).toContain("cloud.google.com/application/web3/faucet/ethereum/sepolia");
  await popup.close();
  await page.screenshot({ path: ".impeccable/review/setup-light.png", fullPage: true });
});

test("advanced phrase setup offers optional check and password", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Setup options" }).click();
  await page.getByRole("button", { name: /Recovery phrase/ }).click();
  const next = page.getByRole("button", { name: "Check my backup" });
  await expect(next).toBeDisabled();
  await page.getByRole("checkbox").check();
  await expect(next).toBeEnabled();
  await expect(page.getByRole("button", { name: "Skip check" })).toBeEnabled();
});
