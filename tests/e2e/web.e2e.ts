import { expect, test } from "@playwright/test";
import { mkdirSync } from "node:fs";

const views = [
  ["desktop", 1440, 900], ["wide", 1920, 1080], ["tablet", 768, 1024], ["mobile", 390, 844], ["mobile-small", 360, 800],
] as const;

test.beforeAll(() => mkdirSync(".impeccable/review", { recursive: true }));

for (const [name, width, height] of views) test(`${name} renders without overflow in both themes`, async ({ page }) => {
  await page.setViewportSize({ width, height });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Open your wallet." })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Wallet sections" })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await page.screenshot({ path: `.impeccable/review/${name}-dark.png`, fullPage: true });
  await page.getByRole("button", { name: "Toggle theme" }).click();
  await expect(page.locator(".app.light")).toBeVisible();
  await page.screenshot({ path: `.impeccable/review/${name}-light.png`, fullPage: true });
});

test("one click creates a memory-only Sepolia burner and opens the faucet", async ({ page }) => {
  await page.goto("/");
  const popupPromise = page.waitForEvent("popup");
  await expect(page.getByRole("navigation", { name: "Wallet sections" })).toHaveCount(0);
  await page.getByRole("button", { name: "Or try a temporary Sepolia wallet" }).click();
  const popup = await popupPromise;
  await expect(page.getByRole("heading", { name: "Fund it, then explore." })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Wallet sections" })).toBeVisible();
  await expect(page.locator(".identifier code")).toHaveText(/^0x[0-9a-fA-F]{40}$/);
  expect(await page.evaluate(() => Object.keys(localStorage).every(key => !key.includes("burner")))).toBe(true);
  await page.screenshot({ path: ".impeccable/review/burner-dark.png", fullPage: true });
  expect(popup.url()).toContain("cloud.google.com/application/web3/faucet/ethereum/sepolia");
  await popup.close();
});

test("backup acknowledgement gates recovery confirmation", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Create wallet" }).click();
  const next = page.getByRole("button", { name: "Verify recovery" });
  await expect(next).toBeDisabled();
  await page.getByRole("checkbox").check();
  await expect(next).toBeEnabled();
});
