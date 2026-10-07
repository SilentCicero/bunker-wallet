import { expect, test } from "@playwright/test";
import { mkdirSync } from "node:fs";

const views = [
  ["desktop", 1440, 900], ["wide", 1920, 1080], ["tablet", 768, 1024], ["mobile", 390, 844], ["mobile-small", 360, 800],
] as const;

test.beforeAll(() => mkdirSync(".impeccable/review", { recursive: true }));

for (const [name, width, height] of views) test(`${name} renders without overflow in both themes`, async ({ page }) => {
  await page.setViewportSize({ width, height });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Every transfer moves the key." })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await page.screenshot({ path: `.impeccable/review/${name}-dark.png`, fullPage: true });
  await page.getByRole("button", { name: "Toggle theme" }).click();
  await expect(page.locator(".app.light")).toBeVisible();
  await page.screenshot({ path: `.impeccable/review/${name}-light.png`, fullPage: true });
});

test("backup acknowledgement gates recovery confirmation", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Create local wallet" }).click();
  const next = page.getByRole("button", { name: "Verify recovery" });
  await expect(next).toBeDisabled();
  await page.getByRole("checkbox").check();
  await expect(next).toBeEnabled();
});
