import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium, expect, test, type Page } from "@playwright/test";

const deviceWalletData=(page:Page)=>page.evaluate(()=>new Promise<string>((resolve,reject)=>{const request=indexedDB.open("bunker-unlocked-session",1);request.onsuccess=()=>{const db=request.result,get=db.transaction("keys").objectStore("keys").getAll();get.onsuccess=()=>{db.close();resolve(JSON.stringify(get.result))};get.onerror=()=>reject(get.error)};request.onerror=()=>reject(request.error)}));
const clearDeviceWallet=(page:Page)=>page.evaluate(()=>new Promise<void>((resolve,reject)=>{const request=indexedDB.deleteDatabase("bunker-unlocked-session");request.onsuccess=()=>resolve();request.onerror=()=>reject(request.error)}));

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
  await expect(page.getByLabel("Recipient")).toHaveValue("vitalik.eth");
  await expect(page.getByLabel("Amount")).toHaveValue("0.0001");
  await expect(page.getByRole("heading", { name: "1.0000 ETH" })).toBeVisible();
  const previousSigner = await page.locator(".signer-steps .current code").innerText();
  await page.getByRole("button", { name: "Send + rotate key" }).click();
  await expect(page.getByRole("status")).toContainText("Simulated locally — not broadcast");
  await expect(page.getByRole("heading", { name: "0.9999 ETH" })).toBeVisible();
  await expect(page.locator(".activity-row").first()).toContainText("Sent 0.0001 ETH");
  await expect(page.locator(".activity a")).toHaveCount(0);
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

test("Sepolia persistence: encrypted wallet survives refresh and relogin", async ({ page }) => {
  test.skip(process.env.BROWSER_SEPOLIA_E2E !== "1");
  await page.goto("/");
  await page.getByRole("button", { name: "Create Sepolia Wallet" }).click();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Skip check" }).click();
  const password = "browser-refresh-test-password";
  await expect(page.getByRole("button", { name: "Continue without password" })).toBeEnabled();
  await page.getByLabel(/Password · 12 characters minimum/).fill(password);
  await page.getByRole("button", { name: /Encrypt and (?:continue|save this browser)/ }).click();
  await expect(page.getByRole("heading", { name: "Add Ethereum Sepolia test ETH." })).toBeVisible();
  const storage = await page.evaluate(() => ({ keys: Object.keys(localStorage), vault: localStorage.getItem("bunker-vault") }));
  const device=await deviceWalletData(page);
  expect(storage.keys).toEqual(["bunker-vault"]);
  expect(storage.vault).not.toContain(password);
  expect(storage.vault).not.toMatch(/mnemonic|privateKey/);
  expect(device).not.toContain(password);
  expect(device).not.toMatch(/mnemonic|privateKey/);
  await page.reload({ waitUntil: "networkidle" });
  await expect(page.getByRole("heading", { name: "Add Ethereum Sepolia test ETH." })).toBeVisible();
  await clearDeviceWallet(page);
  await page.reload({ waitUntil: "networkidle" });
  await expect(page.getByRole("heading", { name: "Resume or recover." })).toBeVisible();
  const newWalletPage=await page.context().newPage();
  await newWalletPage.goto("/");
  await newWalletPage.getByRole("button", { name: "Create new wallet" }).click();
  await expect(newWalletPage.getByRole("heading", { name: "Write down these 24 words." })).toBeVisible();
  await newWalletPage.close();
  await page.getByLabel("Vault password").fill("wrong-browser-password");
  await page.getByRole("button", { name: "Unlock saved wallet" }).click();
  await expect(page.getByRole("status")).toContainText("could not be opened");
  await page.getByLabel("Vault password").fill(password);
  await page.getByRole("button", { name: "Unlock saved wallet" }).click();
  await expect(page.getByRole("heading", { name: "Add Ethereum Sepolia test ETH." })).toBeVisible();
});

test("Sepolia persistence: passwordless wallet survives tab closure", async ({ page }) => {
  test.skip(process.env.BROWSER_SEPOLIA_E2E !== "1");
  await page.goto("/");
  await page.getByRole("button", { name: "Create Sepolia Wallet" }).click();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Skip check" }).click();
  await expect(page.getByText(/non-extractable device key/)).toBeVisible();
  await page.getByRole("button", { name: "Continue without password" }).click();
  await expect(page.getByRole("heading", { name: "Add Ethereum Sepolia test ETH." })).toBeVisible();
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([]);
  expect(await deviceWalletData(page)).not.toMatch(/mnemonic|privateKey/);
  const context=page.context();await page.close();const reopened=await context.newPage();
  await reopened.goto("/");
  await expect(reopened.getByRole("heading", { name: "Add Ethereum Sepolia test ETH." })).toBeVisible();
});

test("Sepolia persistence: browser restart restores until Lock", async () => {
  test.skip(process.env.BROWSER_SEPOLIA_E2E !== "1");
  const profile=mkdtempSync(join(tmpdir(),"bunker-profile-"));
  try{
    let context=await chromium.launchPersistentContext(profile,{serviceWorkers:"block"}),page=await context.newPage();
    await page.goto("http://127.0.0.1:4173");
    await page.getByRole("button",{name:"Create Sepolia Wallet"}).click();
    await page.getByRole("checkbox").check();await page.getByRole("button",{name:"Skip check"}).click();
    await page.getByRole("button",{name:"Continue without password"}).click();
    await expect(page.getByRole("heading",{name:"Add Ethereum Sepolia test ETH."})).toBeVisible();
    await context.close();
    context=await chromium.launchPersistentContext(profile,{serviceWorkers:"block"});page=context.pages()[0]??await context.newPage();await page.goto("http://127.0.0.1:4173");
    await expect(page.getByRole("heading",{name:"Add Ethereum Sepolia test ETH."})).toBeVisible();
    await page.getByRole("button",{name:"Lock"}).click();await expect(page.getByRole("heading",{name:"One address. Fresh keys."})).toBeVisible();
    expect(await deviceWalletData(page)).toBe("[]");await context.close();
    context=await chromium.launchPersistentContext(profile,{serviceWorkers:"block"});page=context.pages()[0]??await context.newPage();await page.goto("http://127.0.0.1:4173");
    await expect(page.getByRole("heading",{name:"One address. Fresh keys."})).toBeVisible();await context.close();
  }finally{rmSync(profile,{recursive:true,force:true})}
});

test("Sepolia persistence: migrates an open legacy tab session", async ({ page }) => {
  test.skip(process.env.BROWSER_SEPOLIA_E2E !== "1");
  await page.goto("/");
  await page.evaluate(async mnemonic=>{const id=crypto.randomUUID(),key=await crypto.subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]),nonce=crypto.getRandomValues(new Uint8Array(12)),ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce},key,new TextEncoder().encode(mnemonic))),hex=(v:Uint8Array)=>Array.from(v,b=>b.toString(16).padStart(2,"0")).join("");const db=await new Promise<IDBDatabase>((resolve,reject)=>{const request=indexedDB.open("bunker-unlocked-session",1);request.onupgradeneeded=()=>request.result.createObjectStore("keys");request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error)});await new Promise<void>((resolve,reject)=>{const request=db.transaction("keys","readwrite").objectStore("keys").put(key,id);request.onsuccess=()=>resolve();request.onerror=()=>reject(request.error)});db.close();sessionStorage.setItem("bunker-unlocked-wallet",JSON.stringify({id,nonce:hex(nonce),ciphertext:hex(ciphertext),expiresAt:Date.now()+60_000}))},`${"abandon ".repeat(23)}art`);
  await page.reload({waitUntil:"networkidle"});
  await expect(page.getByRole("heading",{name:"Add Ethereum Sepolia test ETH."})).toBeVisible();
  expect(await page.evaluate(()=>sessionStorage.getItem("bunker-unlocked-wallet"))).toBeNull();
  expect(await deviceWalletData(page)).not.toMatch(/mnemonic|privateKey/);
});

test("Sepolia persistence: phrase recovery needs no password", async ({ page }) => {
  test.skip(process.env.BROWSER_SEPOLIA_E2E !== "1");
  await page.goto("/");
  await page.getByRole("button", { name: "Setup options" }).click();
  await page.getByRole("button", { name: /Load existing wallet/ }).click();
  await page.getByLabel("Recovery phrase").fill(`${"abandon ".repeat(23)}art`);
  await page.getByRole("button", { name: "Recover with phrase" }).click();
  await expect(page.getByRole("heading", { name: "Add Ethereum Sepolia test ETH." })).toBeVisible();
});

test("X post loads automatically", async ({ page }) => {
  let widgetRequests = 0;
  page.on("request", request => { if (request.url()==="https://platform.twitter.com/widgets.js") widgetRequests++; });
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Read the post by Justin Drake on X" })).toHaveAttribute("href", "https://x.com/drakefjustin/status/2107837081313505768");
  expect(widgetRequests).toBe(1);
});
