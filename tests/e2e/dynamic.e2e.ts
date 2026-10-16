import { test, expect } from "@playwright/test";

for (const retry of [{amount:"0.002",recipient:"0x000000000000000000000000000000000000cafe"},{amount:"",recipient:"not-an-address"}])
test(`dynamic V2 browser: recovery and pending intent with retry ${retry.amount || "invalid"}`,  async ({page}) => {
  test.skip(!process.env.DYNAMIC_ANVIL_RPC);
  test.setTimeout(180_000);
  const rpc = process.env.DYNAMIC_ANVIL_RPC!;
  if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(rpc)) throw new Error("Local Anvil only");
  const call = async (method:string,params:unknown[]) => {
    const response = await fetch(rpc,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method,params})});
    const result = await response.json() as {error?:unknown;result:unknown};
    if(result.error) throw new Error(`Anvil ${method} failed`);
    return result.result;
  };
  await page.route("https://platform.twitter.com/**",r=>r.abort());
  await page.goto("/");
  await page.getByRole("button",{name:"Create Wallet (Testnet)"}).click();
  const originalPhrase = await page.locator(".words li").evaluateAll(items => items.map(item => item.lastChild!.textContent).join(" "));
  await page.getByRole("checkbox").check();
  await page.getByRole("button",{name:"Skip check"}).click();
  await page.getByRole("button",{name:"Continue without password"}).click();
  await expect(page.locator(".setup-address code")).toHaveText(/^0x[0-9a-fA-F]{40}$/);
  const setup = await page.locator(".setup-address code").innerText();
  await call("anvil_setBalance",[setup,"0xde0b6b3a7640000"]);
  await page.getByRole("button",{name:"I funded it — check balance"}).click();
  await page.getByRole("button",{name:"Create guarded Safe",exact:true}).click();
  await expect(page.getByRole("button",{name:"Copy stable Safe address"})).toBeVisible({timeout:90_000});
  const safe = await page.locator(".stable-copy code").innerText();
  const phrase = `${"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"}`;
  // Selecting B, then recovering A without Lock must discard the abandoned
  // selection in both the signer session and UI, and preserve A's vault.
  const { encryptMnemonic } = await import("../../packages/vault/src/index");
  const originalVault = JSON.stringify(await encryptMnemonic(originalPhrase, "regression-test-password", {chainId:11155111,derivation:"m/44'/60'/7331'/0/index",sequenceVersion:2}));
  await page.evaluate(vault => localStorage.setItem("bunker-vault", vault), originalVault);
  await page.getByLabel("New recovery phrase",{exact:false}).fill(phrase);
  await page.getByLabel(/I backed up the new phrase/).check();
  await page.getByRole("button",{name:"Select next signer locally"}).click();
  await page.getByRole("button",{name:"Setup options"}).click();
  await page.getByRole("button",{name:/Load existing wallet/}).click();
  await page.getByLabel("Recovery phrase",{exact:true}).fill(originalPhrase);
  await page.getByRole("button",{name:"Recover with phrase"}).click();
  await expect(page.locator(".stable-copy code")).toHaveText(safe);
  await page.getByLabel("Recipient",{exact:false}).fill("0x000000000000000000000000000000000000beef");
  await page.getByRole("button",{name:"Send + rotate key"}).click();
  await expect(page.getByRole("status")).toContainText("Confirmed on Ethereum Sepolia",{timeout:60_000});
  expect(await page.evaluate(()=>localStorage.getItem("bunker-vault"))).toBe(originalVault);
  await page.reload();
  await expect(page.locator(".stable-copy code")).toHaveText(safe);
  await expect(page.locator(".rotation-card strong")).toHaveText("Key 2");
  await page.getByLabel("Next derivation index").fill("147");
  await page.getByLabel("New recovery phrase",{exact:false}).fill(phrase);
  await page.getByLabel(/I backed up the new phrase/).check();
  await page.getByRole("button",{name:"Select next signer locally"}).click();
  await expect(page.getByRole("status")).toContainText("Next signer selected locally");
  await page.getByLabel("Recipient",{exact:false}).fill("0x000000000000000000000000000000000000beef");
  await page.getByRole("button",{name:"Send + rotate key"}).click();
  await expect(page.getByRole("status")).toContainText("Confirmed on Ethereum Sepolia",{timeout:60_000});
  // The default automatic search cannot find index 147: offer manual recovery,
  // never tell the user their backed-up wallet is unrecoverable.
  await page.reload();
  await expect(page.getByLabel("Recovery start index")).toBeVisible();
  await expect(page.getByRole("status")).toContainText("recovery range");
  await page.evaluate(async()=>{localStorage.clear();sessionStorage.clear();await new Promise<void>((resolve,reject)=>{const r=indexedDB.deleteDatabase("bunker-unlocked-session");r.onsuccess=()=>resolve();r.onerror=()=>reject(r.error)})});
  await page.reload();
  await page.getByRole("button",{name:"Setup options"}).click();
  await page.getByRole("button",{name:/Load existing wallet/}).click();
  await page.getByLabel("Recovery phrase",{exact:true}).fill(phrase);
  await page.getByLabel("Stable Safe address · optional").fill(safe);
  await page.getByLabel("Recovery start index").fill("140");
  await page.getByLabel("Keys to search (1–1000)").fill("20");
  await page.getByRole("button",{name:"Recover with phrase"}).click();
  await expect(page.locator(".stable-copy code")).toHaveText(safe);
  expect(await page.evaluate(()=>localStorage.getItem("bunker-safe-wallet"))).toBe(safe);
  await page.getByLabel("Recipient",{exact:false}).fill("0x000000000000000000000000000000000000beef");
  // Lose the owner read after mining. Retrying must reconcile, not send twice.
  const originalAmount = await page.getByLabel("Amount",{exact:false}).inputValue();
  const originalRecipient = await page.getByLabel("Recipient",{exact:false}).inputValue();
  const recipientBalance = await call("eth_getBalance",[originalRecipient,"latest"]);
  const changedRecipient = "0x000000000000000000000000000000000000cafe";
  const changedBalance = await call("eth_getBalance",[changedRecipient,"latest"]);
  let originalHash = "";
  let mined = false;
  await page.route(rpc, async route => {
    const body = route.request().postDataJSON();
    if (mined && body.method === "eth_call" && body.params[0].data === "0xa0e67e2b") {
      await route.fulfill({json:{jsonrpc:"2.0",id:body.id,error:{code:-32603,message:"injected owner read failure"}}});
      return;
    }
    const response = await route.fetch();
    const json = await response.json();
    if (body.method === "eth_getTransactionReceipt" && json.result) { mined = true; originalHash = json.result.transactionHash; }
    await route.fulfill({response});
  });
  await page.getByRole("button",{name:"Send + rotate key"}).click();
  await expect(page.getByRole("status")).toContainText("injected owner read failure",{timeout:60_000});
  await page.unroute(rpc);
  await page.getByLabel("Amount",{exact:false}).fill(retry.amount);
  await page.getByLabel("Recipient",{exact:false}).fill(retry.recipient);
  await page.getByRole("button",{name:"Send + rotate key"}).click();
  await expect(page.getByRole("status")).toContainText("Confirmed on Ethereum Sepolia",{timeout:60_000});
  const originalActivity = page.locator(`.activity-link[href$="${originalHash}"]`);
  await expect(originalActivity).toContainText(`Sent ${originalAmount} ETH`);
  await expect(originalActivity).toContainText(originalRecipient);
  expect(BigInt(await call("eth_getBalance",[originalRecipient,"latest"]) as string)-BigInt(recipientBalance as string)).toBe((await import("viem")).parseEther(originalAmount));
  expect(await call("eth_getBalance",[changedRecipient,"latest"])).toBe(changedBalance);
  await expect(page.locator(".rotation-card strong")).toHaveText("Key 4");
  await page.getByLabel("Amount",{exact:false}).fill(originalAmount);
  await page.getByLabel("Recipient",{exact:false}).fill(originalRecipient);
  // The transfer can also succeed before a UI balance refresh fails.
  mined = false;
  await page.route(rpc, async route => {
    const body = route.request().postDataJSON();
    if (mined && body.method === "eth_getBalance") {
      await route.fulfill({json:{jsonrpc:"2.0",id:body.id,error:{code:-32603,message:"injected balance read failure"}}});
      return;
    }
    const response = await route.fetch();
    const json = await response.json();
    if (body.method === "eth_getTransactionReceipt" && json.result) { mined = true; originalHash = json.result.transactionHash; }
    await route.fulfill({response});
  });
  await page.getByRole("button",{name:"Send + rotate key"}).click();
  await expect(page.getByRole("status")).toContainText("injected balance read failure",{timeout:60_000});
  await page.unroute(rpc);
  await page.getByRole("button",{name:"Send + rotate key"}).click();
  await expect(page.getByRole("status")).toContainText("Confirmed on Ethereum Sepolia",{timeout:60_000});
  await expect(page.locator(".rotation-card strong")).toHaveText("Key 5");
  await expect(page.locator(".stable-copy code")).toHaveText(safe);
});
