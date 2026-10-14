import {test,expect,type Page} from '@playwright/test';

// Only local built assets are served; the address bar has the exact isolated preview host.
const host='bunker-wallet-pq-sepolia-test.pages.dev';
async function localPreview(page:Page){
 await page.route(`https://${host}/**`,async route=>{
  const url=new URL(route.request().url()),upstream=await route.fetch({url:`http://127.0.0.1:4180${url.pathname}${url.search}`});
  await route.fulfill({response:upstream});
 });
 await page.route('https://platform.twitter.com/**',route=>route.abort());
}
test('production build enables only exact-host testnet preview',async({page})=>{
 await localPreview(page);await page.goto(`https://${host}/`);
 await expect(page.getByRole('button',{name:'Create wallet (Testnet)'})).toBeVisible();
 await expect(page.getByText('Sepolia testnet · Unaudited · Test ETH only')).toBeVisible();
 await page.getByRole('button',{name:'Create wallet (Testnet)'}).click();
 for(const mode of ['Standard','Quantum Shield','Maximum'] as const)await expect(page.getByRole('button',{name:`Select ${mode}`})).toBeVisible();
 await page.getByRole('button',{name:'Recover wallet'}).click();
 await expect(page.getByRole('heading',{name:'Recover your wallet.'})).toBeVisible();
});
for(const [kind,key] of [['Standard','bunker-vault'],['PQ','bunker-experimental-wallet-v1']] as const)test(`production build auto-opens recovery for saved ${kind} metadata`,async({page})=>{
 await localPreview(page);
 await page.addInitScript(([hostname,storageKey])=>{if(location.hostname===hostname)localStorage.setItem(storageKey,'{"synthetic":true}')},[host,key] as const);
 await page.goto(`https://${host}/`);
 await expect(page.getByRole('heading',{name:'Recover your wallet.'})).toBeVisible();
 expect(await page.evaluate(storageKey=>localStorage.getItem(storageKey),key)).toBe('{"synthetic":true}');
});
