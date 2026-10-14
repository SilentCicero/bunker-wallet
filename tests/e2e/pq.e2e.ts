import {test,expect,type Page} from '@playwright/test';
import {mnemonicToAccount} from 'viem/accounts';
import {parseTransaction,hexToBytes,bytesToHex,keccak256} from 'viem';
import {prepareMLDSA} from '../../packages/pq/src/keys';
import fixture from '../fixtures/sepolia-safe-1.4.1.json';
const enabled=process.env.BROWSER_PQ_E2E==='1';
const phrase='abandon '.repeat(23)+'art';
const RPC='http://127.0.0.1:18545';
async function rpc(method:string,params:unknown[]=[]){const r=await fetch(RPC,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});const j=await r.json();if(j.error)throw new Error(j.error.message);return j.result;}
test.beforeAll(async()=>{if(!enabled)return;for(const path of ['/src/burner.ts','/src/pq/wallet.ts']){const source=await fetch(`http://127.0.0.1:4173${path}`).then(r=>r.text());expect(source,`${path} must point only to disposable Anvil`).toContain(RPC);}for(const x of Object.values(fixture.codes))await rpc('anvil_setCode',[x.address,x.runtime]);});
async function choose(page:Page,mode:'Standard'|'Quantum Shield'|'Maximum'){
 await page.goto('/');await page.getByRole('button',{name:'Create wallet (Testnet)'}).click();
 await page.getByRole('slider',{name:'Signing mode'}).fill(String(['Standard','Quantum Shield','Maximum'].indexOf(mode)));
}
async function recovery(page:Page){await page.goto('/');await page.getByRole('button',{name:'Recover wallet'}).click();return page.locator('.recover-screen');}
async function recoverSafe(page:Page,mnemonic:string,safe:string,browserPassword='public-test-password'){const screen=await recovery(page);await screen.getByLabel('24-word recovery phrase').fill(mnemonic);await screen.getByLabel('Existing Safe address').fill(safe);await screen.getByLabel('Browser password · 12–256 characters').fill(browserPassword);await screen.getByRole('button',{name:'Recover and save wallet'}).click();return page.getByRole('region',{name:'Experimental PQ wallet'});}
async function startNew(page:Page,mode:'Quantum Shield'|'Maximum'='Quantum Shield',password='public-test-password'){
 await choose(page,mode);await page.getByRole('button',{name:'Create wallet'}).click();
 const mnemonic=(await page.locator('.words li').allTextContents()).map(word=>word.replace(/^\d+/,'')).join(' ');
 await page.getByLabel('I saved the phrase offline.').check();await page.getByRole('button',{name:'Skip check'}).click();
 await page.getByLabel('Password · 12 characters minimum').fill(password);
 await page.getByRole('button',{name:'Encrypt and save this browser'}).click();
 const panel=page.getByRole('region',{name:'Experimental PQ wallet'});await expect(panel.getByText('Setup address',{exact:true})).toBeVisible({timeout:30000});
 return {panel,mnemonic};
}
test('creation has one CTA; recovery is separate with phrase and Safe only',async({page})=>{
 test.skip(!enabled);await page.setViewportSize({width:1366,height:768});
 for(const mode of ['Standard','Quantum Shield','Maximum'] as const){
  await choose(page,mode);await expect(page.getByRole('slider',{name:'Signing mode'})).toHaveAttribute('aria-valuetext',new RegExp(mode));
  await expect(page.locator('.advanced .stepper li')).toHaveCount(5);expect(await page.locator('.advanced .stepper').evaluate(el=>getComputedStyle(el).borderTopWidth)).toBe('0px');await expect(page.locator('.advanced .stepper li[aria-current="step"]')).toContainText('Choose signing mode');await expect(page.locator('.advanced .stepper li[aria-current="step"] span')).toHaveText('1');
  await expect(page.locator('.security-selector label strong')).toHaveText(`${mode} · ${mode==='Standard'?'Single Signature':'Dual Signature (2 of 2)'}`);
  await expect(page.locator('.security-gas')).toContainText(/~\S+ setup \/ ~\S+ sending/);
  await expect(page.locator('.security-ticks small')).toHaveText(['Non-experimental','Experimental','Experimental']);
  const selected=page.getByRole('button',{name:`Select ${mode}`});await expect(selected).toHaveAttribute('aria-pressed','true');expect(await selected.evaluate(el=>({border:getComputedStyle(el).borderTopWidth,radius:getComputedStyle(el).borderRadius,shadow:getComputedStyle(el).boxShadow}))).toEqual({border:'2px',radius:'4px',shadow:'none'});
  await expect(page.getByRole('slider',{name:'Signing mode'})).toHaveAttribute('aria-valuetext',new RegExp(mode==='Standard'?'Single Signature':'Dual Signature, 2 of 2'));
  await expect(page.locator('.advanced .secure-actions button')).toHaveCount(1);
  await expect(page.getByText(/Budget at least 0.03 test ETH for setup/)).not.toBeVisible();
  const alignment=await page.locator('.security-selector .security-details summary').evaluate(el=>{const left=el.querySelector('.security-summary')!.getBoundingClientRect(),right=el.querySelector('.details-toggle')!.getBoundingClientRect();return {left:left.left,right:right.left,rightTop:right.top,leftBottom:left.bottom}});expect(alignment.right).toBeGreaterThan(alignment.left);expect(alignment.rightTop).toBeLessThan(alignment.leftBottom);
  await page.setViewportSize({width:320,height:700});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(320);await page.setViewportSize({width:1366,height:768});
  await page.getByText('Read details').click();
  await expect(page.getByText(/Budget at least 0.03 test ETH for setup/)).toBeVisible();
  await expect(page.getByText(new RegExp(`Setup:.*${mode==='Standard'?'2\\.93M':mode==='Quantum Shield'?'17\\.52M':'22\\.92M'} gas across ${mode==='Standard'?4:mode==='Quantum Shield'?6:7} transactions`))).toBeVisible();
  await expect(page.getByText(/At 1 gwei per gas:/)).toBeVisible();
  await expect(page.getByRole('link',{name:mode==='Standard'?'Safe signature handling':mode==='Quantum Shield'?'C10 verifier source':'ML-DSA verifier safety requirements'})).toBeVisible();
  await page.getByRole('button',{name:'Create wallet'}).click();await expect(page.getByRole('heading',{name:'Write down these 24 words.'})).toBeVisible();
  await expect(page.locator('.stepper li[aria-current="step"]')).toContainText('Back up recovery phrase');await expect(page.locator('.stepper li[aria-current="step"] span')).toHaveText('2');
  await expect(page.getByText(`Signing mode: ${mode} · chosen before backup`)).toBeVisible();await expect(page.locator('.words li')).toHaveCount(24);
  await page.getByLabel('I saved the phrase offline.').check();await page.getByRole('button',{name:'Check my backup'}).click();await expect(page.getByLabel('Word 3')).toBeVisible();
  await expect(page.locator('.stepper li[aria-current="step"]')).toContainText('Back up recovery phrase');
 }
 const screen=await recovery(page);await expect(screen.getByLabel('Browser password · 12–256 characters')).toBeVisible();
 await expect(screen.getByRole('slider')).toHaveCount(0);await expect(screen.getByText(/create wallet/i)).toHaveCount(0);
 await screen.getByRole('button',{name:'Recover and save wallet'}).click();await expect(page.getByRole('status')).toContainText('valid 24-word');
 await screen.getByLabel('24-word recovery phrase').fill(phrase);await screen.getByRole('button',{name:'Recover and save wallet'}).click();await expect(page.getByRole('status')).toContainText('existing Safe address');
 await screen.getByLabel('Existing Safe address').fill('0x0000000000000000000000000000000000005678');await screen.getByRole('button',{name:'Recover and save wallet'}).click();await expect(page.getByRole('status')).toContainText('browser password of 12–256');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(1366);
 await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(390);
});
test('coexisting browser vaults have unambiguous recovery choices',async({page})=>{
 test.skip(!enabled);await page.goto('/');await page.evaluate(()=>{localStorage.setItem('bunker-vault','{}');localStorage.setItem('bunker-experimental-vault-v1','{}')});await page.reload();
 await expect(page.getByRole('button',{name:'Recover saved Standard wallet'})).toBeVisible();await expect(page.getByRole('button',{name:'Recover saved experimental wallet'})).toBeVisible();await expect(page.getByRole('button',{name:'Unlock',exact:true})).toHaveCount(0);
});
test('unsupported Safe cannot infer a mode or write a wallet',async({page})=>{
 test.skip(!enabled);const screen=await recovery(page);await screen.getByLabel('24-word recovery phrase').fill(phrase);await screen.getByLabel('Existing Safe address').fill('0x0000000000000000000000000000000000005678');await screen.getByLabel('Browser password · 12–256 characters').fill('public-test-password');
 await screen.getByRole('button',{name:'Recover and save wallet'}).click();await expect(page.getByRole('status')).toContainText('Not a supported Safe proxy');
 expect(await page.evaluate(()=>[localStorage.getItem('bunker-experimental-wallet-v1'),localStorage.getItem('bunker-vault')])).toEqual([null,null]);
});
test('all signing combinations share creation milestones and one Safe action',async({browser})=>{
 test.skip(!enabled);for(const mode of ['Standard','Quantum Shield','Maximum'] as const){const context=await browser.newContext({serviceWorkers:'block'}),page=await context.newPage();try{
  await choose(page,mode);await expect(page.locator('.stepper li[aria-current="step"]')).toContainText('Choose signing mode');await page.getByRole('button',{name:'Create wallet'}).click();
  await expect(page.locator('.stepper li[aria-current="step"]')).toContainText('Back up recovery phrase');await page.getByLabel('I saved the phrase offline.').check();await page.getByRole('button',{name:'Skip check'}).click();
  await expect(page.locator('.stepper li[aria-current="step"]')).toContainText('Protect browser');await expect(page.locator('.stepper li[aria-current="step"] span')).toHaveText('3');
  if(mode==='Standard')await page.getByRole('button',{name:'Continue without password'}).click();else{await page.getByLabel('Password · 12 characters minimum').fill('public-test-password');await page.getByRole('button',{name:'Encrypt and save this browser'}).click()}
  const screen=mode==='Standard'?page.locator('.setup'):page.locator('#experimental-wallet');
  await expect(screen.getByRole('heading',{name:'Add Ethereum Sepolia test ETH.'})).toBeVisible({timeout:30000});
  if(mode!=='Standard'){await expect(screen.getByRole('note')).toContainText('Send at least 0.03 test ETH to the setup address.');await expect(screen.locator('.pq-setup-address').getByText('Setup balance')).toBeVisible();await expect(screen.locator('.balance-row')).toHaveCount(0)}
  await expect(screen.locator('.stepper li[aria-current="step"]')).toContainText('Fund setup key');await expect(screen.locator('.stepper li[aria-current="step"] span')).toHaveText('4');
  await page.setViewportSize({width:320,height:700});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(320);
  const setup=await screen.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();
  await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await screen.getByRole('button',{name:'I funded it — check balance'}).click();
  await expect(screen.getByRole('heading',{name:'Create your Safe wallet.'})).toBeVisible();
  await expect(screen.locator('.stepper li[aria-current="step"]')).toContainText('Create Safe wallet');await expect(screen.locator('.stepper li[aria-current="step"] span')).toHaveText('5');
  await expect(screen.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/})).toBeEnabled();
  if(mode!=='Standard')expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-vault-v1'))).toContain('ciphertext');
 }finally{await context.close()}}
});
test('explicit testnet replacement deletes only a non-pending PQ browser checkpoint after confirmation',async({page})=>{
 test.skip(!enabled);const {panel}=await startNew(page,'Quantum Shield','public-test-password');
 const before=await page.evaluate(()=>[localStorage.getItem('bunker-experimental-wallet-v1'),localStorage.getItem('bunker-experimental-vault-v1')]);
 await panel.getByRole('button',{name:'Lock / cancel'}).click();await page.getByRole('button',{name:'Create wallet (Testnet)'}).click();
 await page.getByRole('slider',{name:'Signing mode'}).fill('1');
 const confirm=page.getByRole('group',{name:'Replace saved test wallet'});await expect(confirm).toBeVisible();await expect(page.getByRole('button',{name:'Create wallet',exact:true})).toHaveCount(0);
 await page.setViewportSize({width:320,height:700});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(320);
 await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(390);
 await expect(confirm.getByRole('button',{name:'Continue — replace local wallet'})).toBeDisabled();
 let broadcasts=0;await page.context().route(url=>url.origin===RPC,async route=>{if(route.request().method()==='POST'){const body=route.request().postDataJSON() as {method?:string};if(body.method==='eth_sendRawTransaction')broadcasts++}await route.continue()});
 await confirm.getByRole('button',{name:'Recover wallet'}).click();await expect(page.getByRole('heading',{name:'Recover your wallet.'})).toBeVisible();expect(await page.evaluate(()=>[localStorage.getItem('bunker-experimental-wallet-v1'),localStorage.getItem('bunker-experimental-vault-v1')])).toEqual(before);expect(broadcasts).toBe(0);
 await page.getByRole('button',{name:'Setup options'}).click();await page.getByRole('slider',{name:'Signing mode'}).fill('1');await expect(confirm).toBeVisible();await confirm.getByRole('button',{name:'Cancel'}).click();expect(await page.evaluate(()=>[localStorage.getItem('bunker-experimental-wallet-v1'),localStorage.getItem('bunker-experimental-vault-v1')])).toEqual(before);
 await page.getByRole('button',{name:'Setup options'}).click();await expect(confirm).toBeVisible();await confirm.getByRole('checkbox').check();
 await confirm.getByRole('button',{name:'Continue — replace local wallet'}).click();
 await expect(page.getByRole('heading',{name:'Write down these 24 words.'})).toBeVisible();
 expect(await page.evaluate(()=>[localStorage.getItem('bunker-experimental-wallet-v1'),localStorage.getItem('bunker-experimental-vault-v1')])).toEqual([null,null]);expect(broadcasts).toBe(0);
});
test('malformed PQ records and Standard journals cannot unlock destructive replacement',async({page})=>{
 test.skip(!enabled);const {panel}=await startNew(page);await panel.getByRole('button',{name:'Lock / cancel'}).click();
 await page.getByRole('button',{name:'Create wallet (Testnet)'}).click();await page.getByRole('slider',{name:'Signing mode'}).fill('1');
 for(const safe of [null,'']){const original=await page.evaluate(value=>{const record=JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!);record.safe=value;const raw=JSON.stringify(record);localStorage.setItem('bunker-experimental-wallet-v1',raw);return raw},safe);
  await page.getByRole('button',{name:'Select Standard'}).click();await page.getByRole('button',{name:'Select Quantum Shield'}).click();await expect(page.getByRole('group',{name:'Unverified saved experimental setup'})).toBeVisible();
  await expect(page.getByRole('group',{name:'Replace saved test wallet'})).toHaveCount(0);expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-wallet-v1'))).toBe(original);
 }
 const arrayRecord=await page.evaluate(()=>{const record=JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!);delete record.safe;record.parts=[];const raw=JSON.stringify(record);localStorage.setItem('bunker-experimental-wallet-v1',raw);return raw});
 await page.getByRole('button',{name:'Select Standard'}).click();await page.getByRole('button',{name:'Select Quantum Shield'}).click();await expect(page.getByRole('group',{name:'Unverified saved experimental setup'})).toBeVisible();
 await expect(page.getByRole('group',{name:'Replace saved test wallet'})).toHaveCount(0);expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-wallet-v1'))).toBe(arrayRecord);
 const original=await page.evaluate(()=>{const record=JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!);record.parts={};const raw=JSON.stringify(record);localStorage.setItem('bunker-experimental-wallet-v1',raw);return raw});
 for(const journal of ['{"version":1,"state":"unknown"}',JSON.stringify({version:1,state:'ready',address:'0x0000000000000000000000000000000000001234',factoryHash:'invalid'}),JSON.stringify({version:1,state:'ready',address:'0x0000000000000000000000000000000000001234',factoryHash:'0x'+'11'.repeat(32)})]){
  await page.evaluate(value=>localStorage.setItem('bunker-standard-setup-v1',value),journal);await page.getByRole('button',{name:'Select Standard'}).click();await page.getByRole('button',{name:'Select Quantum Shield'}).click();
  await expect(page.getByRole('group',{name:'Saved Standard setup'})).toContainText('Standard setup outcome uncertain');await expect(page.getByRole('button',{name:'Create wallet',exact:true})).toHaveCount(0);
  await expect(page.getByRole('group',{name:'Replace saved test wallet'})).toHaveCount(0);expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-wallet-v1'))).toBe(original);
  expect(await page.evaluate(()=>localStorage.getItem('bunker-standard-setup-v1'))).toBe(journal);
 }
});
test('passwordless unfinished Standard setup resumes locally after Lock without Safe recovery',async({page})=>{
 test.skip(!enabled);await choose(page,'Standard');await page.getByRole('button',{name:'Create wallet'}).click();
 const mnemonic=(await page.locator('.words li').allTextContents()).map(word=>word.replace(/^\d+/,'')).join(' ');
 await page.getByLabel('I saved the phrase offline.').check();await page.getByRole('button',{name:'Skip check'}).click();await page.getByRole('button',{name:'Continue without password'}).click();
 const setup=await page.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);
 await page.getByRole('button',{name:'Lock',exact:true}).click();await page.reload();
 await page.setViewportSize({width:320,height:700});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(320);
 await expect(page.getByRole('heading',{name:'Resume saved setup.'})).toBeVisible();await expect(page.getByText('Resume unfinished Standard setup')).toBeVisible();
 await page.getByLabel('Original 24-word phrase').fill(phrase);await page.getByRole('button',{name:'Resume setup'}).last().click();
 await expect(page.getByRole('status')).toContainText('does not match the unfinished setup');
 expect(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-standard-setup-v1')!))).toMatchObject({state:'ready',address:setup});
 await page.getByLabel('Original 24-word phrase').fill(mnemonic);await page.getByRole('button',{name:'Resume setup'}).last().click();
 await expect(page.getByText('Setup address',{exact:true}).locator('..').locator('code')).toHaveText(setup!);
 await expect(page.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/})).toBeEnabled();
});
test('encrypted Standard pre-Safe setup resumes only with its matching checkpoint',async({page})=>{
 test.skip(!enabled);await choose(page,'Standard');await page.getByRole('button',{name:'Create wallet'}).click();
 const phrase=(await page.locator('.words li').allTextContents()).map(word=>word.replace(/^\d+/,'' )).join(' ');
 await page.getByLabel('I saved the phrase offline.').check();await page.getByRole('button',{name:'Skip check'}).click();
 await page.getByLabel('Password · 12 characters minimum').fill('public-test-password');await page.getByRole('button',{name:'Encrypt and save this browser'}).click();
 const stored=await page.evaluate(()=>JSON.stringify(localStorage));expect(stored).not.toContain(phrase);expect(stored).not.toContain('public-test-password');
 const setup=await page.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();
 expect(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-standard-setup-v1')!))).toMatchObject({version:1,state:'ready',address:setup});
 await page.setViewportSize({width:320,height:700});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(320);
 await expect(page.getByRole('button',{name:'Recover wallet'})).toBeVisible();await expect(page.getByRole('button',{name:'Lock',exact:true})).toBeVisible();
 await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(390);
 await page.reload();await expect(page.getByRole('heading',{name:'Add Ethereum Sepolia test ETH.'})).toBeVisible();
 await page.getByRole('button',{name:'Lock',exact:true}).click();await page.reload();
 await expect(page.getByRole('heading',{name:'Recover your wallet.'})).toBeVisible();
 await page.getByLabel('Standard vault password').fill('public-test-password');await page.getByRole('button',{name:'Recover saved wallet'}).click();
 await expect(page.getByText('Setup address',{exact:true}).locator('..').locator('code')).toHaveText(setup!);
 await page.getByRole('button',{name:'Lock',exact:true}).click();const vault=await page.evaluate(()=>{const data=localStorage.getItem('bunker-vault');localStorage.removeItem('bunker-standard-setup-v1');return data});
 await page.reload();await page.getByLabel('Standard vault password').fill('public-test-password');await page.getByRole('button',{name:'Recover saved wallet'}).click();
 await expect(page.getByRole('status')).toContainText('Saved Standard setup is missing');
 await expect(page.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/})).toHaveCount(0);
 expect(await page.evaluate(()=>localStorage.getItem('bunker-vault'))).toBe(vault);
});
test('leaving during Standard encryption cannot reopen setup or save a partial vault',async({page})=>{
 test.skip(!enabled);await choose(page,'Standard');await page.getByRole('button',{name:'Create wallet'}).click();
 await page.getByLabel('I saved the phrase offline.').check();await page.getByRole('button',{name:'Skip check'}).click();
 await page.getByLabel('Password · 12 characters minimum').fill('public-test-password');
 await page.evaluate(()=>{const original=crypto.subtle.encrypt.bind(crypto.subtle);let release!:()=>void;const gate=new Promise<void>(resolve=>release=resolve);
  (window as any).__releaseVault=release;(crypto.subtle as any).encrypt=async(...args:Parameters<typeof original>)=>{(window as any).__enteredVault=true;await gate;return original(...args)};});
 await page.getByRole('button',{name:'Encrypt and save this browser'}).click();await expect.poll(()=>page.evaluate(()=>Boolean((window as any).__enteredVault))).toBe(true);
 await page.getByRole('button',{name:'Setup options'}).click();await page.evaluate(()=>(window as any).__releaseVault());await page.waitForTimeout(300);
 await expect(page.getByRole('heading',{name:'Choose how to sign.'})).toBeVisible();
 expect(await page.evaluate(()=>[localStorage.getItem('bunker-vault'),localStorage.getItem('bunker-standard-setup-v1')])).toEqual([null,null]);
 await page.reload();await expect(page.getByRole('heading',{name:'One address. Fresh keys.'})).toBeVisible();
});
test('Standard recovery auto-detects an actual guarded Safe',async({page,browser})=>{
 test.skip(!enabled);test.setTimeout(120000);await choose(page,'Standard');await page.getByRole('button',{name:'Create wallet'}).click();
 const mnemonic=(await page.locator('.words li').allTextContents()).map(word=>word.replace(/^\d+/,'')).join(' ');
 await page.getByLabel('I saved the phrase offline.').check();await page.getByRole('button',{name:'Skip check'}).click();await page.getByRole('button',{name:'Continue without password'}).click();
 const setup=await page.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);
 await page.getByRole('button',{name:'I funded it — check balance'}).click();
 expect(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-standard-setup-v1')!))).toMatchObject({state:'ready',address:setup});
 const hashes:string[]=[];await page.context().route(url=>url.origin===RPC,async route=>{const body=route.request().postDataJSON() as {method?:string;params?:string[]};if(body.method==='eth_sendRawTransaction')hashes.push(keccak256(body.params![0] as `0x${string}`));await route.continue()});
 await page.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();
 await expect(page.getByText('Ethereum Sepolia Safe · live')).toBeVisible({timeout:90000});
 const safe=await page.getByRole('button',{name:'Copy stable Safe address'}).locator('code').textContent();
 expect(BigInt(await rpc('eth_getBalance',[safe,'latest']))).toBeGreaterThan(0n);
 const setupHashes=hashes.slice();await page.getByLabel('Recipient').fill('0x000000000000000000000000000000000000cafe');await page.getByLabel('Amount').fill('0.00001');await page.getByRole('button',{name:'Send + rotate key'}).click();await expect(page.locator('.rotation-card strong')).toHaveText('Key 2',{timeout:30000});
 const gas=async(hash:string)=>BigInt((await rpc('eth_getTransactionReceipt',[hash]) as {gasUsed:string}).gasUsed);console.log('GAS_SAMPLE standard',JSON.stringify({setupTransactions:setupHashes.length,setupGas:(await Promise.all(setupHashes.map(gas))).reduce((a,b)=>a+b,0n).toString(),sendGas:(await gas(hashes.at(-1)!)).toString()}));
 expect(await page.evaluate(()=>localStorage.getItem('bunker-standard-setup-v1'))).toBeNull();await page.getByRole('button',{name:'Lock',exact:true}).click();
 await recoverSafe(page,mnemonic,safe!);await expect(page.getByText('Ethereum Sepolia Safe · live')).toBeVisible({timeout:30000});
 expect(await page.evaluate(()=>localStorage.getItem('bunker-vault'))).toBeTruthy();await expect(page.getByText(/Standard · ECDSA only/)).toBeVisible();await expect(page.getByText('ECDSA ROTATION')).toBeVisible();await expect(page.getByText('Single elliptic rotation')).toBeVisible();
 await page.reload();await expect(page.getByText('Ethereum Sepolia Safe · live')).toBeVisible({timeout:30000});
 await expect(page.getByRole('button',{name:'Copy stable Safe address'}).locator('code')).toHaveText(safe!);
 await page.getByRole('button',{name:'Lock',exact:true}).click();await page.reload();await expect(page.getByRole('heading',{name:'Recover your wallet.'})).toBeVisible();await expect(page.getByText('Saved on this browser')).toBeVisible();await expect(page.getByRole('button',{name:'Unlock',exact:true})).toHaveCount(0);await page.getByLabel('Standard vault password').fill('public-test-password');await page.getByRole('button',{name:'Recover saved wallet'}).click();await expect(page.getByText('Ethereum Sepolia Safe · live')).toBeVisible();
 // Lock/navigation during the Safe RPC must not revive a Standard session or persist the Safe.
 const other=await browser.newContext({serviceWorkers:'block'}),fresh=await other.newPage();let release!:()=>void,entered!:()=>void;
 const gate=new Promise<void>(resolve=>release=resolve),hit=new Promise<void>(resolve=>entered=resolve);
 await fresh.route(url=>url.origin===RPC,async route=>{if(route.request().method()==='POST'){const body=route.request().postDataJSON() as {method?:string;params?:unknown[]};if(body.method==='eth_getBalance'&&String(body.params?.[0]).toLowerCase()===safe!.toLowerCase()){entered();await gate}}await route.continue()});
 await fresh.goto('/');await fresh.getByRole('button',{name:'Recover wallet'}).click();await fresh.getByLabel('24-word recovery phrase').fill(mnemonic);await fresh.getByLabel('Existing Safe address').fill(safe!);await fresh.getByLabel('Browser password · 12–256 characters').fill('public-test-password');
 await fresh.locator('.recover-screen').getByRole('button',{name:'Recover and save wallet'}).click();await Promise.race([hit,new Promise((_,reject)=>setTimeout(()=>reject(new Error('Standard Safe RPC was not delayed')),15000))]);
 await fresh.getByRole('button',{name:'← Back'}).click();release();await fresh.waitForTimeout(350);
 expect(await fresh.evaluate(()=>localStorage.getItem('bunker-safe-wallet'))).toBeNull();await expect(fresh.getByText('Ethereum Sepolia Safe · live')).toHaveCount(0);await other.close();
});
test('an uncertain Standard factory broadcast survives Lock without reviving UI or allowing another Safe',async({page})=>{
 test.skip(!enabled);test.setTimeout(120000);await choose(page,'Standard');await page.getByRole('button',{name:'Create wallet'}).click();
 await page.getByLabel('I saved the phrase offline.').check();await page.getByRole('button',{name:'Skip check'}).click();await page.getByRole('button',{name:'Continue without password'}).click();
 const setup=await page.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await page.getByRole('button',{name:'I funded it — check balance'}).click();
 let release!:()=>void,entered!:()=>void,delayed=false;const gate=new Promise<void>(resolve=>release=resolve),hit=new Promise<void>(resolve=>entered=resolve),seen:Record<string,number>={};
 await page.context().route(url=>url.origin===RPC,async route=>{if(!delayed&&route.request().method()==='POST'){const body=route.request().postDataJSON() as {method?:string;params?:unknown[]}|{method?:string;params?:unknown[]}[];
  const calls=Array.isArray(body)?body:[body];for(const call of calls){seen[call.method??'?']=(seen[call.method??'?']??0)+1;if(call.method==='eth_sendRawTransaction'&&typeof call.params?.[0]==='string'){
   const tx=parseTransaction(call.params[0] as `0x${string}`);if(tx.to?.toLowerCase()==='0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67'){delayed=true;entered();await gate;break}
  }}await route.continue();}else await route.continue()});
 await page.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await Promise.race([hit,new Promise((_,reject)=>setTimeout(()=>reject(new Error(`Factory broadcast was not delayed: ${JSON.stringify(seen)}`)),30000))]);
 expect(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-standard-setup-v1')!))).toMatchObject({state:'deploying',address:setup});
 await page.getByRole('button',{name:'Lock',exact:true}).click();release();
 await expect.poll(()=>page.evaluate(()=>localStorage.getItem('bunker-safe-wallet')),{timeout:20000}).not.toBeNull();
 await expect(page.getByRole('heading',{name:'One address. Fresh keys.'})).toBeVisible();await expect(page.getByText('Ethereum Sepolia Safe · live')).toHaveCount(0);
 expect(await page.evaluate(()=>localStorage.getItem('bunker-standard-setup-v1'))).toBeNull();
 await page.getByRole('button',{name:'Create wallet (Testnet)'}).click();await expect(page.getByRole('group',{name:'Saved Standard setup'})).toContainText('Standard wallet already saved');await expect(page.getByRole('button',{name:'Create wallet',exact:true})).toHaveCount(0);
});
test('unknown Standard deployment journal blocks replacement without broadcasting',async({page})=>{
 test.skip(!enabled);await choose(page,'Standard');await page.getByRole('button',{name:'Create wallet'}).click();
 await page.getByLabel('I saved the phrase offline.').check();await page.getByRole('button',{name:'Skip check'}).click();await page.getByRole('button',{name:'Continue without password'}).click();
 const setup=await page.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);
 await page.evaluate(()=>{const key='bunker-standard-setup-v1',value=JSON.parse(localStorage.getItem(key)!);localStorage.setItem(key,JSON.stringify({...value,state:'deploying',factoryHash:'0x'+'11'.repeat(32)}))});
 await page.getByRole('button',{name:'I funded it — check balance'}).click();await expect(page.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/})).toBeDisabled();
 await expect(page.getByText(/Do not create another Safe/)).toBeVisible();await page.getByRole('button',{name:'Lock',exact:true}).click();
 await page.reload();await expect(page.getByRole('alert')).toContainText('A Standard Safe deployment may already exist');
 await page.getByRole('button',{name:'Create wallet (Testnet)'}).click();await expect(page.getByRole('group',{name:'Saved Standard setup'})).toContainText('Standard setup outcome uncertain');await expect(page.getByRole('button',{name:'Create wallet',exact:true})).toHaveCount(0);
 await page.getByRole('slider',{name:'Signing mode'}).fill('1');await expect(page.getByRole('group',{name:'Saved Standard setup'})).toBeVisible();await expect(page.getByRole('button',{name:'Create wallet',exact:true})).toHaveCount(0);await expect(page.getByRole('group',{name:'Replace saved test wallet'})).toHaveCount(0);
});
for(const mode of ['Quantum Shield','Maximum'] as const)test(`${mode}: on-chain Safe selects signing mode for phrase+address recovery`,async({page},testInfo)=>{
 test.skip(!enabled);test.setTimeout(180000);const {panel,mnemonic}=await startNew(page,mode,'public-test-password');
 const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);
 await panel.getByRole('button',{name:'I funded it — check balance'}).click();await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();
 await expect(panel.getByText('Stable Safe address',{exact:true})).toBeVisible({timeout:90000});
 await expect(panel.getByRole('button',{name:'Creating and funding Safe wallet…'})).toHaveCount(0,{timeout:20000});
 const safe=(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).safe as string;
 expect(BigInt(await rpc('eth_getBalance',[safe,'latest']))).toBeGreaterThan(0n);
 await expect(panel.getByLabel('Recipient address')).toHaveValue('vitalik.eth');await expect(panel.getByLabel('Test ETH amount',{exact:true})).toHaveValue('0.0001');
 await expect(panel.getByText('Key 1 → Key 2')).toBeVisible();
 if(mode==='Quantum Shield'){await page.setViewportSize({width:390,height:844});await page.screenshot({path:testInfo.outputPath('pq-wallet-mobile.png')});expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBe(390);await expect(panel.getByRole('button',{name:'Send + rotate key'})).toBeInViewport();await page.setViewportSize({width:1366,height:768});await page.screenshot({path:testInfo.outputPath('pq-wallet-desktop.png')});}
 await panel.getByText('Wallet details & setup funding').click();const ecOwner=await panel.getByText(/Current owner/).locator('code').first().textContent(),nextOwner=await panel.getByText(/Current owner/).locator('code').nth(1).textContent(),pqOwner=await panel.getByText(/Fixed PQ owner/).locator('code').first().textContent();
 await expect(panel.getByLabel('Add more setup test ETH to Safe (optional)')).toBeVisible();
 await panel.getByText('Wallet details & setup funding').click();
 await panel.getByLabel('Recipient address').fill('0x000000000000000000000000000000000000cafe');await panel.getByLabel('Test ETH amount',{exact:true}).fill('0.00001');
 await panel.getByRole('button',{name:'Send + rotate key',exact:true}).click();await expect(panel.getByText('Key 2 → Key 3')).toBeVisible({timeout:20000});
 await panel.getByText('Wallet details & setup funding').click();await expect(panel.getByText(/Fixed PQ owner/).locator('code').first()).toHaveText(pqOwner!);
 await expect(panel.getByText(/Current owner/).locator('code').first()).toHaveText(nextOwner!);expect(nextOwner).not.toBe(ecOwner);
 await expect(panel.getByRole('link',{name:'View actual Sepolia transaction'})).toHaveCount(0);
 expect(JSON.stringify(await page.evaluate(()=>[...Object.entries(localStorage),...Object.entries(sessionStorage)]))).not.toContain(mnemonic);
 await panel.getByRole('button',{name:'Lock / cancel'}).click();const checkpoint=await page.evaluate(()=>localStorage.getItem('bunker-experimental-wallet-v1'));
 const screen=await recovery(page);await screen.getByLabel('24-word recovery phrase').fill(phrase);await screen.getByLabel('Existing Safe address').fill(safe);await screen.getByLabel('Browser password · 12–256 characters').fill('public-test-password');
 await screen.getByRole('button',{name:'Recover and save wallet'}).click();await expect(page.getByRole('region',{name:'Verifying Safe wallet'}).getByRole('heading',{name:'Verifying recovered Safe…'})).toBeVisible();
 await expect(page.locator('.pq-workflow .stepper')).toHaveCount(0);
 await expect(page.getByRole('region',{name:'Verifying Safe wallet'}).getByRole('alert')).toContainText('This browser stores a different experimental vault',{timeout:30000});
 expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-wallet-v1'))).toBe(checkpoint);
 await recoverSafe(page,mnemonic,safe);await expect(panel.getByText('Key 2 → Key 3')).toBeVisible({timeout:30000});
 await expect(panel.getByText(`Sepolia testnet · ${mode}`)).toBeVisible();await expect(page.locator('.pq-workflow .stepper')).toHaveCount(0);
 await panel.getByRole('button',{name:'Lock / cancel'}).click();
 // Saved-vault recovery is first, with phrase+Safe still available below it.
 const savedScreen=await recovery(page);await savedScreen.getByLabel('Experimental vault password').fill('public-test-password');await savedScreen.getByRole('button',{name:'Recover saved wallet'}).click();await expect(panel.getByText('Key 2 → Key 3')).toBeVisible({timeout:30000});
 await panel.getByRole('button',{name:'Lock / cancel'}).click();
 const retainedVault=await page.evaluate(()=>{const vault=localStorage.getItem('bunker-experimental-vault-v1');localStorage.removeItem('bunker-experimental-wallet-v1');return vault});
 const missing=await recovery(page);await missing.getByLabel('Experimental vault password').fill('public-test-password');await missing.getByRole('button',{name:'Recover saved wallet'}).click();
 await expect(page.getByRole('status')).toContainText('checkpoint missing');
 expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-wallet-v1'))).toBeNull();
 await recoverSafe(page,mnemonic,safe);await expect(panel.getByText('Key 2 → Key 3')).toBeVisible({timeout:30000});
 expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-vault-v1'))).toBe(retainedVault);
 await panel.getByRole('button',{name:'Lock / cancel'}).click();await page.evaluate(()=>{localStorage.removeItem('bunker-experimental-wallet-v1');localStorage.removeItem('bunker-experimental-vault-v1')});
 // A fresh-browser attestation interrupted at its last balance RPC must not save a recovery checkpoint.
 let release!:()=>void,entered!:()=>void,delayed=false;const gate=new Promise<void>(resolve=>release=resolve),hit=new Promise<void>(resolve=>entered=resolve);
 await page.route(url=>url.origin===RPC,async route=>{if(!delayed&&route.request().method()==='POST'){const body=route.request().postDataJSON() as {method?:string;params?:unknown[]};if(body.method==='eth_getBalance'&&String(body.params?.[0]).toLowerCase()===safe.toLowerCase()){delayed=true;entered();await gate}}await route.continue()});
 await recoverSafe(page,mnemonic,safe);await Promise.race([hit,new Promise((_,reject)=>setTimeout(()=>reject(new Error('Safe balance RPC was not delayed')),15000))]);
 await page.getByRole('region',{name:'Verifying Safe wallet'}).getByRole('button',{name:'Lock / cancel'}).click();release();await page.waitForTimeout(300);
 expect(await page.evaluate(()=>[localStorage.getItem('bunker-experimental-wallet-v1'),localStorage.getItem('bunker-experimental-vault-v1')])).toEqual([null,null]);
});
test('one click completes every deployment, Safe creation and funding before showing wallet',async({page})=>{
 test.skip(!enabled);test.setTimeout(120000);
 for(const mode of ['Quantum Shield','Maximum'] as const){
  const {panel}=await startNew(page,mode);const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await panel.getByRole('button',{name:'I funded it — check balance'}).click();
  const total=mode==='Quantum Shield'?6:7;await expect(panel.getByLabel('Safe setup transactions').locator('li')).toHaveCount(total);
  let broadcasts=0;const hashes:string[]=[];const route=async(r:import('@playwright/test').Route)=>{const body=r.request().postDataJSON() as {method?:string;params?:string[]};if(body.method==='eth_sendRawTransaction'){broadcasts++;hashes.push(keccak256(body.params![0] as `0x${string}`))}await r.continue()};await page.context().route(url=>url.origin===RPC,route);
  await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await expect(panel.getByRole('button',{name:'Send + rotate key'})).toBeEnabled({timeout:90000});await expect(panel.getByText('ECDSA ROTATION')).toBeVisible();await expect(panel.getByText(mode==='Quantum Shield'?'Rotating ECDSA + fixed SPHINCs+C10':'Rotating ECDSA + fixed ML-DSA-44')).toBeVisible();
  const saved=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(saved.safe).toBeTruthy();expect(saved.pending).toBeUndefined();expect(BigInt(await rpc('eth_getBalance',[saved.safe,'latest']))).toBeGreaterThan(0n);expect(broadcasts).toBe(total);
  await panel.getByLabel('Recipient address').fill('0x000000000000000000000000000000000000cafe');await panel.getByLabel('Test ETH amount').fill('0.00001');await panel.getByRole('button',{name:'Send + rotate key'}).click();await expect(panel.locator('.rotation-card strong')).toContainText('Key 2 → Key 3',{timeout:30000});expect(hashes).toHaveLength(total+1);
  const gas=async(hash:string)=>BigInt((await rpc('eth_getTransactionReceipt',[hash]) as {gasUsed:string}).gasUsed);console.log('GAS_SAMPLE',mode,JSON.stringify({setupTransactions:total,setupGas:(await Promise.all(hashes.slice(0,total).map(gas))).reduce((a,b)=>a+b,0n).toString(),sendGas:(await gas(hashes.at(-1)!)).toString()}));
  await page.context().unroute(url=>url.origin===RPC,route);if(mode==='Quantum Shield'){await panel.getByRole('button',{name:'Lock / cancel'}).click();await page.evaluate(()=>{localStorage.removeItem('bunker-experimental-wallet-v1');localStorage.removeItem('bunker-experimental-vault-v1')})}
 }
});
test('funded Safe with stale balance enters wallet after read-only verification',async({page})=>{
 test.skip(!enabled);test.setTimeout(90000);const {panel}=await startNew(page,'Quantum Shield','public-test-password');const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await panel.getByRole('button',{name:'I funded it — check balance'}).click();
 let broadcasts=0,mask=false,masked=false,hide=0,safe='';await page.context().route(url=>url.origin===RPC,async route=>{const body=route.request().postDataJSON() as {method?:string;id?:number;params?:string[]};if(body.method==='eth_sendRawTransaction'){broadcasts++;const tx=parseTransaction(body.params![0] as `0x${string}`);if(tx.to&&(tx.data??'0x')==='0x'&&(tx.value??0n)>0n){safe=tx.to;mask=true;hide=1}}if(body.method==='eth_getBalance'&&mask&&hide>0&&body.params?.[0]?.toLowerCase()===safe.toLowerCase()){hide--;masked=true;await route.fulfill({json:{jsonrpc:'2.0',id:body.id,result:'0x0'}});return}await route.continue()});
 await panel.getByRole('button',{name:'Create Safe wallet'}).click();await expect(panel.getByRole('button',{name:'Creating and funding Safe wallet…'})).toHaveCount(0,{timeout:70000});await expect(panel.getByRole('heading',{name:'Finish funding your Safe.'})).toBeVisible();expect(masked).toBe(true);expect(broadcasts).toBe(6);expect(BigInt(await rpc('eth_getBalance',[safe,'latest']))).toBeGreaterThan(0n);expect((await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending).toBeUndefined();
 await panel.getByRole('button',{name:/^Finish funding Safe/}).click();await expect(panel.getByRole('button',{name:'Send + rotate key'})).toBeEnabled({timeout:30000});expect(broadcasts).toBe(6);
 await panel.getByRole('button',{name:'Lock / cancel'}).click();masked=false;hide=2;await page.reload();await page.getByLabel('Experimental vault password').fill('public-test-password');await page.getByRole('button',{name:'Recover saved wallet'}).click();const recovered=page.getByRole('region',{name:'Experimental PQ wallet'});await expect(recovered.getByRole('heading',{name:'Finish funding your Safe.'})).toBeVisible({timeout:30000});expect(masked).toBe(true);await recovered.getByRole('button',{name:'Verify funded Safe'}).click();await expect(recovered.getByRole('button',{name:'Send + rotate key'})).toBeEnabled({timeout:30000});expect(broadcasts).toBe(6);
});
test('uncertain pre-Safe deployment is visible without opening wallet details',async({page})=>{
 test.skip(!enabled);const {panel}=await startNew(page);const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await panel.getByRole('button',{name:'I funded it — check balance'}).click();
 let broadcasts=0;await page.context().route(url=>url.origin===RPC,async route=>{const body=route.request().postDataJSON() as {method?:string;id?:number};if(body.method==='eth_sendRawTransaction'){broadcasts++;await route.fulfill({json:{jsonrpc:'2.0',id:body.id,error:{code:-32000,message:'simulated unknown broadcast'}}});return}await route.continue()});
 await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await expect(panel.getByRole('alert').filter({hasText:'Setup transaction pending'})).toBeVisible();await expect(panel.getByLabel('Safe setup transactions').getByText('Transaction 1 of 6')).toBeVisible();await expect(panel.getByLabel('Safe setup transactions').locator('li')).toHaveCount(6);await expect(panel.getByLabel('Safe setup transactions').locator('li').first()).toContainText('Awaiting confirmation');await expect(panel.getByLabel('Safe setup transactions').locator('li').last()).toContainText('Remaining');await expect(panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/})).toBeDisabled();await expect(panel.getByText('Wallet details & setup funding')).toBeVisible();expect(broadcasts).toBe(1);
 expect((await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending?.kind).toBe('helper');
});
test('forged initial mined deployment receipt cannot poison the saved checkpoint',async({page})=>{
 test.skip(!enabled);const {panel}=await startNew(page);const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await panel.getByRole('button',{name:'I funded it — check balance'}).click();
 let broadcasts=0,forged=2;await page.context().route(url=>url.origin===RPC,async route=>{const body=route.request().postDataJSON() as {method?:string};if(body.method==='eth_sendRawTransaction')broadcasts++;if(body.method==='eth_getTransactionReceipt'&&forged){const response=await route.fetch(),json=await response.json();if(json.result){forged--;json.result.contractAddress='0x0000000000000000000000000000000000001234';await route.fulfill({json});return}}await route.continue()});
 await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await expect(panel.getByRole('button',{name:'Creating and funding Safe wallet…'})).toHaveCount(0,{timeout:20000});const blocked=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(blocked.pending?.kind).toBe('helper');expect(blocked.parts.helper).toBeUndefined();expect(forged).toBe(0);expect(broadcasts).toBe(1);
 await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByRole('alert').filter({hasText:'Setup transaction pending'})).toHaveCount(0,{timeout:20000});const settled=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(settled.pending).toBeUndefined();expect(settled.parts.helper).toBeTruthy();expect(broadcasts).toBe(1);
});
test('a forged reverted receipt cannot discard a mined pre-Safe signed intent',async({page})=>{
 test.skip(!enabled);const {panel}=await startNew(page);const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await panel.getByRole('button',{name:'I funded it — check balance'}).click();
 let broadcasts=0,forged=2;await page.context().route(url=>url.origin===RPC,async route=>{const body=route.request().postDataJSON() as {method?:string};if(body.method==='eth_sendRawTransaction')broadcasts++;if(body.method==='eth_getTransactionReceipt'&&forged){const response=await route.fetch(),json=await response.json();if(json.result){forged--;json.result.status='0x0';await route.fulfill({json});return}}await route.continue()});
 await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await expect(panel.getByRole('button',{name:'Creating and funding Safe wallet…'})).toHaveCount(0,{timeout:20000});const original=(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending;expect(original?.kind).toBe('helper');expect(broadcasts).toBe(1);
 await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByRole('status')).toHaveCount(0);expect((await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending).toEqual(original);expect(broadcasts).toBe(1);expect(forged).toBe(0);
 await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByRole('alert').filter({hasText:'Setup transaction pending'})).toHaveCount(0,{timeout:20000});const settled=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(settled.pending).toBeUndefined();expect(settled.parts.helper).toBeTruthy();expect(broadcasts).toBe(1);
});
test('mined pre-Safe deployment with lost RPC response reconciles without another broadcast',async({page})=>{
 test.skip(!enabled);const {panel}=await startNew(page);const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await panel.getByRole('button',{name:'I funded it — check balance'}).click();
 let broadcasts=0,lose=true,forgedReads=3;await page.context().route(url=>url.origin===RPC,async route=>{const body=route.request().postDataJSON() as {method?:string;id?:number};if(body.method==='eth_sendRawTransaction'){broadcasts++;if(lose){lose=false;await route.fetch();await route.fulfill({json:{jsonrpc:'2.0',id:body.id,error:{code:-32000,message:'lost RPC response after mining'}}});return}}if(body.method==='eth_getTransactionReceipt'&&forgedReads>0){const response=await route.fetch(),json=await response.json();if(json.result){forgedReads--;json.result.contractAddress='0x0000000000000000000000000000000000001234';await route.fulfill({json});return}}await route.continue()});
 await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await expect(panel.getByRole('alert').filter({hasText:'Setup transaction pending'})).toBeVisible();const original=(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending;
 await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByRole('alert').filter({hasText:'Original deployment address does not match'})).toBeVisible();expect((await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending).toEqual(original);expect(broadcasts).toBe(1);
 await panel.getByText('Wallet details & setup funding').click();await panel.getByRole('button',{name:'Rebroadcast same signed transaction'}).click();await expect(panel.getByRole('status')).toHaveCount(0);await expect(panel.getByRole('alert').filter({hasText:'Original deployment address does not match'})).toBeVisible();expect(forgedReads).toBe(0);expect((await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending).toEqual(original);expect(broadcasts).toBe(1);
 await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByRole('alert').filter({hasText:'Setup transaction pending'})).toHaveCount(0,{timeout:20000});
 const saved=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(saved.pending).toBeUndefined();expect(saved.parts.helper).toBe(await rpc('eth_getTransactionReceipt',[original.hash]).then((receipt:{contractAddress:string})=>receipt.contractAddress));expect(broadcasts).toBe(1);
 await expect(panel.getByLabel('Safe setup transactions').getByText('Transaction 2 of 6')).toBeVisible();await expect(panel.getByLabel('Safe setup transactions').locator('li').first()).toContainText('Confirmed');await expect(panel.getByRole('button',{name:'Continue setup — transaction 2 of 6'})).toBeEnabled();
 for(const kind of ['SphincsC10Asm','MLDSA44Verifier','ExperimentalFactory']){lose=true;const before=broadcasts;await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await expect(panel.getByRole('button',{name:'Creating and funding Safe wallet…'})).toHaveCount(0,{timeout:30000});const checkpoint=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(checkpoint.pending?.kind).toBe(kind);await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByRole('alert').filter({hasText:'Setup transaction pending'})).toHaveCount(0,{timeout:20000});const next=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(next.pending).toBeUndefined();expect(next.parts[kind]).toBeTruthy();expect(broadcasts).toBe(before+1)}
});
test('Maximum prepared-key blob reconciles exact bytes before continuing setup',async({page})=>{
 test.skip(!enabled);test.setTimeout(90000);const {panel}=await startNew(page,'Maximum');const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await panel.getByRole('button',{name:'I funded it — check balance'}).click();
 let broadcasts=0;await page.context().route(url=>url.origin===RPC,async route=>{const body=route.request().postDataJSON() as {method?:string;id?:number};if(body.method==='eth_sendRawTransaction'&&++broadcasts===4){await route.fetch();await route.fulfill({json:{jsonrpc:'2.0',id:body.id,error:{code:-32000,message:'lost prepared-blob response'}}});return}await route.continue()});
 await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await expect(panel.getByRole('button',{name:'Creating and funding Safe wallet…'})).toHaveCount(0,{timeout:60000});const checkpoint=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(checkpoint.pending?.kind).toBe('blob');await expect(panel.getByLabel('Safe setup transactions').getByText('Transaction 4 of 7')).toBeVisible();await expect(panel.getByLabel('Safe setup transactions').locator('li').nth(3)).toContainText('Awaiting confirmation');await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByRole('alert').filter({hasText:'Setup transaction pending'})).toHaveCount(0,{timeout:30000});const saved=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(saved.pending).toBeUndefined();expect(await rpc('eth_getCode',[saved.parts.blob,'latest'])).toBe(bytesToHex(prepareMLDSA(hexToBytes(saved.publicKey))));expect(broadcasts).toBe(4);await expect(panel.getByRole('button',{name:'Continue setup — transaction 5 of 7'})).toBeEnabled();
});
test('mined Safe creation with lost RPC response reconciles without another broadcast',async({page})=>{
 test.skip(!enabled);test.setTimeout(90000);const {panel}=await startNew(page);const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await panel.getByRole('button',{name:'I funded it — check balance'}).click();
 let broadcasts=0,lost=false;await page.context().route(url=>url.origin===RPC,async route=>{const body=route.request().postDataJSON() as {method?:string;id?:number;params?:string[]};if(body.method==='eth_sendRawTransaction'){broadcasts++;if(!lost&&parseTransaction(body.params![0] as `0x${string}`).to){lost=true;await route.fetch();await route.fulfill({json:{jsonrpc:'2.0',id:body.id,error:{code:-32000,message:'lost creation receipt response'}}});return}}await route.continue()});
 await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await expect(panel.getByRole('button',{name:'Creating and funding Safe wallet…'})).toHaveCount(0,{timeout:60000});await expect(panel.getByRole('alert').filter({hasText:'Setup transaction pending'})).toBeVisible();const before=broadcasts,original=(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending;expect(original.kind).toBe('create');await expect(panel.getByLabel('Safe setup transactions').getByText('Transaction 5 of 6')).toBeVisible();
 await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByText('Safe address',{exact:true})).toBeVisible({timeout:30000});const saved=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(saved.pending).toBeUndefined();expect(saved.safe).toBeTruthy();expect(broadcasts).toBe(before);expect(BigInt(await rpc('eth_getBalance',[saved.safe,'latest']))).toBe(0n);
 await expect(panel.getByRole('button',{name:'Send + rotate key'})).toHaveCount(0);await expect(panel.getByLabel('Safe setup transactions').getByText('Transaction 6 of 6')).toBeVisible();await panel.getByRole('button',{name:/^Finish funding Safe/}).click();await expect(panel.getByRole('button',{name:'Send + rotate key'})).toBeEnabled({timeout:20000});expect(BigInt(await rpc('eth_getBalance',[saved.safe,'latest']))).toBeGreaterThan(0n);expect(broadcasts).toBe(before+1);
});
test('forged revert on a mined Safe creation cannot authorize a second Safe',async({page})=>{
 test.skip(!enabled);test.setTimeout(90000);const {panel}=await startNew(page);const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);await panel.getByRole('button',{name:'I funded it — check balance'}).click();
 let broadcasts=0,forged=2;await page.context().route(url=>url.origin===RPC,async route=>{const body=route.request().postDataJSON() as {method?:string};if(body.method==='eth_sendRawTransaction')broadcasts++;if(body.method==='eth_getTransactionReceipt'&&forged){const response=await route.fetch(),json=await response.json();if(json.result?.to){forged--;json.result.status='0x0';await route.fulfill({json});return}}await route.continue()});
 await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();await expect(panel.getByRole('button',{name:'Creating and funding Safe wallet…'})).toHaveCount(0,{timeout:60000});const original=(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending;expect(original?.kind).toBe('create');const before=broadcasts;await expect(panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/})).toBeDisabled();
 await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByRole('status')).toHaveCount(0);expect((await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).pending).toEqual(original);expect(broadcasts).toBe(before);expect(forged).toBe(0);
 await panel.getByRole('button',{name:'Check original transaction status'}).click();await expect(panel.getByText('Safe address',{exact:true})).toBeVisible({timeout:30000});const saved=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));expect(saved.pending).toBeUndefined();expect(saved.safe).toBeTruthy();expect(broadcasts).toBe(before);
});
test('a saved partial PQ checkpoint resumes separately from existing-Safe recovery',async({page})=>{
 test.skip(!enabled);const {panel,mnemonic}=await startNew(page);await panel.getByRole('button',{name:'Lock / cancel'}).click();
 await page.evaluate(()=>localStorage.removeItem('bunker-experimental-vault-v1'));await page.getByRole('button',{name:'Recover wallet'}).click();await expect(page.getByRole('button',{name:'Enter original phrase'})).toBeVisible();
 await page.getByRole('button',{name:'Enter original phrase'}).click();await panel.getByLabel('Original 24-word phrase').fill(mnemonic);await panel.getByRole('button',{name:'Recover interrupted setup'}).click();
 await expect(panel.getByText('Setup address',{exact:true})).toBeVisible({timeout:30000});
});
test('a vault without its public checkpoint cannot silently create another Safe',async({page})=>{
 test.skip(!enabled);const {panel}=await startNew(page,'Quantum Shield','public-test-password');await panel.getByRole('button',{name:'Lock / cancel'}).click();
 const vault=await page.evaluate(()=>{const data=localStorage.getItem('bunker-experimental-vault-v1');localStorage.removeItem('bunker-experimental-wallet-v1');return data});
 await page.getByRole('button',{name:'Recover wallet'}).click();await page.getByLabel('Experimental vault password').fill('public-test-password');await page.getByRole('button',{name:'Recover saved wallet'}).click();
 await expect(page.getByRole('status')).toContainText('checkpoint missing');await expect(panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/})).toHaveCount(0);
 expect(await page.evaluate(()=>[localStorage.getItem('bunker-experimental-wallet-v1'),localStorage.getItem('bunker-experimental-vault-v1')])).toEqual([null,vault]);
 await page.getByRole('button',{name:'Setup options'}).click();await page.getByRole('slider',{name:'Signing mode'}).fill('1');
 await expect(page.getByRole('group',{name:'Unverified saved experimental setup'})).toBeVisible();await expect(page.getByRole('group',{name:'Replace saved test wallet'})).toHaveCount(0);
 expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-vault-v1'))).toBe(vault);
});
test('replacing a confirmed test wallet deletes local data, not its on-chain Safe',async({page})=>{
 test.skip(!enabled);test.setTimeout(120000);const {panel,mnemonic}=await startNew(page,'Quantum Shield','public-test-password');
 const setup=await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent();await rpc('anvil_setBalance',[setup,'0x3635c9adc5dea00000']);
 await panel.getByRole('button',{name:'I funded it — check balance'}).click();await panel.getByRole('button',{name:/^(Create Safe wallet|Continue setup)/}).click();
 await expect(panel.getByText('Stable Safe address',{exact:true})).toBeVisible({timeout:90000});const safe=(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!))).safe as string;
 const code=await rpc('eth_getCode',[safe,'latest']);await panel.getByRole('button',{name:'Lock / cancel'}).click();
 await page.getByRole('button',{name:'Create wallet (Testnet)'}).click();await page.getByRole('slider',{name:'Signing mode'}).fill('1');
 const confirm=page.getByRole('group',{name:'Replace saved test wallet'});await expect(confirm).toBeVisible();await confirm.getByRole('checkbox').check();let broadcasts=0;
 await page.context().route(url=>url.origin===RPC,async route=>{if(route.request().method()==='POST'&&(route.request().postDataJSON() as {method?:string}).method==='eth_sendRawTransaction')broadcasts++;await route.continue()});
 await confirm.getByRole('button',{name:'Continue — replace local wallet'}).click();await expect(page.getByRole('heading',{name:'Write down these 24 words.'})).toBeVisible();
 expect(await page.evaluate(()=>[localStorage.getItem('bunker-experimental-wallet-v1'),localStorage.getItem('bunker-experimental-vault-v1')])).toEqual([null,null]);expect(broadcasts).toBe(0);
 expect(await rpc('eth_getCode',[safe,'latest'])).toBe(code);
 await recoverSafe(page,mnemonic,safe);await expect(panel.getByText('Stable Safe address',{exact:true})).toBeVisible({timeout:30000});
});
test('a pending outbox cannot be discarded by unknown Safe recovery',async({page})=>{
 test.skip(!enabled);const {panel}=await startNew(page);await panel.getByRole('button',{name:'Lock / cancel'}).click();
 const original=await page.evaluate(()=>{const record=JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!);record.safe='0x0000000000000000000000000000000000001234';record.pending={kind:'fund',hash:'0x'+'11'.repeat(32)};const raw=JSON.stringify(record);localStorage.setItem('bunker-experimental-wallet-v1',raw);return raw});
 const screen=await recovery(page);await screen.getByLabel('24-word recovery phrase').fill(phrase);await screen.getByLabel('Existing Safe address').fill('0x0000000000000000000000000000000000005678');await screen.getByLabel('Browser password · 12–256 characters').fill('public-test-password');await screen.getByRole('button',{name:'Recover and save wallet'}).click();
 await expect(page.getByRole('status')).toContainText('Not a supported Safe proxy');expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-wallet-v1'))).toBe(original);
 await page.getByRole('button',{name:'Setup options'}).click();await page.getByRole('slider',{name:'Signing mode'}).fill('1');
 await expect(page.getByRole('group',{name:'Pending saved experimental setup'})).toBeVisible();await expect(page.getByRole('group',{name:'Replace saved test wallet'})).toHaveCount(0);
 expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-wallet-v1'))).toBe(original);await page.getByRole('group',{name:'Pending saved experimental setup'}).getByRole('button',{name:'Cancel'}).click();
 const malformed=await page.evaluate(()=>{const record=JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!);record.pending=null;const raw=JSON.stringify(record);localStorage.setItem('bunker-experimental-wallet-v1',raw);return raw});
 await page.getByRole('button',{name:'Setup options'}).click();await page.getByRole('slider',{name:'Signing mode'}).fill('1');await expect(page.getByRole('group',{name:'Unverified saved experimental setup'})).toBeVisible();
 await expect(page.getByRole('group',{name:'Replace saved test wallet'})).toHaveCount(0);expect(await page.evaluate(()=>localStorage.getItem('bunker-experimental-wallet-v1'))).toBe(malformed);
});
