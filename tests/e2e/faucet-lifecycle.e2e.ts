import {test,expect,type Page} from '@playwright/test';
import {createPublicClient,createWalletClient,http,parseEther,formatEther,keccak256,parseAbi,type Address,type Hex} from 'viem';
import {mnemonicToAccount,privateKeyToAccount} from 'viem/accounts';
import {sepolia} from 'viem/chains';
import fixture from '../fixtures/sepolia-safe-1.4.1.json';
import {bunkerGuardRuntimeHash as standardV3GuardHash} from '../../apps/web/src/safeArtifactsV3';

// Disposable chain only. Supply an ephemeral Anvil genesis account and a predeployed local V2 or V3 factory.
const enabled=process.env.BROWSER_FAUCET_E2E==='1';
const rpc='http://127.0.0.1:18545';
const publicClient=createPublicClient({chain:sepolia,transport:http(rpc),pollingInterval:100});
const ownerABI=parseAbi(['function getOwners() view returns (address[])','function nonce() view returns (uint256)']);
test.use({trace:'off'});
test.describe.configure({mode:'serial'});
test.setTimeout(120000);

let faucet:ReturnType<typeof privateKeyToAccount>;
test.beforeAll(async()=>{
 if(!enabled)return;
 expect(await publicClient.getChainId()).toBe(11155111);
 for(const path of ['/src/burner.ts','/src/pq/wallet.ts'])expect(await fetch(`http://127.0.0.1:4173${path}`).then(r=>r.text())).toContain(rpc);
 const key=process.env.LOCAL_FAUCET_PRIVATE_KEY as Hex|undefined;
 if(!key||!/^0x[0-9a-fA-F]{64}$/.test(key))throw new Error('Provide an ephemeral LOCAL_FAUCET_PRIVATE_KEY for disposable Anvil');
 faucet=privateKeyToAccount(key);
 expect(await publicClient.getBalance({address:faucet.address})).toBeGreaterThan(parseEther('1'));
 for(const code of Object.values(fixture.codes))await publicClient.request({method:'anvil_setCode' as never,params:[code.address,code.runtime] as never});
 const factory=(process.env.VITE_EXPERIMENTAL_V3_LOCAL_FACTORY||process.env.VITE_EXPERIMENTAL_V2_LOCAL_FACTORY) as Address|undefined;
 if(!factory||!(await publicClient.getCode({address:factory})))throw new Error('Deploy the shared local factory before the browser suite');
});

async function receipt(hash:Hex){const result=await publicClient.waitForTransactionReceipt({hash,timeout:60000});expect(result.status).toBe('success');return result}
async function sweep(account:ReturnType<typeof mnemonicToAccount>){
 const balance=await publicClient.getBalance({address:account.address});if(!balance)return;
 const gasPrice=await publicClient.getGasPrice(),gas=21000n;
 expect(balance).toBeGreaterThan(gas*gasPrice);
 const client=createWalletClient({account,chain:sepolia,transport:http(rpc)});
 await receipt(await client.sendTransaction({to:faucet.address,value:balance-gas*gasPrice,gas,gasPrice,type:'legacy'}));
 expect(await publicClient.getBalance({address:account.address})).toBe(0n);
}
async function createBrowserWallet(page:Page,mode:'Standard'|'Quantum Shield'|'Maximum'){
 await page.goto('/');await page.getByRole('button',{name:'Create wallet (Testnet)'}).click();
 await page.getByRole('button',{name:`Select ${mode}`}).click();await page.getByRole('button',{name:'Create wallet',exact:true}).click();
 const phrase=(await page.locator('.words li').allTextContents()).map(word=>word.replace(/^\d+/,'')).join(' ');
 await page.getByRole('checkbox',{name:'I saved the phrase offline.'}).check();await page.getByRole('button',{name:'Skip check'}).click();
 if(mode==='Standard')await page.getByRole('button',{name:'Continue without password'}).click();else{await page.getByLabel('Password · 12 characters minimum').fill('public-test-password');await page.getByRole('button',{name:'Encrypt and save this browser'}).click()}

 const panel=mode==='Standard'?page.locator('.setup'):page.getByRole('region',{name:'Experimental PQ wallet'});
 const address=(await panel.getByText('Setup address',{exact:true}).locator('..').locator('code').textContent()) as Address;
 expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
 return {phrase,panel,address};
}

for(const mode of ['Standard','Quantum Shield','Maximum'] as const)test(`faucet → create → send/rotate → return: ${mode}`,async({page})=>{
 test.skip(!enabled);
 const start=await publicClient.getBalance({address:faucet.address});
 const {phrase,panel,address}=await createBrowserWallet(page,mode);
 const derived=(index:number)=>mnemonicToAccount(phrase,{path:`m/44'/60'/7331'/0/${index}`});
 expect(address.toLowerCase()).toBe(derived(0).address.toLowerCase());
 const funding=parseEther('0.08');
 const fundingReceipt=await receipt(await createWalletClient({account:faucet,chain:sepolia,transport:http(rpc)}).sendTransaction({to:address,value:funding}));
 expect(fundingReceipt.to?.toLowerCase()).toBe(address.toLowerCase());
 expect(await publicClient.getBalance({address})).toBe(funding);
 await panel.getByRole('button',{name:'I funded it — check balance'}).click();
 const broadcasts:Hex[]=[];
 await page.context().route(url=>url.origin===new URL(rpc).origin,async route=>{
  const request=route.request().postDataJSON() as {method?:string;params?:string[]};
  if(request.method==='eth_sendRawTransaction'&&request.params?.[0])broadcasts.push(keccak256(request.params[0] as Hex));
  await route.continue();
 });
 await panel.getByRole('button',{name:'Create Safe wallet'}).click();
 if(mode==='Standard')await expect(page.getByText('Ethereum Sepolia Safe · live')).toBeVisible({timeout:90000});
 else await expect(panel.getByRole('button',{name:'Send + rotate key'})).toBeEnabled({timeout:90000});
 const safe=(mode==='Standard'?await page.getByRole('button',{name:'Copy stable Safe address'}).locator('code').textContent():await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!).safe)) as Address;
 expect(safe).toMatch(/^0x[0-9a-fA-F]{40}$/);
 if(mode!=='Standard'){
  const record=await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!));
  const v3=process.env.VITE_EXPERIMENTAL_V3_LOCAL_FACTORY;
  expect(record.parts[v3?'ExperimentalSharedFactoryV3':'ExperimentalSharedFactoryV2']?.toLowerCase()).toBe((v3||process.env.VITE_EXPERIMENTAL_V2_LOCAL_FACTORY)!.toLowerCase());
  expect(record.parts[v3?'ExperimentalSharedFactoryV2':'ExperimentalSharedFactoryV3']).toBeUndefined();
 }
 if(mode==='Standard'){
  const slot=await publicClient.getStorageAt({address:safe,slot:'0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8'});
  expect(slot).toBeTruthy();const guard=`0x${slot!.slice(-40)}` as Address;
  expect(keccak256((await publicClient.getCode({address:guard}))!)).toBe(standardV3GuardHash);
 }
 const ownersBefore=await publicClient.readContract({address:safe,abi:ownerABI,functionName:'getOwners'});
 const sendPanel=mode==='Standard'?page.locator('.wallet'):panel;
 const to=sendPanel.getByLabel(mode==='Standard'?'Recipient':'Recipient address');
 const amount=sendPanel.getByLabel(mode==='Standard'?'Amount':'Test ETH amount');
 await to.fill(faucet.address);await amount.fill('0.0001');
 const beforeFirst=broadcasts.length;
 await sendPanel.getByRole('button',{name:'Send + rotate key'}).click();
 await expect(sendPanel.locator('.rotation-card strong')).toContainText(mode==='Standard'?'Key 2':'Key 2 → Key 3',{timeout:45000});
 expect(broadcasts.length).toBe(beforeFirst+1);await receipt(broadcasts.at(-1)!);
 const ownersAfter=await publicClient.readContract({address:safe,abi:ownerABI,functionName:'getOwners'});
 expect(ownersAfter.map(x=>x.toLowerCase())).not.toEqual(ownersBefore.map(x=>x.toLowerCase()));
 expect(ownersAfter.map(x=>x.toLowerCase())).toContain(derived(1).address.toLowerCase());
 expect(await publicClient.getBalance({address:derived(1).address})).toBeGreaterThanOrEqual(parseEther('0.001'));
 if(mode==='Maximum')await receipt(await createWalletClient({account:faucet,chain:sepolia,transport:http(rpc)}).sendTransaction({to:derived(1).address,value:parseEther('0.003')}));
 const remainder=await publicClient.getBalance({address:safe});expect(remainder).toBeGreaterThan(parseEther('0.001'));
 await amount.fill(formatEther(remainder-parseEther('0.001')));
 const beforeReturn=await publicClient.getBalance({address:faucet.address});
 await sendPanel.getByRole('button',{name:'Send + rotate key'}).click();
 await expect.poll(()=>broadcasts.length,{timeout:45000}).toBe(beforeFirst+2);await receipt(broadcasts.at(-1)!);
 if(mode==='Standard')await expect(sendPanel.locator('.rotation-card strong')).toContainText('Key 3');
 else await expect(panel.getByRole('heading',{name:'Finish funding your Safe.'})).toBeVisible();
 expect(await publicClient.getBalance({address:safe})).toBe(0n);
 expect(await publicClient.getBalance({address:faucet.address})).toBeGreaterThan(beforeReturn);
 const ownersReturned=await publicClient.readContract({address:safe,abi:ownerABI,functionName:'getOwners'});
 expect(ownersReturned).not.toEqual(ownersAfter);
 expect(ownersReturned.map(x=>x.toLowerCase())).toContain(derived(2).address.toLowerCase());
 expect(await publicClient.getBalance({address:derived(2).address})).toBeGreaterThanOrEqual(parseEther('0.001'));
 if(mode==='Standard')expect(await page.evaluate(()=>localStorage.getItem('bunker-standard-setup-v1'))).toBeNull();
 else expect(await page.evaluate(()=>JSON.parse(localStorage.getItem('bunker-experimental-wallet-v1')!).pending)).toBeUndefined();
 for(const hash of broadcasts)await receipt(hash);
 // Return gas reserves from the setup key and both newly funded broadcaster keys.
 for(let index=0;index<=2;index++)await sweep(derived(index));
 expect(await publicClient.getBalance({address:faucet.address})).toBeLessThan(start); // Only network gas is spent.
 expect(await publicClient.getBalance({address:safe})).toBe(0n);
});
