// Disposable Sepolia only. Never use these phrases for real funds. No automatic replacement of uncertain transactions.
import {readFileSync,existsSync,openSync,closeSync,writeFileSync,fsyncSync,renameSync,statSync} from 'node:fs';
import {dirname} from 'node:path';
import {strict as assert} from 'node:assert';
import {createPublicClient,createWalletClient,http,encodeDeployData,keccak256,getContractAddress,parseEther,formatEther,parseTransaction,recoverTransactionAddress,bytesToHex,hexToBytes,padHex,toHex,parseAbi, type Address,type Hex} from 'viem';
import {mnemonicToAccount} from 'viem/accounts';
import {sepolia} from 'viem/chains';
import {entropyToMnemonic,mnemonicToSeed} from '@scure/bip39';
import {wordlist} from '@scure/bip39/wordlists/english.js';
import {ml_dsa44} from '@noble/post-quantum/ml-dsa.js';
import {derivePQSeed,prepareMLDSA,c10Keygen,c10Sign,type C10Wasm,type PQMode} from '../packages/pq/src/keys';
import {createExperimentalWallet,artifacts,runtime,dataCreation,validateRecord,type WalletRecord} from '../apps/web/src/pq/wallet';
import {outboxKey,sealTransaction} from '../apps/web/src/pq/outbox';
import type {PQSigner} from '../apps/web/src/pq/signer';
import v2 from '../apps/web/src/pq/generated/artifactsV2.json';

const stage=process.argv[2]??'',local=process.env.BUNKER_V2_RPC?.startsWith('http://127.0.0.1:')??false;
if(!['infra','fund-c10','test-c10','fund-mldsa44','test-mldsa44'].includes(stage))throw new Error('Choose infra, fund-c10, test-c10, fund-mldsa44 or test-mldsa44');
if(!local&&process.env.BUNKER_V2_CONFIRM!=='sepolia-test-eth-1-max')throw new Error('Explicit 1 test ETH Sepolia authorization required');
const rpc=process.env.BUNKER_V2_RPC??'https://ethereum-sepolia.publicnode.com',client=createPublicClient({chain:sepolia,transport:http(rpc),pollingInterval:local?50:4000});
const root='/root/bunker-hybrid-validation/private',prefix=local?'v2-local':'v2-sepolia',envPath='/root/.config/bunker-wallet/secrets/sepolia-e2e.env';
if(statSync(envPath).mode&0o077)throw new Error('Configured mnemonic file must be private');
const env=Object.fromEntries(readFileSync(envPath,'utf8').split(/\r?\n/).filter(x=>x.includes('=')).map(x=>{const[k,...v]=x.split('=');return[k,v.join('=').replace(/^"|"$/g,'')]}));
const payer=mnemonicToAccount(env.BUNKER_SEPOLIA_MNEMONIC,{path:"m/44'/60'/7331'/0/0"});
assert.equal(payer.address.toLowerCase(),env.BUNKER_SEPOLIA_SETUP_ADDRESS.toLowerCase());
assert.equal(await client.getChainId(),11155111);
const durable=(path:string,value:unknown)=>{const temp=`${path}.${process.pid}.tmp`,fd=openSync(temp,'w',0o600);try{writeFileSync(fd,JSON.stringify(value));fsyncSync(fd)}finally{closeSync(fd)}renameSync(temp,path);const dir=openSync(dirname(path),'r');try{fsyncSync(dir)}finally{closeSync(dir)}};
const load=<T>(path:string):T|undefined=>existsSync(path)?JSON.parse(readFileSync(path,'utf8')) as T:undefined;
const sources={singleton:'0x41675C099F32341bf84BFc5382aF534df5C7461a',proxyFactory:'0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67',multi:'0x9641d764fc13c8B624c04430C7356C1C7C8102e2',helper:'0xea655ad17483b3b1ad68c8ff69ff8166489ea71c',c10:'0x69105696002246141c78c6c7af1c8c855814c043',mldsa:'0x2f214312ce536d65e4d04a03cd9a2c4b9f592d51'} as const;
const proxyHash='0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c' as Hex;
const officialHashes={singleton:'0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4',proxyFactory:'0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317',multi:'0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939'} as const;
const sourceCode=Object.fromEntries(await Promise.all(Object.entries(sources).map(async([name,address])=>[name,await client.getCode({address})]))) as Record<keyof typeof sources,Hex>;
for(const[name,hash]of Object.entries(officialHashes))assert.equal(keccak256(sourceCode[name as keyof typeof sources]),hash,`${name} canonical runtime`);
assert.equal(sourceCode.helper.toLowerCase(),artifacts.helper.toLowerCase());
assert.equal(sourceCode.c10.toLowerCase(),runtime('SphincsC10Asm',{}).toLowerCase());
assert.equal(sourceCode.mldsa.toLowerCase(),runtime('MLDSA44Verifier',{F1600:sources.helper}).toLowerCase());
const dep=(name:keyof typeof sources)=>({target:sources[name],codeHash:keccak256(sourceCode[name])});
const args=[dep('singleton'),dep('proxyFactory'),dep('multi'),dep('c10'),dep('mldsa'),dep('helper'),proxyHash] as const;
const factoryData=encodeDeployData({abi:v2.abi,bytecode:v2.bytecode as Hex,args});
const ledgerPath=`${root}/${prefix}-budget.json`,manifestPath=`${root}/${prefix}-manifest.json`,phrasesPath=`${root}/${prefix}-phrases.json`;
type Entry={kind:string;hash:Hex;ceiling:string;value:string;gas:string;maxFeePerGas:string;receiptBlock?:string;gasUsed?:string;effectiveGasPrice?:string;contractAddress?:Address};
type Ledger={pending?:Entry&{sealed:{iv:Hex;ciphertext:Hex}};completed:Entry[]};
let ledger=load<Ledger>(ledgerPath)??{completed:[]};
if(ledger.pending){let status='not found';try{const r=await client.getTransactionReceipt({hash:ledger.pending.hash});status=`${r.status} in block ${r.blockNumber}`}catch{}throw new Error(`Original ${ledger.pending.kind} transaction ${ledger.pending.hash} is ${status}; inspect/resolve this journal, no replacement broadcast`)}
// ponytail: one sequential runner owns these journals; add an interprocess lock before parallel live runs.
const globalReserved=()=>ledger.completed.reduce((sum,entry)=>sum+BigInt(entry.ceiling),ledger.pending?BigInt(ledger.pending.ceiling):0n)+(['c10','mldsa44'] as const).reduce((sum,mode)=>sum+Object.values(load<Record<Hex,string>>(`${root}/${prefix}-${mode}-budget.json`)??{}).reduce((total,ceiling)=>total+BigInt(ceiling),0n),0n);
const budget=parseEther('1'),balance=await client.getBalance({address:payer.address});
if(globalReserved()>budget||balance===0n)throw new Error('Global budget or payer balance unavailable');
const secretKey=await outboxKey(env.BUNKER_SEPOLIA_MNEMONIC,`${prefix}-${payer.address}`);
async function sourceTransaction(kind:string,to:Address|undefined,value:bigint,data:Hex){
 if(ledger.completed.some(entry=>entry.kind===kind))throw new Error(`${kind} already confirmed; never duplicate it`);
 const wallet=createWalletClient({account:payer,chain:sepolia,transport:http(rpc)}),[latest,pending]=await Promise.all([client.getTransactionCount({address:payer.address,blockTag:'latest'}),client.getTransactionCount({address:payer.address,blockTag:'pending'})]);
 if(latest!==pending)throw new Error('Payer has another pending transaction; stop');
 const estimated=await client.estimateGas({account:payer.address,...(to?{to}:{}),data,value}),gas=estimated+estimated/10n,[fees,block,current]=await Promise.all([client.estimateFeesPerGas(),client.getBlock(),client.getBalance({address:payer.address})]);
 const ceiling=gas*fees.maxFeePerGas+value;
 if(gas>block.gasLimit||globalReserved()+ceiling>budget||current<ceiling||current-ceiling<parseEther('0.08'))throw new Error(`Budget or reserve exceeded before ${kind}: ceiling ${formatEther(ceiling)} test ETH`);
 const request=await wallet.prepareTransactionRequest({account:payer,...(to?{to}:{}),data,value,gas,maxFeePerGas:fees.maxFeePerGas,maxPriorityFeePerGas:fees.maxPriorityFeePerGas});
 if(request.chainId!==11155111||request.nonce!==latest||request.data!==data||request.value!==value||request.to?.toLowerCase()!==to?.toLowerCase())throw new Error('Prepared source transaction differs');
 const raw=await payer.signTransaction(request),hash=keccak256(raw),entry:Entry={kind,hash,ceiling:ceiling.toString(),value:value.toString(),gas:gas.toString(),maxFeePerGas:fees.maxFeePerGas.toString()};
 const sealed=await sealTransaction(secretKey,{raw,sender:payer.address,to:to??null,value:value.toString(),nonce:latest,data,gas:gas.toString()},hash);
 ledger={...ledger,pending:{...entry,sealed}};durable(ledgerPath,ledger); // Durable encrypted signed intent before broadcasting.
 try{const returned=await wallet.sendRawTransaction({serializedTransaction:raw});if(returned.toLowerCase()!==hash.toLowerCase())throw new Error('RPC hash mismatch')}catch{throw new Error(`Broadcast outcome unknown for ${kind}: ${hash}; original encrypted intent retained`)}
 const receipt=await client.waitForTransactionReceipt({hash});if(receipt.transactionHash.toLowerCase()!==hash.toLowerCase()||receipt.from.toLowerCase()!==payer.address.toLowerCase()||receipt.to?.toLowerCase()!==to?.toLowerCase()||receipt.status!=='success')throw new Error(`Receipt failed identity/status for ${hash}; original intent retained`);
 ledger={completed:[...ledger.completed,{...entry,receiptBlock:receipt.blockNumber.toString(),gasUsed:receipt.gasUsed.toString(),effectiveGasPrice:receipt.effectiveGasPrice.toString(),...(receipt.contractAddress?{contractAddress:receipt.contractAddress}:{})}]};durable(ledgerPath,ledger);
 return receipt;
}
async function verifyFactory(address:Address,confirmedBlock?:bigint){
 const abi=parseAbi(['function singleton() view returns(address)','function guard() view returns(address)','function setup() view returns(address)','function mldsaHelper() view returns(address)','function c10Verifier() view returns(address)','function mldsaVerifier() view returns(address)','function proxyFactory() view returns(address)','function factoryVersion() view returns(uint256)']);
 const at=confirmedBlock??await client.getBlockNumber(),actual=await client.getCode({address,blockNumber:at});if(!actual)throw new Error('Factory code missing');
 const bytes=hexToBytes(v2.runtime as Hex);
 for(const[name,refs]of Object.entries(v2.immutables)){const value=await client.readContract({address,abi:v2.abi,functionName:name,blockNumber:at}) as Address|bigint|Hex;const word=hexToBytes(typeof value==='bigint'?toHex(value,{size:32}):padHex(value,{size:32}));for(const ref of refs)bytes.set(word,ref.start)}
 assert.equal(actual.toLowerCase(),bytesToHex(bytes).toLowerCase(),'V2 runtime and immutable bindings');
 const read=(fn:'guard'|'setup'|'singleton'|'mldsaHelper'|'c10Verifier'|'mldsaVerifier'|'proxyFactory'|'factoryVersion')=>client.readContract({address,abi,functionName:fn,blockNumber:at});
 assert.equal(await read('factoryVersion'),2n);
 for(const[name,source]of [['singleton','singleton'],['mldsaHelper','helper'],['c10Verifier','c10'],['mldsaVerifier','mldsa'],['proxyFactory','proxyFactory']] as const)assert.equal(String(await read(name)).toLowerCase(),sources[source].toLowerCase());
 const guard=await read('guard') as Address,setup=await read('setup') as Address;
 const guardExpected=runtime('ExperimentalRotationGuard',{factory:address,singleton:sources.singleton,singletonCodeHash:officialHashes.singleton,multiSendCallOnly:sources.multi,multiSendCodeHash:officialHashes.multi,proxyCodeHash:proxyHash});
 assert.equal((await client.getCode({address:guard,blockNumber:at}))?.toLowerCase(),guardExpected.toLowerCase());
 assert.equal((await client.getCode({address:setup,blockNumber:at}))?.toLowerCase(),runtime('ExperimentalSetup',{guard,proxyFactory:sources.proxyFactory}).toLowerCase());
 return {factory:address,guard,setup,creationBytecodeHash:keccak256(v2.bytecode as Hex),runtimeHash:keccak256(actual)};
}
if(stage==='infra'){
 const old=load<{factory:Address}>(manifestPath);if(old){console.log('Verified existing V2 infrastructure',await verifyFactory(old.factory));process.exit(0)}
 if(ledger.completed.length){const entry=ledger.completed.find(e=>e.kind==='infra');if(!entry?.contractAddress||ledger.completed.length!==1||!entry.receiptBlock)throw new Error('Inspect existing infrastructure journal before retrying');const receipt=await client.getTransactionReceipt({hash:entry.hash});if(receipt.status!=='success'||receipt.contractAddress?.toLowerCase()!==entry.contractAddress.toLowerCase()||receipt.blockNumber!==BigInt(entry.receiptBlock))throw new Error('Original infrastructure receipt mismatch');const verified=await verifyFactory(entry.contractAddress,receipt.blockNumber);durable(manifestPath,verified);console.log('Recovered and verified original V2 infrastructure',verified,'receipt',receipt.transactionHash);process.exit(0)}
 const receipt=await sourceTransaction('infra',undefined,0n,factoryData);if(!receipt.contractAddress)throw new Error('Missing factory address in confirmed receipt');
 const verified=await verifyFactory(receipt.contractAddress,receipt.blockNumber);durable(manifestPath,verified);console.log('V2 infrastructure deployed and runtime verified',verified,'receipt',receipt.transactionHash);process.exit(0);
}
const manifest=load<{factory:Address}>(manifestPath);if(!manifest)throw new Error('Deploy/verify V2 infrastructure first');await verifyFactory(manifest.factory);
const mode:PQMode=stage.endsWith('c10')?'c10':'mldsa44';
let phrases=load<Partial<Record<PQMode,{mnemonic:string;address:Address}>>>(phrasesPath)??{};
if(!existsSync(phrasesPath))durable(phrasesPath,phrases);
if(stage.startsWith('fund-')){
 if(!phrases![mode]){const phrase=entropyToMnemonic(crypto.getRandomValues(new Uint8Array(32)),wordlist),account=mnemonicToAccount(phrase,{path:"m/44'/60'/7331'/0/0"});phrases![mode]={mnemonic:phrase,address:account.address};durable(phrasesPath,phrases)}
 const target=phrases![mode].address,existing=ledger.completed.find(e=>e.kind===`fund-${mode}`);
 if(existing){console.log(`${mode} setup funding already confirmed`,existing.hash,target);process.exit(0)}
 if(await client.getBalance({address:target})!==0n)throw new Error('Disposable setup address already has funds but no matching journal');
 const receipt=await sourceTransaction(`fund-${mode}`,target,parseEther('0.04'),'0x');
 assert.equal((await client.getBalance({address:target,blockNumber:receipt.blockNumber})),parseEther('0.04'));
 console.log(`${mode} fresh setup address funded with 0.04 Sepolia test ETH`,target,'receipt',receipt.transactionHash);process.exit(0);
}
const identity=phrases![mode];if(!identity||!ledger.completed.some(e=>e.kind===`fund-${mode}`))throw new Error('Fund the disposable setup address first');
class Signer{
 secret:Uint8Array|undefined;wasm:C10Wasm|undefined;kind:PQMode|undefined;
 async init(phrase:string,kind:PQMode){this.kind=kind;const master=await mnemonicToSeed(phrase),seed=derivePQSeed(master,kind);master.fill(0);try{if(kind==='c10'){this.wasm=(await WebAssembly.instantiate(await Bun.file('apps/web/src/pq/generated/c10.wasm').arrayBuffer())).instance.exports as C10Wasm;return{mode:kind,publicKey:bytesToHex(c10Keygen(this.wasm,seed))}}const key=ml_dsa44.keygen(seed);this.secret=key.secretKey;return{mode:kind,publicKey:bytesToHex(key.publicKey),blob:bytesToHex(prepareMLDSA(key.publicKey))}}finally{seed.fill(0)}}
 async sign(digest:Hex){return bytesToHex(this.kind==='c10'?c10Sign(this.wasm!,hexToBytes(digest)):ml_dsa44.sign(hexToBytes(digest),this.secret!))}
 close(){this.secret?.fill(0);this.secret=undefined;if(this.wasm)new Uint8Array(this.wasm.memory.buffer).fill(0);this.wasm=undefined}
}
const recordPath=`${root}/${prefix}-${mode}-record.json`,modeBudgetPath=`${root}/${prefix}-${mode}-budget.json`;
let record=load<WalletRecord>(recordPath);if(record?.pending){let status='not found';try{const r=await client.getTransactionReceipt({hash:record.pending.hash});status=`${r.status} block ${r.blockNumber}`}catch{}throw new Error(`Original ${mode} ${record.pending.kind} ${record.pending.hash}: ${status}. Inspect and reconcile read-only; no new broadcast`)}
let modeBudget=load<Record<Hex,string>>(modeBudgetPath)??{},broadcasts=0;
const proxy=Bun.serve({hostname:'127.0.0.1',port:0,async fetch(request){const body=await request.text(),call=JSON.parse(body);if(call.method==='eth_sendRawTransaction'){
 try{const raw=call.params?.[0] as Hex,tx=parseTransaction(raw),sender=await recoverTransactionAddress({serializedTransaction:raw as `0x02${string}`}),hash=keccak256(raw);if(tx.chainId!==11155111||sender.toLowerCase()!==identity.address.toLowerCase()||!tx.gas||!tx.maxFeePerGas||!record?.pending||record.pending.hash!==hash)throw new Error('Unauthorized PQ signed transaction');
 const ceiling=tx.gas*tx.maxFeePerGas+(tx.value??0n),reserved=Object.values(modeBudget).reduce((sum,x)=>sum+BigInt(x),0n);if(!modeBudget[hash]){if(reserved+ceiling>parseEther('0.04')||globalReserved()+ceiling>budget)throw new Error('Disposable wallet or global 1 ETH budget exceeded');modeBudget={...modeBudget,[hash]:ceiling.toString()};durable(modeBudgetPath,modeBudget)}broadcasts++;
 }catch(error){return Response.json({jsonrpc:'2.0',id:call.id,error:{code:-32000,message:error instanceof Error?error.message:'PQ test budget failed'}})}}
 const upstream=await fetch(rpc,{method:'POST',headers:{'content-type':'application/json','accept-encoding':'identity'},body});return new Response(await upstream.text(),{status:upstream.status,headers:{'content-type':'application/json'}})
}});
const wallet=createExperimentalWallet(r=>{durable(recordPath,r);record=r},new Signer() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`,manifest.factory);
try{
 await wallet.open(identity.mnemonic,mode,record);let safe=record?.safe;
 if(!safe){safe=await wallet.create(parseEther('0.01'));assert.equal(broadcasts,mode==='c10'?1:2,`${mode} user setup transaction count`)}
 const setupCount=mode==='c10'?1:2;
 if(Object.keys(modeBudget).length>setupCount){const hash=Object.keys(modeBudget).at(-1)! as Hex,receipt=await client.getTransactionReceipt({hash});if(receipt.status!=='success'||receipt.to?.toLowerCase()!==safe.toLowerCase())throw new Error('Saved send receipt identity/status mismatch');const authenticated=await wallet.attest(safe,receipt.blockNumber);assert.equal(authenticated.index,1,'Original send receipt must prove rotation')}
 const before=await wallet.attest(safe);assert.equal(before.factoryVersion,2);assert(before.balance>=(before.index===0?parseEther('0.01'):parseEther('0.00899')));assert.equal(before.algorithm,mode==='c10'?1:2);
 if(before.index===0){if(Object.keys(modeBudget).length>(mode==='c10'?1:2))throw new Error('A signed send already exists; RPC is stale. Inspect its original receipt before retrying');await wallet.send('0x000000000000000000000000000000000000cafe',parseEther('0.00001'));assert.equal((await wallet.attest(safe)).index,1)}
 const snapshot=validateRecord(record!);wallet.close();const recovered=createExperimentalWallet(()=>{},new Signer() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`,manifest.factory);
 try{await recovered.open(identity.mnemonic,mode,snapshot);const state=await recovered.restore(safe);assert.equal(state.index,1);assert.equal(state.factoryVersion,2);assert.equal(state.safe.toLowerCase(),safe.toLowerCase());console.log(`${mode} public Sepolia V2 lifecycle, send/rotation and recovery verified`,{safe,creationBroadcasts:mode==='c10'?1:2,sendBroadcasts:1,setupBalance:formatEther(state.balance)})}finally{recovered.close()}
}finally{wallet.close();proxy.stop()}
