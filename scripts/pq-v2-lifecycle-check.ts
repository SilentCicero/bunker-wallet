// Disposable Anvil Sepolia only. Public deterministic phrases; never use with real funds.
import {createPublicClient,createWalletClient,http,encodeDeployData,parseEther,bytesToHex,hexToBytes,keccak256,formatEther,parseTransaction,type Address,type Hex} from 'viem';
import {mnemonicToAccount} from 'viem/accounts';
import {sepolia} from 'viem/chains';
import {entropyToMnemonic,mnemonicToSeed} from '@scure/bip39';
import {wordlist} from '@scure/bip39/wordlists/english.js';
import {ml_dsa44} from '@noble/post-quantum/ml-dsa.js';
import {derivePQSeed,prepareMLDSA,c10Keygen,c10Sign,type C10Wasm,type PQMode} from '../packages/pq/src/keys';
import {createExperimentalWallet,artifacts,dataCreation,type WalletRecord} from '../apps/web/src/pq/wallet';
import v2Artifact from '../apps/web/src/pq/generated/artifactsV2.json';
import type {PQSigner} from '../apps/web/src/pq/signer';
import official from '../tests/fixtures/sepolia-safe-1.4.1.json';
import {strict as assert} from 'node:assert';
const rpc='http://127.0.0.1:18545',client=createPublicClient({chain:sepolia,transport:http(rpc),pollingInterval:50});
assert.equal(await client.getChainId(),11155111,'Run only against disposable Sepolia-chain Anvil');
for(const fixture of Object.values(official.codes))await client.request({method:'anvil_setCode' as any,params:[fixture.address,fixture.runtime] as any});
const phrases={c10:entropyToMnemonic(new Uint8Array(32).fill(1),wordlist),mldsa44:entropyToMnemonic(new Uint8Array(32).fill(2),wordlist)};
class RealSigner {
 sk?:Uint8Array;wasm:C10Wasm|undefined;mode?:PQMode;
 async init(mnemonic:string,mode:PQMode){this.mode=mode;const seed=derivePQSeed(await mnemonicToSeed(mnemonic),mode);if(mode==='c10'){this.wasm=(await WebAssembly.instantiate(await Bun.file('apps/web/src/pq/generated/c10.wasm').arrayBuffer())).instance.exports as C10Wasm;return {mode,publicKey:bytesToHex(c10Keygen(this.wasm,seed))}}const key=ml_dsa44.keygen(seed);this.sk=key.secretKey;return {mode,publicKey:bytesToHex(key.publicKey),blob:bytesToHex(prepareMLDSA(key.publicKey))}}
 async sign(digest:Hex){return bytesToHex(this.mode==='c10'?c10Sign(this.wasm!,hexToBytes(digest)):ml_dsa44.sign(hexToBytes(digest),this.sk!))}
 close(){this.sk?.fill(0);this.wasm=undefined}
}
const infraAccount=mnemonicToAccount(phrases.c10,{path:"m/44'/60'/7331'/0/0"}),infraWallet=createWalletClient({account:infraAccount,chain:sepolia,transport:http(rpc)});
await client.request({method:'anvil_setBalance' as any,params:[infraAccount.address,'0x1bc16d674ec800000'] as any});
async function deploy(name:string,args:readonly unknown[]=[],raw?:Hex){const artifact=name==='ExperimentalSharedFactoryV2'?v2Artifact:artifacts[name]!;const data=raw?dataCreation(raw):encodeDeployData({abi:artifact.abi,bytecode:artifact.bytecode as Hex,args});const hash=await infraWallet.sendTransaction({data,gas:12_000_000n});const receipt=await client.waitForTransactionReceipt({hash});assert.equal(receipt.status,'success');assert(receipt.contractAddress);return receipt.contractAddress;}
const helper=await deploy('',[],artifacts.helper),c10=await deploy('SphincsC10Asm'),mldsa=await deploy('MLDSA44Verifier',[helper]);
const dependency=async(address:Address)=>({target:address,codeHash:keccak256((await client.getCode({address}))!)});
const shared=await deploy('ExperimentalSharedFactoryV2',[await dependency(official.codes.singleton.address as Address),await dependency(official.codes.factory.address as Address),await dependency(official.codes.multisend.address as Address),await dependency(c10),await dependency(mldsa),await dependency(helper),'0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c']);
for(const mode of ['c10','mldsa44'] as const){
 const phrase=phrases[mode],setup=mnemonicToAccount(phrase,{path:"m/44'/60'/7331'/0/0"}).address;
 await client.request({method:'anvil_setBalance' as any,params:[setup,'0x1bc16d674ec800000'] as any});
 let broadcasts=0,lose=true,unavailable=true,pinnedRead:Address|undefined;const retryBlocks:string[]=[];const proxy=Bun.serve({port:0,async fetch(request){const body=await request.text(),call=JSON.parse(body);if(pinnedRead&&call.method==='eth_getCode'&&call.params?.[0]?.toLowerCase()===pinnedRead.toLowerCase()){retryBlocks.push(call.params[1]);if(unavailable){unavailable=false;return Response.json({jsonrpc:'2.0',id:call.id,error:{code:-32000,message:`block not found: ${call.params[1]}`}})}}if(call.method==='eth_sendRawTransaction'){broadcasts++;const tx=parseTransaction(call.params[0]);if(lose&&tx.to?.toLowerCase()===shared.toLowerCase()){lose=false;const accepted=await (await fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body})).json();if(accepted.error)throw new Error(`Anvil rejected creation: ${accepted.error.message}`);return Response.json({jsonrpc:'2.0',id:call.id,error:{code:-32000,message:'simulated lost creation response'}})}}return fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body})}});
 let record:WalletRecord|undefined,wallet=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`,shared);
 await wallet.open(phrase,mode);await assert.rejects(wallet.create(parseEther('0.1')),/Broadcast outcome unknown/);assert(record?.pending?.kind==='createV2');const expected=mode==='c10'?1:2;assert.equal(broadcasts,expected,`${mode} must require ${expected} user broadcast(s) including preparation`);
 await client.waitForTransactionReceipt({hash:record!.pending!.hash,timeout:10000});const settled=await wallet.reconcile();assert.equal(settled?.kind,'createV2');assert(record!.safe);assert.equal(broadcasts,expected,'read-only reconciliation cannot rebroadcast');const creationGas=(await client.getTransactionReceipt({hash:settled.hash})).gasUsed;
 pinnedRead=record!.safe!;const state=await wallet.attest(record!.safe!);assert.equal(unavailable,false);assert.equal(retryBlocks.length,2);assert.equal(retryBlocks[0],retryBlocks[1],'retry must preserve the original block');pinnedRead=undefined;assert.equal(state.factoryVersion,2);assert.equal(state.balance,parseEther('0.1'));assert.equal(state.index,0);
 if(mode==='mldsa44')assert.equal(await client.getCode({address:record!.parts.blob!}),bytesToHex(prepareMLDSA(hexToBytes(record!.publicKey))));
 const recipient='0x000000000000000000000000000000000000cafe' as Address;
 await wallet.send(recipient,parseEther('0.00001'));assert.equal((await wallet.attest(record!.safe!)).index,1);
 const safe=record!.safe!;wallet.close();wallet=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`,shared);await wallet.open(phrase,mode);const recovered=await wallet.restore(safe);assert.equal(recovered.index,1);assert.equal(recovered.factoryVersion,2);
 console.log(mode,'V2 creation+funding, full real-verifier send/rotation/recovery passed',expected,'creation broadcast(s), creation gas',creationGas.toString(),'safe',safe,'remaining',formatEther(recovered.balance));wallet.close();
 const unknown=createExperimentalWallet(()=>{},new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`);await unknown.open(phrase,mode);await assert.rejects(unknown.restore(safe),/shared address verification failed/);unknown.close();
 const wrongFactory=createExperimentalWallet(()=>{},new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`,c10);await wrongFactory.open(phrase,mode);await assert.rejects(wrongFactory.restore(safe),/shared address verification failed/);wrongFactory.close();proxy.stop();
}
const wrongPhrase=entropyToMnemonic(new Uint8Array(32).fill(3),wordlist);let wrongRecord:WalletRecord|undefined;
let wrong=createExperimentalWallet(r=>wrongRecord=r,new RealSigner() as unknown as PQSigner,rpc,shared);await wrong.open(wrongPhrase,'mldsa44');wrong.close();
const tampered=structuredClone(wrongRecord!);tampered.parts.blob=helper;let wrongBroadcasts=0;
const wrongProxy=Bun.serve({port:0,async fetch(request){const body=await request.text(),call=JSON.parse(body);if(call.method==='eth_sendRawTransaction')wrongBroadcasts++;return fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body})}});
wrong=createExperimentalWallet(r=>wrongRecord=r,new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${wrongProxy.port}`,shared);await wrong.open(wrongPhrase,'mldsa44',tampered);
await assert.rejects(wrong.create(parseEther('0.1')),/Deployment bytecode verification failed/);assert.equal(wrongBroadcasts,0);assert(!wrongRecord?.pending);wrong.close();wrongProxy.stop();
console.log('Mismatched prepared ML-DSA blob rejected before any broadcast');
