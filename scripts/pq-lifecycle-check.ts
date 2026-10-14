// Disposable local-chain test only. Public mnemonic; never use it for funds.
import { createPublicClient,http,hexToBytes,bytesToHex,parseEther,encodeFunctionData,parseAbi,decodeFunctionData,sliceHex,padHex,concatHex,toHex,encodeDeployData,keccak256,type Hex,type Address } from 'viem';
import { mnemonicToSeed } from '@scure/bip39';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { derivePQSeed,prepareMLDSA,c10Keygen,c10Sign,type C10Wasm,type PQMode } from '../packages/pq/src/keys';
import { createExperimentalWallet, artifacts, runtime, safeABI, type WalletRecord } from '../apps/web/src/pq/wallet';
import type {PQSigner} from '../apps/web/src/pq/signer';
import official from '../tests/fixtures/sepolia-safe-1.4.1.json';
import { strict as assert } from 'node:assert';
const rpc='http://127.0.0.1:18545';const client=createPublicClient({transport:http(rpc)});
if(await client.getChainId()!==11155111)throw new Error('Start local Anvil with chain11155111');
for(const fixture of Object.values(official.codes))await client.request({method:'anvil_setCode' as any,params:[fixture.address,fixture.runtime] as any});
const phrase='abandon '.repeat(23)+'art';
class RealSigner {
 sk?:Uint8Array; wasm:C10Wasm|undefined; mode?:PQMode;
 async init(mnemonic:string,mode:PQMode){this.mode=mode;const seed=derivePQSeed(await mnemonicToSeed(mnemonic),mode);if(mode==='c10'){this.wasm=(await WebAssembly.instantiate(await Bun.file('apps/web/src/pq/generated/c10.wasm').arrayBuffer())).instance.exports as C10Wasm;return{mode,publicKey:bytesToHex(c10Keygen(this.wasm,seed))};}const k=ml_dsa44.keygen(seed);this.sk=k.secretKey;return{mode,publicKey:bytesToHex(k.publicKey),blob:bytesToHex(prepareMLDSA(k.publicKey))}}
 async sign(digest:Hex){return bytesToHex(this.mode==='c10'?c10Sign(this.wasm!,hexToBytes(digest)):ml_dsa44.sign(hexToBytes(digest),this.sk!));}
 close(){this.sk?.fill(0);this.wasm=undefined}
}
for(const mode of ['c10','mldsa44'] as const){
 let record:WalletRecord|undefined,interrupted=false;const signer=new RealSigner();let wallet=createExperimentalWallet(r=>{record=r;if(r.parts.helper&&!interrupted){interrupted=true;wallet.close();}},signer as unknown as PQSigner,rpc);
 const started=performance.now();const opened=await wallet.open(phrase,mode);
 await client.request({method:'anvil_setBalance' as any,params:[opened.address,'0x3635c9adc5dea00000'] as any});
 await assert.rejects(wallet.create(),/locked/);assert(record!.parts.helper);const retainedHelper=record!.parts.helper;wallet=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,rpc);await wallet.open(phrase,mode,record);
 const safe=await wallet.create();assert.equal(record!.parts.helper,retainedHelper);assert(record?.safe===safe);const before=await wallet.attest(safe);assert.equal(before.index,0);
 await wallet.fund(parseEther('0.1'));
 const recipient='0x000000000000000000000000000000000000cafe' as Address;
 const snapshot=await client.request({method:'evm_snapshot' as any} as any);
 const hash=await wallet.send(recipient,parseEther('0.00001'));const tx=await client.getTransaction({hash});
 await client.request({method:'evm_revert' as any,params:[snapshot] as any});
 wallet.close();wallet=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,rpc);await wallet.open(phrase,mode,record);await wallet.restore(safe); // Reorg discards the old session's confirmed-block floor.
 const decoded=decodeFunctionData({abi:safeABI,data:tx.input});assert.equal(decoded.functionName,'execTransaction');
 const args=[...decoded.args!] as any[],pair=args[9] as Hex;
 const pos=BigInt(before.ec)<BigInt(before.pq)?0:65;
 const ecOnly=sliceHex(pair,pos,pos+65);
 const pqRaw=sliceHex(pair,162);
 const pqOnly=concatHex([padHex(before.pq,{size:32}),toHex(65n,{size:32}),'0x00',toHex(BigInt((pqRaw.length-2)/2),{size:32}),pqRaw]);
 for(const sig of [ecOnly,pqOnly,sliceHex(pair,0,(pair.length-2)/2-1)]){
  args[9]=sig;const data=encodeFunctionData({abi:safeABI,functionName:'execTransaction',args:args as any});
  await assert.rejects(client.call({account:tx.from,to:safe,data}),/./,'one owner/malformed PQ must fail');
 }
 const confirmedSend=await wallet.send(recipient,parseEther('0.00001'));
 const mined=await client.getTransactionReceipt({hash:confirmedSend});assert.equal((await wallet.attest(safe,mined.blockNumber-1n)).index,0);assert.equal((await wallet.attest(safe,mined.blockNumber)).index,1);
 if(mode==='mldsa44'){
  const parts=record!.parts;
  const abi=artifacts.ExperimentalMLDSAOwner!.abi;
  for(const bytes of [new Uint8Array(1312),new Uint8Array(1312).fill(255),new Uint8Array(1311)]){
   const data=encodeDeployData({abi,bytecode:artifacts.ExperimentalMLDSAOwner!.bytecode,args:[bytesToHex(bytes),parts.blob,keccak256(await client.getCode({address:parts.blob!}) as Hex),parts.MLDSA44Verifier,keccak256(await client.getCode({address:parts.MLDSA44Verifier!}) as Hex),0n,parts.helper]});
   await assert.rejects(client.estimateGas({account:opened.address,data}),/./,'degenerate/malformed key must fail on-chain');
  }
  const original=await client.getCode({address:parts.blob!}) as Hex,mutated=('0x00'+(original.slice(4,6)==='01'?'02':'01')+original.slice(6)) as Hex;
  await client.request({method:'anvil_setCode' as any,params:[parts.blob,mutated] as any});await assert.rejects(wallet.attest(safe));
  await assert.rejects(client.readContract({address:before.guard,abi:artifacts.ExperimentalRotationGuard!.abi,functionName:'attest',args:[safe,(await client.readContract({address:safe,abi:safeABI,functionName:'getOwners'}))[0],before.pq]}));
  await client.request({method:'anvil_setCode' as any,params:[parts.blob,original] as any});
 }

 const after=await wallet.attest(safe);assert.equal(after.index,1);assert.equal(after.pq,before.pq);assert.notEqual(after.ec,before.ec);
 await assert.rejects(client.call({account:tx.from,to:safe,data:tx.input}),/./,'replay must fail');
 wallet.close();let staleBlock:bigint|undefined,staleReads=0;
 const staleProxy=Bun.serve({port:0,async fetch(req){const body=await req.text(),call=JSON.parse(body);if(call.method==='eth_blockNumber'&&staleBlock!==undefined){staleReads++;return Response.json({jsonrpc:'2.0',id:call.id,result:toHex(staleBlock)})}return fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body})}});
 wallet=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${staleProxy.port}`);await wallet.open(phrase,mode,record);const restored=await wallet.restore(safe);assert.equal(restored.index,1);assert.equal(restored.pq,before.pq);
 await client.request({method:'anvil_setBalance' as any,params:[restored.ec,'0x2386f26fc10000'] as any});
 const secondHash=await wallet.send(recipient,parseEther('0.00001'));staleBlock=(await client.getTransactionReceipt({hash:secondHash})).blockNumber-1n;
 await new Promise(resolve=>setTimeout(resolve,100));assert.equal((await wallet.attest(safe)).index,2);assert(staleReads>0,'confirmed-block floor must defeat stale latest block');wallet.close();staleProxy.stop();
 wallet=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,rpc);await wallet.open(phrase,mode,record);await wallet.restore(safe);
 // Two complete sequence renewals, genuine signatures throughout, fixed PQ owner.
 while(true){const current=await wallet.attest(safe);if(current.cycle===2)break;await client.request({method:'anvil_setBalance' as any,params:[current.ec,'0x2386f26fc10000'] as any});if(current.index===19)await wallet.renew();else await wallet.send(recipient,parseEther('0.00001'));}
 const renewed=await wallet.attest(safe);assert.equal(renewed.cycle,2);assert.equal(renewed.index,0);assert.equal(renewed.pq,before.pq);
 wallet.close();wallet=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,rpc);await wallet.open(phrase,mode);await wallet.restore(safe);
 await client.request({method:'anvil_setBalance' as any,params:[renewed.ec,'0x2386f26fc10000'] as any});await wallet.send(recipient,parseEther('0.00001'));assert.equal((await wallet.attest(safe)).index,1);wallet.close();
 // Delay viem's fill (or fallback nonce) RPC: after explicit checks, DURING preparation.
 let nonces=0,broadcasts=0,reached!:()=>void,release!:()=>void;
 const hit=new Promise<void>(r=>reached=r),gate=new Promise<void>(r=>release=r);
 const proxy=Bun.serve({port:0,async fetch(req){const body=await req.text(),call=JSON.parse(body);if(call.method==='eth_fillTransaction'||(call.method==='eth_getTransactionCount'&&++nonces===3)){reached();await gate;}if(call.method==='eth_sendRawTransaction')broadcasts++;return fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body});}});
 const locked=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`);await locked.open(phrase,mode,record);const lockState=await locked.restore(safe);await client.request({method:'anvil_setBalance' as any,params:[lockState.ec,'0x2386f26fc10000'] as any});
 const attempt=locked.fund(1n);const rejected=assert.rejects(attempt,/locked/);await Promise.race([hit,new Promise((_,reject)=>setTimeout(()=>reject(new Error('Did not intercept preparation')),10000))]);locked.close();release();await rejected;assert.equal(broadcasts,0);proxy.stop();
 // Real local RPC accepts/mines, then response is lost. Never infer that failure means no payment.
 let drop=true,accept=true,rawCalls:Hex[]=[];
 const uncertainProxy=Bun.serve({port:0,async fetch(req){const body=await req.text(),call=JSON.parse(body);if(call.method==='eth_sendRawTransaction'){rawCalls.push(call.params[0]);if(drop){if(accept)await (await fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body})).text();return Response.json({jsonrpc:'2.0',id:call.id,error:{code:-32000,message:'simulated lost broadcast response'}});}}return fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body});}});
 const uncertainRPC=`http://127.0.0.1:${uncertainProxy.port}`;
 let uncertain=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,uncertainRPC);await uncertain.open(phrase,mode,record);await uncertain.restore(safe);
 for(const kind of ['fund','send'] as const){
  const current=await uncertain.attest(safe);await client.request({method:'anvil_setBalance' as any,params:[current.ec,'0x2386f26fc10000'] as any});
  const target=kind==='fund'?safe:recipient,balanceBefore=await client.getBalance({address:target});rawCalls=[];
  await assert.rejects(kind==='fund'?uncertain.fund(3n):uncertain.send(recipient,7n),/Broadcast outcome unknown/);
  assert.equal(record!.pending!.kind,kind);assert(record!.pending!.sealed);assert(!JSON.stringify(record).includes(rawCalls[0]!));assert.equal(new Set(rawCalls).size,1);
  // A substituted public hash must not authenticate an unrelated mined receipt.
  const genuine=structuredClone(record!);let corrupt:WalletRecord={...structuredClone(genuine),pending:{...genuine.pending!,hash:('0x'+'11'.repeat(32)) as Hex}};
  const unrelatedBlock=await client.getBlock({blockNumber:(await client.getBlockNumber())-1n,includeTransactions:true});if(unrelatedBlock.transactions[0])corrupt.pending!.hash=unrelatedBlock.transactions[0].hash;
  const tampered=createExperimentalWallet(r=>corrupt=r,new RealSigner() as unknown as PQSigner,uncertainRPC);await tampered.open(phrase,mode,corrupt);await tampered.restore(safe);await assert.rejects(tampered.reconcile());assert(corrupt.pending);tampered.close();

  const submitted=rawCalls.length;uncertain.close();uncertain=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,uncertainRPC);await uncertain.open(phrase,mode,record);await uncertain.restore(safe);
  await assert.rejects(kind==='fund'?uncertain.fund(3n):uncertain.send(recipient,7n),/Previous .* confirmed/);
  assert.equal(rawCalls.length,submitted);assert.equal(await client.getBalance({address:target}),balanceBefore+(kind==='fund'?3n:7n));assert(!record!.pending);
 }
 // If the first RPC did NOT accept, an unlocked explicit retry broadcasts byte-identical ciphertext-decrypted intent.
 accept=false;rawCalls=[];const stateRetry=await uncertain.attest(safe);await client.request({method:'anvil_setBalance' as any,params:[stateRetry.ec,'0x2386f26fc10000'] as any});const balanceBefore=await client.getBalance({address:safe});
 await assert.rejects(uncertain.fund(11n),/Broadcast outcome unknown/);const originalRaw=rawCalls[0];uncertain.close();drop=false;
 uncertain=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,uncertainRPC);await uncertain.open(phrase,mode,record);await uncertain.restore(safe);await uncertain.rebroadcast();assert.equal(rawCalls.at(-1),originalRaw);assert.equal(await client.getBalance({address:safe}),balanceBefore+11n);uncertain.close();
 // Durable persistence failure must happen BEFORE dispatch, even though signing succeeded in memory.
 rawCalls=[];const diskFailure=createExperimentalWallet(r=>{if(r.pending)throw new Error('simulated disk full');record=r;},new RealSigner() as unknown as PQSigner,uncertainRPC);await diskFailure.open(phrase,mode,record);await diskFailure.restore(safe);await assert.rejects(diskFailure.fund(1n),/disk full/);assert.equal(rawCalls.length,0);diskFailure.close();
 // A one-time durable write failure AFTER a mined receipt must roll memory back to pending.
 for(const kind of ['fund','send'] as const){let sawPending=false,failOnce=true;rawCalls=[];
  const afterReceipt=createExperimentalWallet(r=>{if(r.pending)sawPending=true;if(sawPending&&!r.pending&&failOnce){failOnce=false;throw new Error('post-receipt storage failure');}record=r;},new RealSigner() as unknown as PQSigner,uncertainRPC);
  await afterReceipt.open(phrase,mode,record);const current=await afterReceipt.restore(safe);await client.request({method:'anvil_setBalance' as any,params:[current.ec,'0x2386f26fc10000'] as any});const target=kind==='fund'?safe:recipient,balanceBefore=await client.getBalance({address:target});
  await assert.rejects(kind==='fund'?afterReceipt.fund(5n):afterReceipt.send(recipient,13n),/post-receipt storage failure/);assert(afterReceipt.record!.pending);const count=rawCalls.length;
  await assert.rejects(kind==='fund'?afterReceipt.fund(5n):afterReceipt.send(recipient,13n),/Previous .* confirmed/);assert.equal(rawCalls.length,count);assert.equal(await client.getBalance({address:target}),balanceBefore+(kind==='fund'?5n:13n));afterReceipt.close();
 }
 uncertainProxy.stop();


 console.log(mode,'actual Safe+factory+guard+verifier create/fund/send/negative signatures/weak-key/mutation/replay/recovery/two renewals/lock-during-prepare passed',Math.round(performance.now()-started),'ms');
}
