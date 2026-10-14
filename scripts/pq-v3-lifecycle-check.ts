// Disposable Anvil Sepolia only. Public deterministic phrases; never use with real funds.
import {createPublicClient,createWalletClient,http,encodeDeployData,parseEther,bytesToHex,hexToBytes,keccak256,formatEther,parseTransaction,encodeFunctionData,encodeAbiParameters,hashTypedData,hashStruct,toHex,concatHex,decodeFunctionData,type Address,type Hex} from 'viem';
import {mnemonicToAccount} from 'viem/accounts';
import {sepolia} from 'viem/chains';
import {entropyToMnemonic,mnemonicToSeed} from '@scure/bip39';
import {wordlist} from '@scure/bip39/wordlists/english.js';
import {ml_dsa44} from '@noble/post-quantum/ml-dsa.js';
import {derivePQSeed,prepareMLDSA,c10Keygen,c10Sign,type C10Wasm,type PQMode} from '../packages/pq/src/keys';
import {createExperimentalWallet,artifacts,dataCreation,safeABI,type WalletRecord} from '../apps/web/src/pq/wallet';
import {hybridMessageDigest,encodeHybridSignatures} from '../packages/safe/src/experimental';
import v3Artifact from '../apps/web/src/pq/generated/artifactsV3.json';
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
async function deploy(name:string,args:readonly unknown[]=[],raw?:Hex){const artifact=name==='ExperimentalSharedFactoryV3'?v3Artifact:name==='ExperimentalSharedFactoryV2'?v2Artifact:artifacts[name]!;const data=raw?dataCreation(raw):encodeDeployData({abi:artifact.abi,bytecode:artifact.bytecode as Hex,args});const hash=await infraWallet.sendTransaction({data,gas:12_000_000n});const receipt=await client.waitForTransactionReceipt({hash});assert.equal(receipt.status,'success');assert(receipt.contractAddress);return receipt.contractAddress;}
const helper=await deploy('',[],artifacts.helper),c10=await deploy('SphincsC10Asm'),mldsa=await deploy('MLDSA44Verifier',[helper]);
const dependency=async(address:Address)=>({target:address,codeHash:keccak256((await client.getCode({address}))!)});
const bindings=[await dependency(official.codes.singleton.address as Address),await dependency(official.codes.factory.address as Address),await dependency(official.codes.multisend.address as Address),await dependency(c10),await dependency(mldsa),await dependency(helper),'0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c'] as const;
const shared=await deploy('ExperimentalSharedFactoryV3',bindings),legacy=await deploy('ExperimentalSharedFactoryV2',bindings);
for(const mode of ['c10','mldsa44'] as const){
 const phrase=phrases[mode],setup=mnemonicToAccount(phrase,{path:"m/44'/60'/7331'/0/0"}).address;
 await client.request({method:'anvil_setBalance' as any,params:[setup,'0x1bc16d674ec800000'] as any});
 let broadcasts=0,lose=true,unavailable=true,pinnedRead:Address|undefined;const retryBlocks:string[]=[];const proxy=Bun.serve({port:0,async fetch(request){const body=await request.text(),call=JSON.parse(body);if(pinnedRead&&call.method==='eth_getCode'&&call.params?.[0]?.toLowerCase()===pinnedRead.toLowerCase()){retryBlocks.push(call.params[1]);if(unavailable){unavailable=false;return Response.json({jsonrpc:'2.0',id:call.id,error:{code:-32000,message:`block not found: ${call.params[1]}`}})}}if(call.method==='eth_sendRawTransaction'){broadcasts++;const tx=parseTransaction(call.params[0]);if(lose&&tx.to?.toLowerCase()===shared.toLowerCase()){lose=false;const accepted=await (await fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body})).json();if(accepted.error)throw new Error(`Anvil rejected creation: ${accepted.error.message}`);return Response.json({jsonrpc:'2.0',id:call.id,error:{code:-32000,message:'simulated lost creation response'}})}}return fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body})}});
 const signer=new RealSigner();let record:WalletRecord|undefined,wallet=createExperimentalWallet(r=>record=r,signer as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`,legacy,shared);
 await wallet.open(phrase,mode);await assert.rejects(wallet.create(parseEther('0.1')),/Broadcast outcome unknown/);assert(record?.pending?.kind==='createV3');const expected=mode==='c10'?1:2;assert.equal(broadcasts,expected,`${mode} must require ${expected} user broadcast(s) including preparation`);
 await client.waitForTransactionReceipt({hash:record!.pending!.hash,timeout:10000});const settled=await wallet.reconcile();assert.equal(settled?.kind,'createV3');assert(record!.safe);assert.equal(broadcasts,expected,'read-only reconciliation cannot rebroadcast');const creationGas=(await client.getTransactionReceipt({hash:settled.hash})).gasUsed;
 pinnedRead=record!.safe!;const state=await wallet.attest(record!.safe!);assert.equal(unavailable,false);assert.equal(retryBlocks.length,2);assert.equal(retryBlocks[0],retryBlocks[1],'retry must preserve the original block');pinnedRead=undefined;assert.equal(state.factoryVersion,3);assert.equal(state.balance,parseEther('0.1'));assert.equal(state.index,0);
 if(mode==='mldsa44')assert.equal(await client.getCode({address:record!.parts.blob!}),bytesToHex(prepareMLDSA(hexToBytes(record!.publicKey))));
 const recipient='0x000000000000000000000000000000000000cafe' as Address,target='0x000000000000000000000000000000000000feed' as Address;
 await client.request({method:'anvil_setCode' as any,params:[target,'0x60005460010160005500'] as any});
 const packed=(to:Address,value:bigint,data:Hex='0x')=>concatHex(['0x00',to,toHex(value,{size:32}),toHex(BigInt((data.length-2)/2),{size:32}),data]);
 const suffix=concatHex([packed(state.nextEc,parseEther('0.001')),packed(state.safe,0n,encodeFunctionData({abi:safeABI,functionName:'swapOwner',args:['0x0000000000000000000000000000000000000001',state.ec,state.nextEc]}))]);
 async function signedBatch(calls:Hex[],withSuffix=true){
  const data=encodeFunctionData({abi:[{type:'function',name:'multiSend',stateMutability:'payable',inputs:[{name:'transactions',type:'bytes'}],outputs:[]}],functionName:'multiSend',args:[concatHex(withSuffix?[...calls,suffix]:calls)]}),nonce=await client.readContract({address:state.safe,abi:safeABI,functionName:'nonce'});
  const zero='0x0000000000000000000000000000000000000000' as Address;
  const tx={to:official.codes.multisend.address as Address,value:0n,data,operation:1,safeTxGas:0n,baseGas:0n,gasPrice:0n,gasToken:zero,refundReceiver:zero,nonce} as const;
  const types={SafeTx:[{name:'to',type:'address'},{name:'value',type:'uint256'},{name:'data',type:'bytes'},{name:'operation',type:'uint8'},{name:'safeTxGas',type:'uint256'},{name:'baseGas',type:'uint256'},{name:'gasPrice',type:'uint256'},{name:'gasToken',type:'address'},{name:'refundReceiver',type:'address'},{name:'nonce',type:'uint256'}]} as const;
  const hash=hashTypedData({domain:{chainId:11155111,verifyingContract:state.safe},types,primaryType:'SafeTx',message:tx});
  assert.equal(hash,await client.readContract({address:state.safe,abi:safeABI,functionName:'getTransactionHash',args:[tx.to,0n,data,1,0n,0n,0n,zero,zero,nonce]}));
  const preimage=concatHex(['0x1901',keccak256(encodeAbiParameters([{type:'bytes32'},{type:'uint256'},{type:'address'}],[keccak256(toHex('EIP712Domain(uint256 chainId,address verifyingContract)')),11155111n,state.safe])),hashStruct({data:tx,types,primaryType:'SafeTx'})]);
  const digest=hybridMessageDigest({chainId:11155111,safe:state.safe,preimage,algorithm:state.algorithm,version:1,adapter:state.pq,keyId:state.keyId,verifier:state.verifier,verifierCodeHash:state.verifierCodeHash,epoch:0n});
  const ec=mnemonicToAccount(phrase,{path:"m/44'/60'/7331'/0/0"});
  const signatures=encodeHybridSignatures(state.ec,state.pq,await ec.sign({hash}),await signer.sign(digest),state.algorithm);
  return encodeFunctionData({abi:safeABI,functionName:'execTransaction',args:[tx.to,0n,data,1,0n,0n,0n,zero,zero,signatures]});
 }
 const invalid=await signedBatch([packed(state.safe,0n,'0x1234')]);await assert.rejects(client.call({to:state.safe,data:invalid,account:infraAccount.address}));
 assert.equal((await wallet.attest(state.safe)).index,0,'denied self-call cannot rotate');
 for(const privileged of [state.pq,state.guard,shared,official.codes.factory.address as Address,official.codes.multisend.address as Address,official.codes.singleton.address as Address]){
  const denied=await signedBatch([packed(privileged,0n,'0x1234')]);
  await assert.rejects(client.call({to:state.safe,data:denied,account:infraAccount.address}));
 }
 const delegate=(packed(target,0n,'0x1234').replace(/^0x00/,'0x01')) as Hex;
 await assert.rejects(client.call({to:state.safe,data:await signedBatch([delegate]),account:infraAccount.address}));
 const missingSuffix=await signedBatch([packed(target,0n,'0x1234')],false);
 await assert.rejects(client.call({to:state.safe,data:missingSuffix,account:infraAccount.address}));
 const malformed=decodeFunctionData({abi:safeABI,data:invalid});
 const truncated=(malformed.args[9] as Hex).slice(0,-2) as Hex;
 const invalidSignature=encodeFunctionData({abi:safeABI,functionName:'execTransaction',args:[...malformed.args.slice(0,9),truncated] as never});
 await assert.rejects(client.call({to:state.safe,data:invalidSignature,account:infraAccount.address}));
 assert.equal((await wallet.attest(state.safe)).index,0,'invalid signature or suffix cannot rotate');
 const reverting='0x000000000000000000000000000000000000fa11' as Address;
 await client.request({method:'anvil_setCode' as any,params:[reverting,'0x60006000fd'] as any});
 const targetBefore=BigInt((await client.getStorageAt({address:target,slot:'0x00'}))||'0x0');
 const failed=await signedBatch([packed(target,0n,'0x1234'),packed(reverting,0n)]);
 const failedHash=await infraWallet.sendTransaction({to:state.safe,data:failed,gas:12_000_000n});
 assert.equal((await client.waitForTransactionReceipt({hash:failedHash})).status,'reverted');
 assert.equal(BigInt((await client.getStorageAt({address:target,slot:'0x00'}))||'0x0'),targetBefore,'revert must roll back first call');
 assert.equal((await wallet.attest(state.safe)).index,0,'failed batch cannot rotate');
 const recipientBefore=await client.getBalance({address:recipient});
 const signed=await signedBatch([packed(target,0n,'0xdeadbeef'),packed(recipient,parseEther('0.00001'))]);
 const callHash=await infraWallet.sendTransaction({to:state.safe,data:signed,gas:12_000_000n});assert.equal((await client.waitForTransactionReceipt({hash:callHash})).status,'success');
 assert.equal(BigInt((await client.getStorageAt({address:target,slot:'0x00'}))!),targetBefore+1n);assert.equal((await client.getBalance({address:recipient}))-recipientBefore,parseEther('0.00001'));
 const rotated=await wallet.attest(record!.safe!);assert.equal(rotated.index,1);
 await assert.rejects(client.call({to:state.safe,data:signed,account:infraAccount.address}),'Safe nonce must reject replay');
 assert.equal((await wallet.attest(state.safe)).index,1,'replay cannot rotate');
 await client.request({method:'anvil_setBalance' as any,params:[rotated.ec,'0x2386f26fc10000'] as any});
 await wallet.send(recipient,parseEther('0.00001'));assert.equal((await wallet.attest(record!.safe!)).index,2);
 const safe=record!.safe!;wallet.close();wallet=createExperimentalWallet(r=>record=r,new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`,legacy,shared);await wallet.open(phrase,mode);const recovered=await wallet.restore(safe);assert.equal(recovered.index,2);assert.equal(recovered.factoryVersion,3);
 for(let index=2;index<19;index++){
  const current=await wallet.attest(safe);assert.equal(current.index,index);
  await client.request({method:'anvil_setBalance' as any,params:[current.ec,'0x2386f26fc10000'] as any});
  await wallet.send(recipient,1n);
 }
 const finalOwner=await wallet.attest(safe);assert.equal(finalOwner.index,19);
 await client.request({method:'anvil_setBalance' as any,params:[finalOwner.ec,'0x2386f26fc10000'] as any});
 await wallet.renew();const renewed=await wallet.attest(safe);assert.equal(renewed.index,0);assert.equal(renewed.cycle,1);
 const factoryCode=(await client.getCode({address:shared}))!,guardCode=(await client.getCode({address:renewed.guard}))!;
 await client.request({method:'anvil_setCode' as any,params:[shared,'0x6000'] as any});
 await assert.rejects(wallet.attest(safe),'factory runtime mismatch must deny access');
 await client.request({method:'anvil_setCode' as any,params:[shared,factoryCode] as any});
 await client.request({method:'anvil_setCode' as any,params:[renewed.guard,'0x6000'] as any});
 await assert.rejects(wallet.attest(safe),'guard runtime mismatch must deny access');
 await client.request({method:'anvil_setCode' as any,params:[renewed.guard,guardCode] as any});
 assert.equal((await wallet.attest(safe)).cycle,1,'restoring exact code must restore attestation');
 console.log(mode,'V3 real-verifier multi-CALL, revert atomicity, malformed signatures, 19 rotations, renewal, recovery, code tamper denial passed',expected,'creation broadcast(s), creation gas',creationGas.toString(),'safe',safe,'remaining',formatEther(renewed.balance));wallet.close();
 let legacyRecord:WalletRecord|undefined;let oldWallet=createExperimentalWallet(r=>legacyRecord=r,new RealSigner() as unknown as PQSigner,rpc,legacy);
 await oldWallet.open(phrase,mode);const oldSafe=await oldWallet.create(parseEther('0.01'));assert.equal((await oldWallet.attest(oldSafe)).factoryVersion,2);oldWallet.close();
 oldWallet=createExperimentalWallet(r=>legacyRecord=r,new RealSigner() as unknown as PQSigner,rpc,legacy,shared);
 await oldWallet.open(phrase,mode,undefined,{persist:false});const oldRecovered=await oldWallet.restore(oldSafe);
 assert.equal(oldRecovered.factoryVersion,2);assert.equal(legacyRecord!.parts.ExperimentalSharedFactoryV2!.toLowerCase(),legacy.toLowerCase());
 assert.equal(legacyRecord!.parts.ExperimentalSharedFactoryV3,undefined);oldWallet.close();
 console.log(mode,'V2 recovery with simultaneous pinned V2+V3 factories passed');
 const unknown=createExperimentalWallet(()=>{},new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`);await unknown.open(phrase,mode);await assert.rejects(unknown.restore(safe),/shared address verification failed/);unknown.close();
 const wrongFactory=createExperimentalWallet(()=>{},new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${proxy.port}`,c10);await wrongFactory.open(phrase,mode);await assert.rejects(wrongFactory.restore(safe),/shared address verification failed/);wrongFactory.close();proxy.stop();
}
const wrongPhrase=entropyToMnemonic(new Uint8Array(32).fill(3),wordlist);let wrongRecord:WalletRecord|undefined;
let wrong=createExperimentalWallet(r=>wrongRecord=r,new RealSigner() as unknown as PQSigner,rpc,undefined,shared);await wrong.open(wrongPhrase,'mldsa44');wrong.close();
const tampered=structuredClone(wrongRecord!);tampered.parts.blob=helper;let wrongBroadcasts=0;
const wrongProxy=Bun.serve({port:0,async fetch(request){const body=await request.text(),call=JSON.parse(body);if(call.method==='eth_sendRawTransaction')wrongBroadcasts++;return fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body})}});
wrong=createExperimentalWallet(r=>wrongRecord=r,new RealSigner() as unknown as PQSigner,`http://127.0.0.1:${wrongProxy.port}`,undefined,shared);await wrong.open(wrongPhrase,'mldsa44',tampered);
await assert.rejects(wrong.create(parseEther('0.1')),/Deployment bytecode verification failed/);assert.equal(wrongBroadcasts,0);assert(!wrongRecord?.pending);wrong.close();wrongProxy.stop();
console.log('Mismatched prepared ML-DSA blob rejected before any broadcast');
