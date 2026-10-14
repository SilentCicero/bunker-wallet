// Explicit, test-only headless Sepolia check. Never run with a phrase protecting real funds.
import {readFileSync,writeFileSync,openSync,closeSync,fsyncSync,renameSync,statSync,existsSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {strict as assert} from 'node:assert';
import {createPublicClient,http,parseEther,bytesToHex,hexToBytes,formatEther,parseTransaction,recoverTransactionAddress,keccak256,type Address,type Hex} from 'viem';
import {mnemonicToAccount} from 'viem/accounts';
import {mnemonicToSeed} from '@scure/bip39';
import {ml_dsa44} from '@noble/post-quantum/ml-dsa.js';
import {derivePQSeed,prepareMLDSA,c10Keygen,c10Sign,type C10Wasm,type PQMode} from '../packages/pq/src/keys';
import {createExperimentalWallet,validateRecord,type WalletRecord} from '../apps/web/src/pq/wallet';
import type {PQSigner} from '../apps/web/src/pq/signer';

const mode=process.env.BUNKER_PQ_E2E_MODE as PQMode;
const secrets=process.env.BUNKER_PQ_E2E_SECRETS_FILE;
const rpc=process.env.BUNKER_PQ_E2E_RPC??'https://ethereum-sepolia.publicnode.com';
if(!['c10','mldsa44'].includes(mode)||!secrets)throw new Error('Set BUNKER_PQ_E2E_MODE and BUNKER_PQ_E2E_SECRETS_FILE');
const local=['localhost','127.0.0.1'].includes(new URL(rpc).hostname);
if(!local&&process.env.BUNKER_PQ_SEPOLIA_CONFIRM!=='disposable-test-eth-only')throw new Error('Explicit Sepolia test-only confirmation required');
if(statSync(secrets).mode&0o077)throw new Error('Secrets file must be private (chmod 600)');
const all=JSON.parse(readFileSync(secrets,'utf8')) as Record<PQMode,{mnemonic:string;address:Address}>;
const {mnemonic,address}=all[mode];
assert.equal(mnemonic.split(' ').length,24);
assert.equal(mnemonicToAccount(mnemonic,{path:"m/44'/60'/7331'/0/0"}).address,address);
const client=createPublicClient({transport:http(rpc)});
assert.equal(await client.getChainId(),11155111);
const initial=await client.getBalance({address});
const limit=parseEther(local?'1':'0.1');
if(initial===0n)throw new Error(`Fund ${address} with disposable test ETH before running`);
console.log(mode,'initial balance',formatEther(initial),'test ETH; cumulative signed-spend cap',formatEther(limit),'test ETH');
const output=resolve(dirname(secrets),`${local?'anvil':'sepolia'}-${mode}-record.json`);
const budgetPath=resolve(dirname(secrets),`${local?'anvil':'sepolia'}-${mode}-budget.json`);
const existing=existsSync(output)?validateRecord(JSON.parse(readFileSync(output,'utf8')) as WalletRecord):undefined;
if(existing?.pending)throw new Error(`Original ${existing.pending.kind} transaction ${existing.pending.hash} has an unknown outcome. Inspect/reconcile before resuming; no replacement was sent.`);
class Signer {
 secret:Uint8Array|undefined; wasm:C10Wasm|undefined;
 async init(phrase:string,kind:PQMode){const master=await mnemonicToSeed(phrase),seed=derivePQSeed(master,kind);master.fill(0);
  try{if(kind==='c10'){this.wasm=(await WebAssembly.instantiate(await Bun.file('apps/web/src/pq/generated/c10.wasm').arrayBuffer())).instance.exports as C10Wasm;return {mode:kind,publicKey:bytesToHex(c10Keygen(this.wasm,seed))};}
   const key=ml_dsa44.keygen(seed);this.secret=key.secretKey;return {mode:kind,publicKey:bytesToHex(key.publicKey),blob:bytesToHex(prepareMLDSA(key.publicKey))};
  }finally{seed.fill(0)}
 }
 async sign(digest:Hex){if(this.wasm)return bytesToHex(c10Sign(this.wasm,hexToBytes(digest)));if(this.secret)return bytesToHex(ml_dsa44.sign(hexToBytes(digest),this.secret));throw new Error('Signer unavailable');}
 close(){this.secret?.fill(0);if(this.wasm)new Uint8Array(this.wasm.memory.buffer).fill(0);this.secret=undefined;this.wasm=undefined;}
}
const durable=(path:string,value:unknown)=>{const temp=`${path}.${process.pid}.tmp`;
 const fd=openSync(temp,'w',0o600);try{writeFileSync(fd,JSON.stringify(value));fsyncSync(fd)}finally{closeSync(fd)}
 renameSync(temp,path);const directory=openSync(dirname(path),'r');try{fsyncSync(directory)}finally{closeSync(directory)}
};
const save=(record:WalletRecord)=>{durable(output,record);if(record.pending)console.log(mode,record.pending.kind,record.pending.hash)};
const budget=existsSync(budgetPath)?JSON.parse(readFileSync(budgetPath,'utf8')) as Record<Hex,string>:{};
let reserved=Object.values(budget).reduce((sum,value)=>sum+BigInt(value),0n);
if(reserved>limit)throw new Error('Headless test budget already exceeded');
const relayHost=local?'127.0.0.1':'127.0.0.2'; // Public-RPC proxy stays loopback-only, but uses production receipt polling.
const relay=Bun.serve({hostname:relayHost,port:0,async fetch(request){
 const body=await request.text(),call=JSON.parse(body);
 if(call.method==='eth_sendRawTransaction'){
  try{
   const raw=call.params?.[0] as Hex,tx=parseTransaction(raw),sender=await recoverTransactionAddress({serializedTransaction:raw as `0x02${string}`});
   if(tx.type!=='eip1559'||tx.chainId!==11155111||sender.toLowerCase()!==address.toLowerCase()||!tx.gas||!tx.maxFeePerGas)throw new Error('Unexpected signed transaction');
   const hash=keccak256(raw),ceiling=tx.gas*tx.maxFeePerGas+(tx.value??0n);
   if(budget[hash]&&BigInt(budget[hash])!==ceiling)throw new Error('Budget reservation mismatch');
   if(!budget[hash]){if(reserved+ceiling>limit)throw new Error('Headless test cumulative spend cap reached');durable(budgetPath,{...budget,[hash]:ceiling.toString()});budget[hash]=ceiling.toString();reserved+=ceiling;}
  }catch(error){return Response.json({jsonrpc:'2.0',id:call.id,error:{code:-32000,message:error instanceof Error?error.message:'Budget check failed'}})}
 }
 const upstream=await fetch(rpc,{method:'POST',headers:{'content-type':'application/json','accept-encoding':'identity'},body});
 return new Response(await upstream.text(),{status:upstream.status,headers:{'content-type':'application/json'}}); // Never forward a compressed upstream header with a decoded body.
}});
const wallet=createExperimentalWallet(save,new Signer() as unknown as PQSigner,`http://${relayHost}:${relay.port}`);
try{
 await wallet.open(mnemonic,mode,existing);
 const safe=await wallet.create();const before=await wallet.attest(safe);
 assert.equal(before.index,0,'Use a fresh test Safe; do not repeat a completed send');
 assert.equal(before.algorithm,mode==='c10'?1:2);
 if(before.balance<parseEther('0.01'))await wallet.fund(parseEther('0.01'));
 const recipient='0x000000000000000000000000000000000000cafe' as Address;
 const hash=await wallet.send(recipient,parseEther('0.00001'));
 const after=await wallet.attest(safe);
 assert.equal(after.index,1);assert.equal(after.cycle,0);assert.equal(after.pq.toLowerCase(),before.pq.toLowerCase());
 const receipts=await Promise.all(Object.keys(budget).map(async id=>{const hash=id as Hex,receipt=await client.getTransactionReceipt({hash}),tx=await client.getTransaction({hash});
  assert.equal(receipt.status,'success');assert.equal(receipt.from.toLowerCase(),address.toLowerCase());
  return {hash,contractAddress:receipt.contractAddress,blockNumber:receipt.blockNumber.toString(),gasUsed:receipt.gasUsed.toString(),effectiveGasPrice:receipt.effectiveGasPrice.toString(),value:tx.value.toString()};
 }));
 durable(resolve(dirname(secrets),`${local?'anvil':'sepolia'}-${mode}-receipts.json`),{mode,safe,pqOwner:after.pq,ecOwner:after.ec,rotation:after.index,receipts});
 console.log(mode,'Safe',safe,'PQ owner',after.pq,'rotation',after.index,'send',hash);
}finally{wallet.close();relay.stop()}
