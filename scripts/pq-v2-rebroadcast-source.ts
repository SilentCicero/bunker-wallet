// One explicit exact-byte rebroadcast of the previously sealed ML-DSA test funding intent.
import {readFileSync,existsSync,statSync,openSync,closeSync,writeFileSync,fsyncSync,renameSync} from 'node:fs';
import {dirname} from 'node:path';
import {strict as assert} from 'node:assert';
import {createPublicClient,http,keccak256,parseTransaction,recoverTransactionAddress,parseEther, TransactionReceiptNotFoundError,TransactionNotFoundError,type Address,type Hex} from 'viem';
import {sepolia} from 'viem/chains';
import {mnemonicToAccount} from 'viem/accounts';
import {outboxKey,openTransaction,type SealedTransaction} from '../apps/web/src/pq/outbox';

if(process.env.BUNKER_V2_REBROADCAST!=='approved-original-0x7478')throw new Error('Explicit approval of the original signed transaction required');
const root='/root/bunker-hybrid-validation/private',path=`${root}/v2-sepolia-budget.json`,secretPath='/root/.config/bunker-wallet/secrets/sepolia-e2e.env';
if(statSync(path).mode&0o077||statSync(secretPath).mode&0o077)throw new Error('Private intent/secret permissions required');
const env=Object.fromEntries(readFileSync(secretPath,'utf8').split(/\r?\n/).filter(x=>x.includes('=')).map(x=>{const[k,...v]=x.split('=');return[k,v.join('=').replace(/^"|"$/g,'')]}));
const sender=mnemonicToAccount(env.BUNKER_SEPOLIA_MNEMONIC,{path:"m/44'/60'/7331'/0/0"}).address;
assert.equal(sender.toLowerCase(),env.BUNKER_SEPOLIA_SETUP_ADDRESS.toLowerCase());
const original='0x74787c6907d6a1ec834d3cc74f4e070d9a971220ad9ddb59e89bbe4471f166be' as Hex;
type Entry={kind:string;hash:Hex;ceiling:string;value:string;gas:string;maxFeePerGas:string;receiptBlock?:string;gasUsed?:string;effectiveGasPrice?:string};
type Journal={pending?:Entry&{sealed:SealedTransaction};completed:Entry[]};
let journal=JSON.parse(readFileSync(path,'utf8')) as Journal;const pending=journal.pending;
if(!pending||pending.kind!=='fund-mldsa44'||pending.hash.toLowerCase()!==original||journal.completed.some(e=>e.hash.toLowerCase()===original))throw new Error('Original pending funding intent is absent or changed');
const publicRecipient=(JSON.parse(readFileSync(`${root}/v2-sepolia-phrases.json`,'utf8')) as {mldsa44:{address:Address}}).mldsa44.address;
const key=await outboxKey(env.BUNKER_SEPOLIA_MNEMONIC,`v2-sepolia-${sender}`);
const intent=await openTransaction(key,pending.sealed,original) as {raw:Hex;sender:Address;to:Address;value:string;nonce:number;data:Hex;gas:string};
if(!intent.raw||keccak256(intent.raw).toLowerCase()!==original||intent.sender.toLowerCase()!==sender.toLowerCase()||intent.to.toLowerCase()!==publicRecipient.toLowerCase()||intent.value!==parseEther('0.04').toString()||intent.data!=='0x'||intent.gas!==pending.gas)throw new Error('Sealed original intent differs from authorized funding');
const tx=parseTransaction(intent.raw),recovered=await recoverTransactionAddress({serializedTransaction:intent.raw as `0x02${string}`});
if(tx.type!=='eip1559'||tx.chainId!==11155111||tx.nonce!==intent.nonce||recovered.toLowerCase()!==sender.toLowerCase()||tx.to?.toLowerCase()!==publicRecipient.toLowerCase()||tx.value?.toString()!==pending.value||tx.gas?.toString()!==pending.gas||tx.maxFeePerGas?.toString()!==pending.maxFeePerGas||(tx.gas!*tx.maxFeePerGas!+tx.value!)!==BigInt(pending.ceiling))throw new Error('Raw transaction authentication failed');
const readers=['https://sepolia.gateway.tenderly.co','https://api.blockvectra.com/v1/eth_sepolia/public'] as const;
for(const rpc of readers){const client=createPublicClient({chain:sepolia,transport:http(rpc)});if(await client.getChainId()!==11155111)throw new Error('RPC is not Sepolia');
 const receipt=await client.getTransactionReceipt({hash:original}).catch(error=>{if(error instanceof TransactionReceiptNotFoundError)return null;throw error});await new Promise(r=>setTimeout(r,650));
 const seen=await client.getTransaction({hash:original}).catch(error=>{if(error instanceof TransactionNotFoundError)return null;throw error});await new Promise(r=>setTimeout(r,650));
 const nonce=await client.getTransactionCount({address:sender,blockTag:'pending'});await new Promise(r=>setTimeout(r,650));
 const targetBalance=await client.getBalance({address:publicRecipient});
 if(receipt||seen||nonce!==tx.nonce||targetBalance!==0n)throw new Error(`Original outcome or recipient state changed on ${rpc}; stop without rebroadcast`);
}
const sum=(v:Record<string,string>)=>Object.values(v).reduce((a,b)=>a+BigInt(b),0n);
const modes=(['c10','mldsa44'] as const).reduce((a,mode)=>{const file=`${root}/v2-sepolia-${mode}-budget.json`;return a+(existsSync(file)?sum(JSON.parse(readFileSync(file,'utf8')) as Record<string,string>):0n)},0n);
const total=journal.completed.reduce((a,e)=>a+BigInt(e.ceiling),BigInt(pending.ceiling))+modes;
if(total>parseEther('1'))throw new Error('Aggregate 1 ETH ceiling exceeded');
if(process.env.BUNKER_V2_REBROADCAST_PREVIEW==='1'){console.log('Original sealed transaction authenticated; two RPCs show no receipt, transaction or nonce change; aggregate ceiling within 1 ETH:',original);process.exit(0)}
// The only network write: exact bytes from the authenticated, fsynced sealed journal.
let returned:Hex;try{returned=await createPublicClient({chain:sepolia,transport:http(readers[1])}).request({method:'eth_sendRawTransaction',params:[intent.raw]});if(returned.toLowerCase()!==original)throw new Error('RPC returned a different hash')}catch{throw new Error(`Original broadcast outcome remains unknown for ${original}; keep the journal and inspect the original receipt`)}
const client=createPublicClient({chain:sepolia,transport:http(readers[0]),pollingInterval:4000});
const receipt=await client.waitForTransactionReceipt({hash:original,timeout:120000});
if(receipt.status!=='success'||receipt.transactionHash.toLowerCase()!==original||receipt.from.toLowerCase()!==sender.toLowerCase()||receipt.to?.toLowerCase()!==publicRecipient.toLowerCase())throw new Error('Original funding receipt is mismatched or reverted; pending intent retained');
const durable=(value:Journal)=>{const tmp=`${path}.${process.pid}.tmp`,fd=openSync(tmp,'w',0o600);try{writeFileSync(fd,JSON.stringify(value));fsyncSync(fd)}finally{closeSync(fd)}renameSync(tmp,path);const dir=openSync(dirname(path),'r');try{fsyncSync(dir)}finally{closeSync(dir)}};
journal={completed:[...journal.completed,{kind:pending.kind,hash:original,ceiling:pending.ceiling,value:pending.value,gas:pending.gas,maxFeePerGas:pending.maxFeePerGas,receiptBlock:receipt.blockNumber.toString(),gasUsed:receipt.gasUsed.toString(),effectiveGasPrice:receipt.effectiveGasPrice.toString()}]};durable(journal);
console.log('Original exact-byte ML-DSA setup funding confirmed',original,'block',receipt.blockNumber.toString(),'recipient',publicRecipient);
