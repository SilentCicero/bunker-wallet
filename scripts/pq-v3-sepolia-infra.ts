// One Sepolia V3 factory only. Encrypted signed intent is durable before broadcast; never auto-replace.
import {readFileSync,existsSync,openSync,closeSync,writeFileSync,fsyncSync,renameSync,statSync} from 'node:fs';
import {dirname} from 'node:path';
import {strict as assert} from 'node:assert';
import {createPublicClient,createWalletClient,http,encodeDeployData,keccak256,hexToBytes,bytesToHex,padHex,toHex,parseEther,formatEther,type Address,type Hex} from 'viem';
import {mnemonicToAccount} from 'viem/accounts';
import {sepolia} from 'viem/chains';
import {artifacts,runtime} from '../apps/web/src/pq/wallet';
import {outboxKey,sealTransaction} from '../apps/web/src/pq/outbox';
import v3 from '../apps/web/src/pq/generated/artifactsV3.json';

const stage=process.argv[2]??'';if(!['plan','deploy','verify','verify-secondary'].includes(stage))throw new Error('Use plan, deploy, verify or verify-secondary');
const privateDir='/root/bunker-hybrid-validation/private',secrets='/root/.config/bunker-wallet/secrets/sepolia-e2e.env';
const journal=`${privateDir}/v3-sepolia-infra-journal.json`,manifest=`${privateDir}/v3-sepolia-infra-manifest.json`;
const rpc=process.env.BUNKER_V3_RPC??'https://ethereum-sepolia.publicnode.com';
const client=createPublicClient({chain:sepolia,transport:http(rpc),pollingInterval:4000});
const durable=(file:string,value:unknown)=>{const tmp=`${file}.${process.pid}.tmp`,fd=openSync(tmp,'w',0o600);try{writeFileSync(fd,JSON.stringify(value));fsyncSync(fd)}finally{closeSync(fd)}renameSync(tmp,file);const dir=openSync(dirname(file),'r');try{fsyncSync(dir)}finally{closeSync(dir)}};
const load=<T>(file:string):T|undefined=>existsSync(file)?JSON.parse(readFileSync(file,'utf8')) as T:undefined;
if(statSync(secrets).mode&0o077)throw new Error('Secrets file permissions are too broad');
const env=Object.fromEntries(readFileSync(secrets,'utf8').split(/\r?\n/).filter(s=>s.includes('=')).map(s=>{const[k,...v]=s.split('=');return[k,v.join('=').replace(/^"|"$/g,'')]}));
const payer=mnemonicToAccount(env.BUNKER_SEPOLIA_MNEMONIC,{path:"m/44'/60'/7331'/0/0"});
assert.equal(payer.address.toLowerCase(),env.BUNKER_SEPOLIA_SETUP_ADDRESS.toLowerCase());assert.equal(await client.getChainId(),11155111);
const sources={singleton:'0x41675C099F32341bf84BFc5382aF534df5C7461a',proxyFactory:'0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67',multi:'0x9641d764fc13c8B624c04430C7356C1C7C8102e2',helper:'0xea655ad17483b3b1ad68c8ff69ff8166489ea71c',c10:'0x69105696002246141c78c6c7af1c8c855814c043',mldsa:'0x2f214312ce536d65e4d04a03cd9a2c4b9f592d51'} as const;
const hashes={singleton:'0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4',proxyFactory:'0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317',multi:'0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939'} as const;
const proxyHash='0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c' as Hex;
const sourceCode=Object.fromEntries(await Promise.all(Object.entries(sources).map(async([name,address])=>[name,await client.getCode({address})]))) as Record<keyof typeof sources,Hex>;
for(const [name,hash] of Object.entries(hashes))assert.equal(keccak256(sourceCode[name as keyof typeof sources]),hash);
assert.equal(sourceCode.helper.toLowerCase(),artifacts.helper.toLowerCase());
assert.equal(sourceCode.c10.toLowerCase(),runtime('SphincsC10Asm',{}).toLowerCase());
assert.equal(sourceCode.mldsa.toLowerCase(),runtime('MLDSA44Verifier',{F1600:sources.helper}).toLowerCase());
const dep=(key:keyof typeof sources)=>({target:sources[key],codeHash:keccak256(sourceCode[key])});
const args=[dep('singleton'),dep('proxyFactory'),dep('multi'),dep('c10'),dep('mldsa'),dep('helper'),proxyHash] as const;
const creation=encodeDeployData({abi:v3.abi,bytecode:v3.bytecode as Hex,args});
type Entry={hash:Hex;ceiling:string;gas:string;maxFeePerGas:string;sealed:{iv:Hex;ciphertext:Hex};address?:Address;block?:string};
let entry=load<Entry>(journal);
async function attest(address:Address,blockNumber?:bigint,observer=client){
 const read=(fn:string,target=address,abi=v3.abi)=>observer.readContract({address:target,abi,functionName:fn,blockNumber}) as Promise<any>;
 const actual=await observer.getCode({address,blockNumber});if(!actual)throw new Error('V3 factory missing');
 const bytes=hexToBytes(v3.runtime as Hex),bindings:Record<string,Hex>={};
 for(const [name,refs] of Object.entries(v3.immutables)){const value=await read(name) as Hex;bindings[name]=value;const word=hexToBytes(padHex(value,{size:32}));for(const ref of refs)bytes.set(word,ref.start)}
 assert.equal(actual.toLowerCase(),bytesToHex(bytes).toLowerCase(),'V3 factory runtime/immutables');
 assert.equal(await read('factoryVersion'),3n);
 for(const [name,key] of [['singleton','singleton'],['proxyFactory','proxyFactory'],['c10Verifier','c10'],['mldsaVerifier','mldsa'],['mldsaHelper','helper']] as const)assert.equal(String(await read(name)).toLowerCase(),sources[key].toLowerCase());
 for(const [name,key] of [['singletonCodeHash','singleton'],['proxyFactoryCodeHash','proxyFactory'],['c10VerifierCodeHash','c10'],['mldsaVerifierCodeHash','mldsa']] as const)assert.equal(String(await read(name)).toLowerCase(),keccak256(sourceCode[key]).toLowerCase());
 const guard=await read('guard') as Address,setup=await read('setup') as Address;
 const guardCode=await observer.getCode({address:guard,blockNumber}),setupCode=await observer.getCode({address:setup,blockNumber});
 assert.equal(guardCode?.toLowerCase(),runtime('ExperimentalRotationGuardV3',{factory:address,singleton:sources.singleton,singletonCodeHash:hashes.singleton,proxyFactory:sources.proxyFactory,proxyFactoryCodeHash:hashes.proxyFactory,multiSendCallOnly:sources.multi,multiSendCodeHash:hashes.multi,proxyCodeHash:proxyHash}).toLowerCase());
 assert.equal(setupCode?.toLowerCase(),runtime('ExperimentalSetup',{guard,proxyFactory:sources.proxyFactory}).toLowerCase());
 assert.equal(String(await read('guardCodeHash')).toLowerCase(),keccak256(guardCode!).toLowerCase());
 assert.equal(String(await read('setupCodeHash')).toLowerCase(),keccak256(setupCode!).toLowerCase());
 return {factory:address,guard,setup,block:blockNumber?.toString(),runtimeHash:keccak256(actual),creationHash:keccak256(v3.bytecode as Hex)};
}
if(stage==='verify'||stage==='verify-secondary'){
 if(!entry)throw new Error('No original V3 factory journal');
 const observer=stage==='verify-secondary'?createPublicClient({chain:sepolia,transport:http('https://sepolia.drpc.org',{timeout:20000})}):client;
 assert.equal(await observer.getChainId(),11155111);
 const receipt=await observer.getTransactionReceipt({hash:entry.hash});assert.equal(receipt.status,'success');assert.equal(receipt.from.toLowerCase(),payer.address.toLowerCase());assert.equal(receipt.to,null);assert(receipt.contractAddress);
 if(entry.address)assert.equal(receipt.contractAddress.toLowerCase(),entry.address.toLowerCase());
 if(entry.block)assert.equal(receipt.blockNumber,BigInt(entry.block));
 if(stage==='verify-secondary')for(const [name,address] of Object.entries(sources))assert.equal((await observer.getCode({address,blockNumber:receipt.blockNumber}))?.toLowerCase(),sourceCode[name as keyof typeof sources].toLowerCase(),`Independent ${name} dependency`);
 const result=await attest(receipt.contractAddress,receipt.blockNumber,observer);
 if(stage==='verify'){entry={...entry,address:receipt.contractAddress,block:receipt.blockNumber.toString()};durable(journal,entry);durable(manifest,{...result,hash:entry.hash})}
 else{const pinned=load<{factory:Address;runtimeHash:Hex;hash:Hex}>(manifest);assert(pinned);assert.equal(pinned.factory.toLowerCase(),result.factory.toLowerCase());assert.equal(pinned.runtimeHash,result.runtimeHash);assert.equal(pinned.hash,entry.hash)}
 console.log('Confirmed V3 factory',result,'transaction',entry.hash,'source',stage);process.exit(0);
}
if(entry)throw new Error(`Original signed V3 intent ${entry.hash} exists. Run verify/read-only; NEVER sign a replacement.`);
const spent=(file:string)=>{const x=load<any>(`${privateDir}/${file}`);if(!x)return 0n;if(x.pending)throw new Error(`An older ${file} journal has an unresolved pending intent`);return x.completed?x.completed.reduce((sum:bigint,item:any)=>sum+BigInt(item.ceiling),x.pending?BigInt(x.pending.ceiling):0n):Object.values(x).reduce((sum:bigint,v)=>sum+BigInt(v as string),0n)};
const previous=['v2-sepolia-budget.json','v2-sepolia-c10-budget.json','v2-sepolia-mldsa44-budget.json','sepolia-c10-budget.json','sepolia-mldsa44-budget.json'].reduce((sum,file)=>sum+spent(file),0n);
const [latest,pending]=await Promise.all([client.getTransactionCount({address:payer.address,blockTag:'latest'}),client.getTransactionCount({address:payer.address,blockTag:'pending'})]);if(latest!==pending)throw new Error('Payer has an earlier pending transaction');
const estimated=await client.estimateGas({account:payer.address,data:creation}),gas=estimated+estimated/10n;
const [fees,block,balance]=await Promise.all([client.estimateFeesPerGas(),client.getBlock(),client.getBalance({address:payer.address})]);
const ceiling=gas*fees.maxFeePerGas;
// Conservative 0.5 ETH allowance for all other historical user-requested testnet transfers.
if(gas>block.gasLimit||previous+parseEther('0.5')+ceiling>parseEther('1')||ceiling>parseEther('0.05')||balance<ceiling+parseEther('0.08'))throw new Error('Aggregate cap, deploy ceiling or payer reserve exceeded');
console.log('V3 factory estimated gas',estimated.toString(),'maximum reserved test ETH',formatEther(ceiling),'prior tracked ceiling',formatEther(previous));
if(stage==='plan')process.exit(0);
if(process.env.BUNKER_V3_CONFIRM!=='sepolia-v3-infra-1-eth-cap')throw new Error('Explicit V3 Sepolia infrastructure authorization flag required');
const wallet=createWalletClient({account:payer,chain:sepolia,transport:http(rpc)});
const request=await wallet.prepareTransactionRequest({account:payer,data:creation,value:0n,gas,maxFeePerGas:fees.maxFeePerGas,maxPriorityFeePerGas:fees.maxPriorityFeePerGas});
if(request.chainId!==11155111||request.nonce!==latest||request.data!==creation||request.value!==0n||request.to!==undefined||request.gas!==gas)throw new Error('Prepared deployment changed');
const raw=await payer.signTransaction(request),hash=keccak256(raw);
const secret=await outboxKey(env.BUNKER_SEPOLIA_MNEMONIC,`v3-sepolia-infra-${payer.address}`);
const sealed=await sealTransaction(secret,{raw,sender:payer.address,to:null,value:'0',nonce:latest,data:creation,gas:gas.toString()},hash);
entry={hash,ceiling:ceiling.toString(),gas:gas.toString(),maxFeePerGas:fees.maxFeePerGas.toString(),sealed};durable(journal,entry);
try{const result=await wallet.sendRawTransaction({serializedTransaction:raw});if(result.toLowerCase()!==hash.toLowerCase())throw new Error('RPC hash mismatch')}catch{throw new Error(`V3 deployment broadcast outcome unknown for ${hash}; encrypted signed intent retained. Verify original, no replacement.`)}
const receipt=await client.waitForTransactionReceipt({hash});
if(receipt.status!=='success'||receipt.from.toLowerCase()!==payer.address.toLowerCase()||receipt.to!==null||!receipt.contractAddress)throw new Error(`Original V3 deployment receipt failed identity/status for ${hash}; intent retained`);
const verified=await attest(receipt.contractAddress,receipt.blockNumber);entry={...entry,address:receipt.contractAddress,block:receipt.blockNumber.toString()};durable(journal,entry);durable(manifest,{...verified,hash});
console.log('V3 factory deployed and attested',verified,'transaction',hash);
