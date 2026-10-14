// Disposable Anvil fixture: spend only the ephemeral faucet signer; never use public Sepolia.
import {strict as assert} from 'node:assert';
import {createPublicClient,createWalletClient,http,encodeDeployData,keccak256,type Address,type Hex} from 'viem';
import {privateKeyToAccount} from 'viem/accounts';
import {sepolia} from 'viem/chains';
import {artifacts,dataCreation} from '../apps/web/src/pq/wallet';
import v2 from '../apps/web/src/pq/generated/artifactsV2.json';
import v3 from '../apps/web/src/pq/generated/artifactsV3.json';
import official from '../tests/fixtures/sepolia-safe-1.4.1.json';

const key=process.env.LOCAL_FAUCET_PRIVATE_KEY as Hex|undefined;
assert(key&&/^0x[0-9a-fA-F]{64}$/.test(key),'Ephemeral faucet key required');
const transport=http('http://127.0.0.1:18545'),client=createPublicClient({chain:sepolia,transport}),account=privateKeyToAccount(key),wallet=createWalletClient({account,chain:sepolia,transport});
assert.equal(await client.getChainId(),11155111);
for(const code of Object.values(official.codes))await client.request({method:'anvil_setCode' as never,params:[code.address,code.runtime] as never});
async function deploy(name:string,args:readonly unknown[]=[],runtime?:Hex){
 const artifact=name==='ExperimentalSharedFactoryV2'?v2:name==='ExperimentalSharedFactoryV3'?v3:artifacts[name]!;
 const data=runtime?dataCreation(runtime):encodeDeployData({abi:artifact.abi,bytecode:artifact.bytecode as Hex,args});
 const receipt=await client.waitForTransactionReceipt({hash:await wallet.sendTransaction({data,gas:12_000_000n})});
 assert.equal(receipt.status,'success');assert(receipt.contractAddress);return receipt.contractAddress;
}
const helper=await deploy('',[],artifacts.helper),c10=await deploy('SphincsC10Asm'),mldsa=await deploy('MLDSA44Verifier',[helper]);
const binding=async(address:Address)=>({target:address,codeHash:keccak256((await client.getCode({address}))!)});
const factory=await deploy(process.env.V3_FIXTURE==='1'?'ExperimentalSharedFactoryV3':'ExperimentalSharedFactoryV2',[await binding(official.codes.singleton.address as Address),await binding(official.codes.factory.address as Address),await binding(official.codes.multisend.address as Address),await binding(c10),await binding(mldsa),await binding(helper),'0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c']);
console.log(factory);
