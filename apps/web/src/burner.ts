import { generatePrivateKey, mnemonicToAccount, privateKeyToAccount } from "viem/accounts";
import { bytesToHex, createPublicClient, createWalletClient, http, parseEther, type Address, type Hex } from "viem";
import { arbitrumSepolia } from "viem/chains";
import { demoWalletAbi, demoWalletBytecode } from "./demoContract";

export const ARBITRUM_SEPOLIA_CHAIN_ID = 421614;
export const ARBITRUM_SEPOLIA_RPC = "https://sepolia-rollup.arbitrum.io/rpc";
export const ARBITRUM_SEPOLIA_FAUCET = "https://faucet.quicknode.com/arbitrum/sepolia";
let privateKey: Hex | undefined;
let mnemonicSecret: string | undefined;
let pendingPrivateKey: Hex | undefined;
let ownerIndex = 0;
const publicClient = createPublicClient({ chain: arbitrumSepolia, transport: http(ARBITRUM_SEPOLIA_RPC) });
function signer() { if (!privateKey) throw new Error("Create or load a testnet key first."); const account=privateKeyToAccount(privateKey); return { account, client:createWalletClient({ account, chain:arbitrumSepolia, transport:http(ARBITRUM_SEPOLIA_RPC) }) }; }
const mnemonicKey=(mnemonic:string,index:number)=>{const key=mnemonicToAccount(mnemonic,{path:`m/44'/60'/7331'/0/${index}`}).getHdKey().privateKey;if(!key)throw new Error("Recovery key could not be derived.");return bytesToHex(key)};
async function reconcilePending(wallet:Address){if(!pendingPrivateKey)return;const onchain=await publicClient.readContract({address:wallet,abi:demoWalletAbi,functionName:"owner"}),pendingOwner=privateKeyToAccount(pendingPrivateKey).address;if(onchain.toLowerCase()===pendingOwner.toLowerCase()){privateKey=pendingPrivateKey;ownerIndex++}pendingPrivateKey=undefined;}
async function rotatedWrite(wallet:Address,functionName:"sendETH"|"sendERC20"|"postMessage",args:readonly unknown[],value?:bigint):Promise<Hex>{await reconcilePending(wallet);const {client}=signer(),next=mnemonicSecret?mnemonicKey(mnemonicSecret,ownerIndex+1):generatePrivateKey(),nextOwner=privateKeyToAccount(next).address;const hash=await client.writeContract({address:wallet,abi:demoWalletAbi,functionName,args:[...args,nextOwner],value} as never);pendingPrivateKey=next;try{const receipt=await publicClient.waitForTransactionReceipt({hash});if(receipt.status!=="success")throw new Error("Arbitrum Sepolia transaction reverted.");await reconcilePending(wallet);return hash}catch(error){try{await reconcilePending(wallet)}catch{}throw error;}}

export function createEphemeralBurner(): Address {
  mnemonicSecret=undefined;ownerIndex=0;privateKey = generatePrivateKey();
  return privateKeyToAccount(privateKey).address;
}
export function loadMnemonicSigner(mnemonic:string,index=0):Address{mnemonicSecret=mnemonic;ownerIndex=index;privateKey=mnemonicKey(mnemonic,index);return privateKeyToAccount(privateKey).address;}
export function clearEphemeralBurner(): void { privateKey = undefined;pendingPrivateKey=undefined;mnemonicSecret=undefined;ownerIndex=0; }
export function hasEphemeralBurner(): boolean { return privateKey !== undefined; }
export async function deployDemoWallet():Promise<Address>{const {account,client}=signer(),balance=await publicClient.getBalance({address:account.address});const reserve=parseEther("0.006");if(balance<=reserve)throw new Error("Fund at least 0.007 Arbitrum Sepolia ETH before creating the demo wallet.");const hash=await client.deployContract({abi:demoWalletAbi,bytecode:demoWalletBytecode,args:[account.address],value:balance-reserve});const receipt=await publicClient.waitForTransactionReceipt({hash});if(receipt.status!=="success"||!receipt.contractAddress)throw new Error("Demo wallet deployment failed.");return receipt.contractAddress;}
export async function readDemoWallet(wallet:Address){const [balance,owner,index]=await Promise.all([publicClient.getBalance({address:wallet}),publicClient.readContract({address:wallet,abi:demoWalletAbi,functionName:"owner"}),publicClient.readContract({address:wallet,abi:demoWalletAbi,functionName:"rotationIndex"})]);return{balance,owner,index:Number(index)}}
export const demoSendETH=(wallet:Address,to:Address,amount:bigint)=>rotatedWrite(wallet,"sendETH",[to,amount]);
export const demoSendERC20=(wallet:Address,token:Address,to:Address,amount:bigint)=>rotatedWrite(wallet,"sendERC20",[token,to,amount]);
export const demoPostMessage=(wallet:Address,message:string)=>rotatedWrite(wallet,"postMessage",[message]);
export async function readArbitrumSepoliaBalance(address: Address): Promise<bigint> {
  const response = await fetch(ARBITRUM_SEPOLIA_RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBalance", params: [address, "latest"] }), signal: AbortSignal.timeout(8_000) });
  if (!response.ok) throw new Error("Arbitrum Sepolia RPC is unavailable.");
  const text = await response.text();
  if (text.length > 4_096) throw new Error("Arbitrum Sepolia returned an oversized response.");
  const body = JSON.parse(text) as { result?: string; error?: unknown };
  if (body.error || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(body.result ?? "")) throw new Error("Arbitrum Sepolia returned an invalid balance.");
  const balance = BigInt(body.result!);
  if (balance >= 1n << 256n) throw new Error("Arbitrum Sepolia returned an invalid balance.");
  return balance;
}
