import {
  concatHex,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  http,
  hashTypedData,
  keccak256,
  padHex,
  parseEther,
  parseEventLogs,
  toHex,
  type Address,
  type Hex,
} from "viem";
import { generatePrivateKey, mnemonicToAccount, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import { bunkerGuardAbi, bunkerGuardBytecode, bunkerGuardRuntimeHash, bunkerSetupAbi, bunkerSetupBytecode, safeProxyRuntimeHash } from "./safeArtifacts";

export const SEPOLIA_CHAIN_ID = 11155111;
export const SEPOLIA_RPC = import.meta.env.VITE_SEPOLIA_RPC || "https://ethereum-sepolia-rpc.publicnode.com";
export const SEPOLIA_FAUCET = "https://cloud.google.com/application/web3/faucet/ethereum/sepolia";

const SAFE_SINGLETON = "0x41675C099F32341bf84BFc5382aF534df5C7461a" as Address;
const SAFE_PROXY_FACTORY = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67" as Address;
const MULTISEND_CALL_ONLY = "0x9641d764fc13c8B624c04430C7356C1C7C8102e2" as Address;
const SAFE_CODE_HASH = "0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4";
const FACTORY_CODE_HASH = "0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317";
const MULTISEND_CODE_HASH = "0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939";
const GUARD_SLOT = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8" as Hex;
const FALLBACK_SLOT = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5" as Hex;
const ZERO = "0x0000000000000000000000000000000000000000" as Address;
const SENTINEL = "0x0000000000000000000000000000000000000001" as Address;

const safeAbi = [
  { type: "function", name: "setup", stateMutability: "nonpayable", inputs: [{ name: "_owners", type: "address[]" }, { name: "_threshold", type: "uint256" }, { name: "to", type: "address" }, { name: "data", type: "bytes" }, { name: "fallbackHandler", type: "address" }, { name: "paymentToken", type: "address" }, { name: "payment", type: "uint256" }, { name: "paymentReceiver", type: "address" }], outputs: [] },
  { type: "function", name: "getOwners", stateMutability: "view", inputs: [], outputs: [{ type: "address[]" }] },
  { type: "function", name: "getThreshold", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "getModulesPaginated", stateMutability: "view", inputs: [{ type: "address", name: "start" }, { type: "uint256", name: "pageSize" }], outputs: [{ type: "address[]", name: "array" }, { type: "address", name: "next" }] },
  { type: "function", name: "nonce", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "swapOwner", stateMutability: "nonpayable", inputs: [{ type: "address", name: "prevOwner" }, { type: "address", name: "oldOwner" }, { type: "address", name: "newOwner" }], outputs: [] },
  { type: "function", name: "getTransactionHash", stateMutability: "view", inputs: [{ type: "address", name: "to" }, { type: "uint256", name: "value" }, { type: "bytes", name: "data" }, { type: "uint8", name: "operation" }, { type: "uint256", name: "safeTxGas" }, { type: "uint256", name: "baseGas" }, { type: "uint256", name: "gasPrice" }, { type: "address", name: "gasToken" }, { type: "address", name: "refundReceiver" }, { type: "uint256", name: "_nonce" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "execTransaction", stateMutability: "payable", inputs: [{ type: "address", name: "to" }, { type: "uint256", name: "value" }, { type: "bytes", name: "data" }, { type: "uint8", name: "operation" }, { type: "uint256", name: "safeTxGas" }, { type: "uint256", name: "baseGas" }, { type: "uint256", name: "gasPrice" }, { type: "address", name: "gasToken" }, { type: "address", name: "refundReceiver" }, { type: "bytes", name: "signatures" }], outputs: [{ type: "bool", name: "success" }] },
] as const;
const factoryAbi = [
  { type: "function", name: "createChainSpecificProxyWithNonce", stateMutability: "nonpayable", inputs: [{ type: "address", name: "_singleton" }, { type: "bytes", name: "initializer" }, { type: "uint256", name: "saltNonce" }], outputs: [{ type: "address", name: "proxy" }] },
  { type: "event", name: "ProxyCreation", inputs: [{ indexed: true, name: "proxy", type: "address" }, { indexed: false, name: "singleton", type: "address" }], anonymous: false },
] as const;
const multiSendAbi = [{ type: "function", name: "multiSend", stateMutability: "payable", inputs: [{ name: "transactions", type: "bytes" }], outputs: [] }] as const;
const safeTxTypes = { SafeTx: [
  { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "data", type: "bytes" },
  { name: "operation", type: "uint8" }, { name: "safeTxGas", type: "uint256" }, { name: "baseGas", type: "uint256" },
  { name: "gasPrice", type: "uint256" }, { name: "gasToken", type: "address" }, { name: "refundReceiver", type: "address" },
  { name: "nonce", type: "uint256" },
] } as const;

let privateKey: Hex | undefined;
let sponsorPrivateKey: Hex | undefined;
let mnemonicSecret: string | undefined;
let pendingPrivateKey: Hex | undefined;
let futurePrivateKeys: Hex[] = [];
let ownerIndex = 0;
let guardAddress: Address | undefined;
const publicClient = createPublicClient({ chain: sepolia, transport: http(SEPOLIA_RPC) });
const mnemonicKey = (mnemonic: string, index: number) => {
  const key = mnemonicToAccount(mnemonic, { path: `m/44'/60'/7331'/0/${index}` }).getHdKey().privateKey;
  if (!key) throw new Error("Recovery key could not be derived.");
  return toHex(key);
};
const ownerAccount = () => { if (!privateKey) throw new Error("Create or load a testnet key first."); return privateKeyToAccount(privateKey); };
const sponsorClient = () => {
  if (!sponsorPrivateKey) throw new Error("The Sepolia broadcaster key is unavailable. Restore or restart setup.");
  const account = privateKeyToAccount(sponsorPrivateKey);
  return { account, client: createWalletClient({ account, chain: sepolia, transport: http(SEPOLIA_RPC) }) };
};
const checkedCode = async (address: Address, expected: Hex) => {
  const code = await publicClient.getCode({ address });
  if (!code || keccak256(code) !== expected) throw new Error("Safe deployment verification failed.");
};
const deploy = async (abi: readonly unknown[], bytecode: Hex, args: readonly unknown[] = []) => {
  const { client } = sponsorClient();
  const hash = await client.deployContract({ abi, bytecode, args, gas: 10_000_000n } as never);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success" || !receipt.contractAddress) throw new Error("Safe component deployment failed.");
  return receipt.contractAddress;
};
const sequence = () => {
  if (futurePrivateKeys.length === 20) return futurePrivateKeys;
  futurePrivateKeys = mnemonicSecret
    ? Array.from({ length: 20 }, (_, i) => mnemonicKey(mnemonicSecret!, i + 1))
    : Array.from({ length: 20 }, () => generatePrivateKey());
  return futurePrivateKeys;
};
const storageAddress = (value?: Hex) => value ? (`0x${value.slice(-40)}` as Address) : ZERO;

async function attestSafe(safe: Address, expectedOwner: Address, expectedGuard: Address) {
  await Promise.all([checkedCode(safe, safeProxyRuntimeHash), checkedCode(expectedGuard, bunkerGuardRuntimeHash)]);
  const [owners, threshold, modules, guardSlot, fallbackSlot, singletonSlot, guardState, multiSend, multiSendHash] = await Promise.all([
    publicClient.readContract({ address: safe, abi: safeAbi, functionName: "getOwners" }),
    publicClient.readContract({ address: safe, abi: safeAbi, functionName: "getThreshold" }),
    publicClient.readContract({ address: safe, abi: safeAbi, functionName: "getModulesPaginated", args: [SENTINEL, 1n] }),
    publicClient.getStorageAt({ address: safe, slot: GUARD_SLOT }),
    publicClient.getStorageAt({ address: safe, slot: FALLBACK_SLOT }),
    publicClient.getStorageAt({ address: safe, slot: toHex(0n, { size: 32 }) }),
    publicClient.readContract({ address: expectedGuard, abi: bunkerGuardAbi, functionName: "state", args: [safe] }),
    publicClient.readContract({ address: expectedGuard, abi: bunkerGuardAbi, functionName: "multiSendCallOnly" }),
    publicClient.readContract({ address: expectedGuard, abi: bunkerGuardAbi, functionName: "multiSendCodeHash" }),
  ]);
  if (owners.length !== 1 || owners[0]?.toLowerCase() !== expectedOwner.toLowerCase() || threshold !== 1n) throw new Error("Safe owner verification failed.");
  if (modules[0].length !== 0 || modules[1].toLowerCase() !== SENTINEL.toLowerCase()) throw new Error("Safe module verification failed.");
  if (storageAddress(guardSlot).toLowerCase() !== expectedGuard.toLowerCase() || storageAddress(fallbackSlot) !== ZERO || storageAddress(singletonSlot).toLowerCase() !== SAFE_SINGLETON.toLowerCase()) throw new Error("Safe storage verification failed.");
  if (multiSend.toLowerCase() !== MULTISEND_CALL_ONLY.toLowerCase() || multiSendHash !== MULTISEND_CODE_HASH) throw new Error("Guard policy verification failed.");
  if (!guardState[2] || guardState[1] !== ownerIndex || guardState[3]) throw new Error("Guard state verification failed.");
}

async function reconcilePending(safe: Address) {
  if (!pendingPrivateKey) return;
  const owners = await publicClient.readContract({ address: safe, abi: safeAbi, functionName: "getOwners" });
  const pendingOwner = privateKeyToAccount(pendingPrivateKey).address;
  if (owners.length === 1 && owners[0]?.toLowerCase() === pendingOwner.toLowerCase()) { privateKey = pendingPrivateKey; sponsorPrivateKey = pendingPrivateKey; ownerIndex++; pendingPrivateKey = undefined; }
}

const packedCall = (to: Address, value: bigint, data: Hex = "0x") => concatHex([
  "0x00",
  to,
  padHex(toHex(value), { size: 32 }),
  padHex(toHex(BigInt((data.length - 2) / 2)), { size: 32 }),
  data,
]);

async function rotatedWrite(safe: Address, to: Address, amount: bigint): Promise<Hex> {
  if (!guardAddress) throw new Error("The Safe guard address is unavailable. Restore or restart setup.");
  await reconcilePending(safe);
  if (pendingPrivateKey) throw new Error("The previous owner rotation is still pending. Wait for confirmation before sending again.");
  const current = ownerAccount();
  const next = sequence()[ownerIndex];
  if (!next) throw new Error("The fixed owner sequence is exhausted.");
  const nextOwner = privateKeyToAccount(next).address;
  const swapData = encodeFunctionData({ abi: safeAbi, functionName: "swapOwner", args: [SENTINEL, current.address, nextOwner] });
  const batch = concatHex([packedCall(to, amount), packedCall(nextOwner, parseEther("0.001")), packedCall(safe, 0n, swapData)]);
  const data = encodeFunctionData({ abi: multiSendAbi, functionName: "multiSend", args: [batch] });
  const nonce = await publicClient.readContract({ address: safe, abi: safeAbi, functionName: "nonce" });
  const tx = { to: MULTISEND_CALL_ONLY, value: 0n, data, operation: 1, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n, gasToken: ZERO, refundReceiver: ZERO, nonce } as const;
  const safeTxHash = hashTypedData({ domain: { chainId: SEPOLIA_CHAIN_ID, verifyingContract: safe }, types: safeTxTypes, primaryType: "SafeTx", message: tx });
  const rpcHash = await publicClient.readContract({ address: safe, abi: safeAbi, functionName: "getTransactionHash", args: [tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, tx.nonce] });
  if (rpcHash !== safeTxHash) throw new Error("Safe transaction hash verification failed.");
  const signature = await current.sign({ hash: safeTxHash });
  const { client } = sponsorClient();
  pendingPrivateKey = next;
  const hash = await client.writeContract({ address: safe, abi: safeAbi, functionName: "execTransaction", args: [tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, signature] });
  try {
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") throw new Error("Ethereum Sepolia transaction reverted.");
    await reconcilePending(safe);
    await attestSafe(safe, privateKeyToAccount(privateKey!).address, guardAddress);
    return hash;
  } catch (error) {
    try { await reconcilePending(safe); } catch {}
    throw error;
  }
}

export function createEphemeralBurner(): Address {
  mnemonicSecret = undefined; ownerIndex = 0; privateKey = generatePrivateKey(); sponsorPrivateKey = privateKey;
  pendingPrivateKey = undefined; futurePrivateKeys = []; guardAddress = undefined;
  return privateKeyToAccount(privateKey).address;
}
export function loadMnemonicSigner(mnemonic: string, index = 0): Address {
  mnemonicSecret = mnemonic; ownerIndex = index; privateKey = mnemonicKey(mnemonic, index); sponsorPrivateKey = privateKey;
  pendingPrivateKey = undefined; futurePrivateKeys = [];
  return privateKeyToAccount(privateKey).address;
}
export function clearEphemeralBurner(): void {
  privateKey = undefined; sponsorPrivateKey = undefined; pendingPrivateKey = undefined; mnemonicSecret = undefined;
  futurePrivateKeys = []; guardAddress = undefined; ownerIndex = 0;
}
export function hasEphemeralBurner(): boolean { return privateKey !== undefined; }

export async function deploySafeWallet(onSafeCreated?: (safe: Address) => void): Promise<Address> {
  const current = ownerAccount();
  const { account, client } = sponsorClient();
  const startingBalance = await publicClient.getBalance({ address: account.address });
  if (startingBalance < parseEther("0.03")) throw new Error("Fund at least 0.03 Ethereum Sepolia ETH before creating the Safe.");
  await Promise.all([
    checkedCode(SAFE_SINGLETON, SAFE_CODE_HASH),
    checkedCode(SAFE_PROXY_FACTORY, FACTORY_CODE_HASH),
    checkedCode(MULTISEND_CALL_ONLY, MULTISEND_CODE_HASH),
  ]);
  const guard = await deploy(bunkerGuardAbi, bunkerGuardBytecode, [MULTISEND_CALL_ONLY, MULTISEND_CODE_HASH]);
  const helper = await deploy(bunkerSetupAbi, bunkerSetupBytecode);
  const owners = sequence().map(key => privateKeyToAccount(key).address) as [Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address, Address];
  const helperData = encodeFunctionData({ abi: bunkerSetupAbi, functionName: "setup", args: [guard, owners] });
  const initializer = encodeFunctionData({ abi: safeAbi, functionName: "setup", args: [[current.address], 1n, helper, helperData, ZERO, ZERO, 0n, ZERO] });
  const saltNonce = BigInt(generatePrivateKey());
  const factoryHash = await client.writeContract({ address: SAFE_PROXY_FACTORY, abi: factoryAbi, functionName: "createChainSpecificProxyWithNonce", args: [SAFE_SINGLETON, initializer, saltNonce] });
  const factoryReceipt = await publicClient.waitForTransactionReceipt({ hash: factoryHash });
  const event = parseEventLogs({ abi: factoryAbi, logs: factoryReceipt.logs, eventName: "ProxyCreation" })[0];
  if (factoryReceipt.status !== "success" || !event) throw new Error("Safe proxy deployment failed.");
  const safe = event.args.proxy;
  guardAddress = guard;
  await attestSafe(safe, current.address, guard);
  onSafeCreated?.(safe);
  const remaining = await publicClient.getBalance({ address: account.address });
  const reserve = parseEther("0.006");
  if (remaining <= reserve) throw new Error("Not enough Sepolia ETH remains to fund the Safe and broadcaster.");
  const fundingHash = await client.sendTransaction({ to: safe, value: remaining - reserve });
  const fundingReceipt = await publicClient.waitForTransactionReceipt({ hash: fundingHash });
  if (fundingReceipt.status !== "success") throw new Error("Safe funding failed.");
  return safe;
}

export async function readSafeWallet(safe: Address) {
  const [balance, owners, guardSlot] = await Promise.all([
    publicClient.getBalance({ address: safe }),
    publicClient.readContract({ address: safe, abi: safeAbi, functionName: "getOwners" }),
    publicClient.getStorageAt({ address: safe, slot: GUARD_SLOT }),
  ]);
  const discoveredGuard = storageAddress(guardSlot);
  if (owners.length !== 1 || discoveredGuard === ZERO) throw new Error("Safe verification failed.");
  const state = await publicClient.readContract({ address: discoveredGuard, abi: bunkerGuardAbi, functionName: "state", args: [safe] });
  ownerIndex = Number(state[1]);
  guardAddress = discoveredGuard;
  await attestSafe(safe, owners[0]!, discoveredGuard);
  const committed = await publicClient.readContract({ address: discoveredGuard, abi: bunkerGuardAbi, functionName: "committedOwner", args: [safe, BigInt(ownerIndex)] });
  if (ownerIndex < 19 && committed === ZERO) throw new Error("Guard sequence verification failed.");
  return { balance, owner: owners[0]!, index: ownerIndex };
}
export async function verifyRecoverySequence(safe: Address): Promise<void> {
  if (!guardAddress || !mnemonicSecret) throw new Error("Recovery sequence is unavailable.");
  const keys = sequence();
  const indexes = Array.from({ length: 20 - ownerIndex }, (_, offset) => ownerIndex + offset);
  const committed = await Promise.all(indexes.map(index => publicClient.readContract({ address: guardAddress!, abi: bunkerGuardAbi, functionName: "committedOwner", args: [safe, BigInt(index)] })));
  if (committed.some((address, offset) => address.toLowerCase() !== privateKeyToAccount(keys[indexes[offset]!]!).address.toLowerCase())) throw new Error("This recovery phrase does not match the Safe signer sequence.");
}
export const demoSendETH = (safe: Address, to: Address, amount: bigint) => rotatedWrite(safe, to, amount);

export async function readSepoliaBalance(address: Address): Promise<bigint> {
  const response = await fetch(SEPOLIA_RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBalance", params: [address, "latest"] }), signal: AbortSignal.timeout(8_000) });
  if (!response.ok) throw new Error("Ethereum Sepolia RPC is unavailable.");
  const text = await response.text();
  if (text.length > 4_096) throw new Error("Ethereum Sepolia returned an oversized response.");
  const body = JSON.parse(text) as { result?: string; error?: unknown };
  if (body.error || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(body.result ?? "")) throw new Error("Ethereum Sepolia returned an invalid balance.");
  const balance = BigInt(body.result!);
  if (balance >= 1n << 256n) throw new Error("Ethereum Sepolia returned an invalid balance.");
  return balance;
}
