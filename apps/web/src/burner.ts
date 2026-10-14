import {
  concatHex,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  http,
  hashTypedData,
  isAddress,
  keccak256,
  padHex,
  parseEther,
  parseEventLogs,
  toHex,
  type Address,
  type Hex,
} from "viem";
import { generatePrivateKey, mnemonicToAccount, privateKeyToAccount } from "viem/accounts";
import { mainnet, sepolia } from "viem/chains";
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

const publicClient = createPublicClient({ chain: sepolia, transport: http(SEPOLIA_RPC) });
type EnsResolver = (name: string) => Promise<Address | null>;
const ensResolvers: EnsResolver[] = ["https://ethereum-rpc.publicnode.com", "https://cloudflare-eth.com"].map(url => {
  const client = createPublicClient({ chain: mainnet, transport: http(url) });
  return name => client.getEnsAddress({ name });
});
export async function resolveRecipient(value: string, resolvers: EnsResolver[] = ensResolvers): Promise<Address> {
  const recipient=value.trim();
  if(isAddress(recipient))return recipient;
  if(!/^[a-z0-9-]+\.eth$/i.test(recipient))throw new Error("Enter a valid Ethereum address or .eth name.");
  for (const resolve of resolvers) {
    try { const address = await resolve(recipient.toLowerCase()); if (address) return address; } catch {}
  }
  throw new Error("Couldn’t resolve this .eth name. Retry or paste the recipient’s 0x address.");
}
const mnemonicKey = (mnemonic: string, index: number) => {
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** 31) throw new Error("Invalid derivation index.");
  const key = mnemonicToAccount(mnemonic, { path: `m/44'/60'/7331'/0/${index}` }).getHdKey().privateKey;
  if (!key) throw new Error("Recovery key could not be derived.");
  return toHex(key);
};
export const deriveLocalPreviewWalletAddress = (mnemonic: string): Address =>
  mnemonicToAccount(mnemonic, { path: "m/44'/60'/7331'/1'/0'" }).address;
export const deriveLocalPreviewOwnerAddress = (mnemonic: string, index: number): Address =>
  mnemonicToAccount(mnemonic, { path: `m/44'/60'/7331'/2'/${index}'` }).address;
export function createBurnerSession() {
let privateKey: Hex | undefined;
let sponsorPrivateKey: Hex | undefined;
let mnemonicSecret: string | undefined;
let pendingPrivateKey: Hex | undefined;
let selected: {key: Hex; index: number; mnemonic: string | undefined} | undefined;
let pendingSelection: typeof selected;
let pendingHash: Hex | undefined;
let pendingIntent: {safe: Address; to: Address; amount: bigint} | undefined;
let writing = false;
let ownerIndex = 0;
let guardAddress: Address | undefined;
const ownerAccount = () => { if (!privateKey) throw new Error("Create or load a testnet key first."); return privateKeyToAccount(privateKey); };
const sponsorClient = () => {
  if (!sponsorPrivateKey) throw new Error("The Sepolia broadcaster key is unavailable. Restore or restart setup.");
  const account = privateKeyToAccount(sponsorPrivateKey);
  return { account, client: createWalletClient({ account, chain: sepolia, transport: http(SEPOLIA_RPC) }) };
};
const checkedCode = async (address: Address, expected: Hex) => {
  const code = await publicClient.getCode({ address });
  if (!code) throw new Error("Safe deployment is not visible yet.");
  if (keccak256(code) !== expected) throw new Error("Safe deployment verification failed.");
};
const transientRead = (error: unknown) => error instanceof Error && (error.message.includes("returned no data") || error.message.includes("not visible yet"));
const waitForSafeReady = async (safe: Address, owner: Address, guard: Address) => {
  for (let attempt = 0; attempt < 8; attempt++) {
    try { await attestSafe(safe, owner, guard); return; }
    catch (error) { if (!transientRead(error) || attempt === 7) throw error; await new Promise(resolve => setTimeout(resolve, 2_000)); }
  }
};
const deploy = async (abi: readonly unknown[], bytecode: Hex, args: readonly unknown[] = []) => {
  const { client } = sponsorClient();
  const hash = await client.deployContract({ abi, bytecode, args, gas: 10_000_000n } as never);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success" || !receipt.contractAddress) throw new Error("Safe component deployment failed.");
  return receipt.contractAddress;
};
function selectNextSigner(index = ownerIndex + 1, mnemonic = mnemonicSecret): Address {
  if (writing || pendingPrivateKey) throw new Error("A rotation is pending.");
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** 31) throw new Error("Invalid derivation index.");
  selected = {key: mnemonic ? mnemonicKey(mnemonic, index) : generatePrivateKey(), index, mnemonic};
  return privateKeyToAccount(selected.key).address;
}
function recoverSigner(mnemonic: string, owner: Address, start = 0, count = 100): number {
  if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(count) || count < 1 || count > 1000 || start + count > 2 ** 31) throw new Error("Invalid recovery range (maximum 1000 keys).");
  for (let i = start; i < start + count; i++) {
    if (privateKeyToAccount(mnemonicKey(mnemonic, i)).address.toLowerCase() === owner.toLowerCase()) {
      loadMnemonicSigner(mnemonic, i); return i;
    }
  }
  throw new Error("Current owner not found in this recovery range. Check the phrase and index range; a switched seed requires its own backup.");
}
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
  if (!guardState[2] || guardState[3]) throw new Error("Guard state verification failed.");
}

async function reconcilePending(safe: Address) {
  if (!pendingPrivateKey) return;
  if (!pendingIntent || pendingIntent.safe.toLowerCase() !== safe.toLowerCase()) throw new Error("Pending transfer belongs to a different Safe.");
  if (!pendingHash) throw new Error("Broadcast status is uncertain. Recover using the on-chain owner before retrying.");
  const receipt = await publicClient.getTransactionReceipt({ hash: pendingHash });
  if (receipt.status !== "success") {
    pendingPrivateKey = undefined; pendingHash = undefined; pendingSelection = undefined; pendingIntent = undefined;
    throw new Error("Ethereum Sepolia transaction reverted. Active signer unchanged.");
  }
  const owners = await publicClient.readContract({ address: safe, abi: safeAbi, functionName: "getOwners" });
  const pendingOwner = privateKeyToAccount(pendingPrivateKey).address;
  if (owners.length !== 1 || owners[0]?.toLowerCase() !== pendingOwner.toLowerCase()) throw new Error("Chain owner has moved. Recover the current signer before sending.");
  if (!guardAddress) throw new Error("The Safe guard address is unavailable.");
  await attestSafe(safe, pendingOwner, guardAddress);
  const result = {...pendingIntent, hash: pendingHash};
  privateKey = pendingPrivateKey; sponsorPrivateKey = pendingPrivateKey;
  ownerIndex = pendingSelection!.index; mnemonicSecret = pendingSelection!.mnemonic;
  selected = undefined; pendingPrivateKey = undefined; pendingHash = undefined; pendingSelection = undefined; pendingIntent = undefined;
  return result;
}

const packedCall = (to: Address, value: bigint, data: Hex = "0x") => concatHex([
  "0x00",
  to,
  padHex(toHex(value), { size: 32 }),
  padHex(toHex(BigInt((data.length - 2) / 2)), { size: 32 }),
  data,
]);

async function rotatedWrite(safe: Address, to: Address, amount: bigint) {
  if (writing) throw new Error("A rotation is already being prepared.");
  writing = true;
  try {
  if (!guardAddress) throw new Error("The Safe guard address is unavailable. Restore or restart setup.");
  if (pendingPrivateKey) {
    // Return the original intent, never the new form values or a second send.
    return (await reconcilePending(safe))!;
  }
  const current = ownerAccount();
  selected ??= {key: mnemonicSecret ? mnemonicKey(mnemonicSecret, ownerIndex + 1) : generatePrivateKey(), index: ownerIndex + 1, mnemonic: mnemonicSecret};
  const next = selected.key;
  const nextOwner = privateKeyToAccount(next).address;
  await attestSafe(safe, current.address, guardAddress);
  if (amount <= 0n || !isAddress(to) || to === ZERO || to.toLowerCase() === safe.toLowerCase()) throw new Error("Invalid ETH transfer.");
  if (await publicClient.readContract({address: guardAddress, abi: bunkerGuardAbi, functionName: "consumed", args: [safe, nextOwner]})) throw new Error("Next signer was already consumed. Select a fresh index or seed.");
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
  pendingPrivateKey = next; pendingSelection = selected; pendingIntent = {safe, to, amount};
  const hash = await client.writeContract({ address: safe, abi: safeAbi, functionName: "execTransaction", args: [tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, signature] });
  pendingHash = hash;
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") { pendingPrivateKey = undefined; pendingHash = undefined; pendingSelection = undefined; pendingIntent = undefined; throw new Error("Ethereum Sepolia transaction reverted."); }
  return (await reconcilePending(safe))!;
  } finally { writing = false; }
}

function createEphemeralBurner(): Address {
  mnemonicSecret = undefined; ownerIndex = 0; privateKey = generatePrivateKey(); sponsorPrivateKey = privateKey;
  pendingPrivateKey = undefined; selected = undefined; pendingHash = undefined; pendingSelection = undefined; pendingIntent = undefined; guardAddress = undefined;
  return privateKeyToAccount(privateKey).address;
}
function loadMnemonicSigner(mnemonic: string, index = 0): Address {
  if (writing) throw new Error("A rotation is in progress.");
  mnemonicSecret = mnemonic; ownerIndex = index; privateKey = mnemonicKey(mnemonic, index); sponsorPrivateKey = privateKey;
  pendingPrivateKey = undefined; selected = undefined; pendingHash = undefined; pendingSelection = undefined; pendingIntent = undefined;
  return privateKeyToAccount(privateKey).address;
}
function clearEphemeralBurner(): void {
  privateKey = undefined; sponsorPrivateKey = undefined; pendingPrivateKey = undefined; mnemonicSecret = undefined;
  selected = undefined; pendingHash = undefined; pendingSelection = undefined; pendingIntent = undefined; guardAddress = undefined; ownerIndex = 0;
}
function hasEphemeralBurner(): boolean { return privateKey !== undefined; }

async function finalizeSafeWallet(safe: Address): Promise<Address> {
  const current = ownerAccount();
  const state = await readSafeWallet(safe);
  if (state.owner.toLowerCase() !== current.address.toLowerCase()) throw new Error("The saved Safe is not controlled by this recovery key.");
  if (state.balance > 0n) return safe;
  const { account, client } = sponsorClient();
  const [latestNonce, pendingNonce, remaining] = await Promise.all([
    publicClient.getTransactionCount({ address: account.address, blockTag: "latest" }),
    publicClient.getTransactionCount({ address: account.address, blockTag: "pending" }),
    publicClient.getBalance({ address: account.address }),
  ]);
  if (pendingNonce > latestNonce) throw new Error("Safe funding is still confirming.");
  const reserve = parseEther("0.006");
  if (remaining <= reserve) throw new Error("Not enough Sepolia ETH remains to fund the Safe and broadcaster.");
  const fundingHash = await client.sendTransaction({ to: safe, value: remaining - reserve });
  const fundingReceipt = await publicClient.waitForTransactionReceipt({ hash: fundingHash });
  if (fundingReceipt.status !== "success") throw new Error("Safe funding failed.");
  return safe;
}

async function deploySafeWallet(onSafeCreated?: (safe: Address, transactionHash: Hex) => void): Promise<Address> {
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
  const helperData = encodeFunctionData({ abi: bunkerSetupAbi, functionName: "setup", args: [guard] });
  const initializer = encodeFunctionData({ abi: safeAbi, functionName: "setup", args: [[current.address], 1n, helper, helperData, ZERO, ZERO, 0n, ZERO] });
  const saltNonce = BigInt(generatePrivateKey());
  const factoryHash = await client.writeContract({ address: SAFE_PROXY_FACTORY, abi: factoryAbi, functionName: "createChainSpecificProxyWithNonce", args: [SAFE_SINGLETON, initializer, saltNonce] });
  const factoryReceipt = await publicClient.waitForTransactionReceipt({ hash: factoryHash });
  const event = parseEventLogs({ abi: factoryAbi, logs: factoryReceipt.logs, eventName: "ProxyCreation" })[0];
  if (factoryReceipt.status !== "success" || !event) throw new Error("Safe proxy deployment failed.");
  const safe = event.args.proxy;
  guardAddress = guard;
  onSafeCreated?.(safe, factoryHash);
  await waitForSafeReady(safe, current.address, guard);
  return finalizeSafeWallet(safe);
}

async function readSafeWalletOnce(safe: Address) {
  const [balance, owners, guardSlot] = await Promise.all([
    publicClient.getBalance({ address: safe }),
    publicClient.readContract({ address: safe, abi: safeAbi, functionName: "getOwners" }),
    publicClient.getStorageAt({ address: safe, slot: GUARD_SLOT }),
  ]);
  const discoveredGuard = storageAddress(guardSlot);
  if (owners.length !== 1 || discoveredGuard === ZERO) throw new Error("Safe verification failed.");
  const state = await publicClient.readContract({ address: discoveredGuard, abi: bunkerGuardAbi, functionName: "state", args: [safe] });
  const rotationCount = Number(state[1]);
  if (!Number.isSafeInteger(rotationCount)) throw new Error("Rotation counter exceeds browser display range.");
  guardAddress = discoveredGuard;
  await attestSafe(safe, owners[0]!, discoveredGuard);
  if (!await publicClient.readContract({ address: discoveredGuard, abi: bunkerGuardAbi, functionName: "consumed", args: [safe, owners[0]!] })) throw new Error("Guard history verification failed.");
  return { balance, owner: owners[0]!, index: rotationCount };
}
async function readSafeWallet(safe: Address) {
  for (let attempt = 0; attempt < 8; attempt++) {
    try { return await readSafeWalletOnce(safe); }
    catch (error) { if (!transientRead(error) || attempt === 7) throw error; await new Promise(resolve => setTimeout(resolve, 2_000)); }
  }
  throw new Error("Safe deployment is still confirming.");
}
async function verifyRecoverySequence(safe: Address): Promise<void> {
  if (!guardAddress || !mnemonicSecret) throw new Error("Recovery signer is unavailable.");
  await attestSafe(safe, ownerAccount().address, guardAddress);
}
const demoSendETH = (safe: Address, to: Address, amount: bigint) => rotatedWrite(safe, to, amount);

const reconcilePendingTransfer = (safe: Address) => pendingIntent
  ? rotatedWrite(safe, pendingIntent.to, pendingIntent.amount)
  : Promise.resolve(undefined);

return { reconcilePendingTransfer, getActiveMnemonic: () => mnemonicSecret, selectNextSigner, recoverSigner, clearEphemeralBurner, createEphemeralBurner, demoSendETH, deploySafeWallet, finalizeSafeWallet, hasEphemeralBurner, loadMnemonicSigner, readSafeWallet, verifyRecoverySequence };
}

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
