import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { Address, Hex } from "viem";

export const SEPOLIA_CHAIN_ID = 11155111;
export const SEPOLIA_RPC = "https://rpc.sepolia.org";
export const SEPOLIA_FAUCET = "https://cloud.google.com/application/web3/faucet/ethereum/sepolia";
let privateKey: Hex | undefined;

export function createEphemeralBurner(): Address {
  privateKey = generatePrivateKey();
  return privateKeyToAccount(privateKey).address;
}
export function clearEphemeralBurner(): void { privateKey = undefined; }
export function hasEphemeralBurner(): boolean { return privateKey !== undefined; }
export async function readSepoliaBalance(address: Address): Promise<bigint> {
  const response = await fetch(SEPOLIA_RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBalance", params: [address, "latest"] }), signal: AbortSignal.timeout(8_000) });
  if (!response.ok) throw new Error("Sepolia RPC is unavailable.");
  const text = await response.text();
  if (text.length > 4_096) throw new Error("Sepolia returned an oversized response.");
  const body = JSON.parse(text) as { result?: string; error?: unknown };
  if (body.error || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(body.result ?? "")) throw new Error("Sepolia returned an invalid balance.");
  const balance = BigInt(body.result!);
  if (balance >= 1n << 256n) throw new Error("Sepolia returned an invalid balance.");
  return balance;
}
