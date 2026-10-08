import { parseEther } from "viem";
import { clearEphemeralBurner, demoSendETH, deploySafeWallet, loadMnemonicSigner, readSafeWallet, SEPOLIA_RPC, verifyRecoverySequence } from "../apps/web/src/burner";

if (!SEPOLIA_RPC.includes("127.0.0.1") && !SEPOLIA_RPC.includes("localhost")) throw new Error("This smoke test must run against local Anvil.");
const rpc = async (method: string, params: unknown[]) => {
  const response = await fetch(SEPOLIA_RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const body = await response.json() as { result?: unknown; error?: unknown };
  if (body.error) throw new Error(`${method} failed`);
  return body.result;
};

const mnemonic = `${"abandon ".repeat(23)}art`;
const setup = loadMnemonicSigner(mnemonic);
await rpc("anvil_setBalance", [setup, `0x${parseEther("100").toString(16)}`]);
const safe = await deploySafeWallet();
clearEphemeralBurner();
const discovered = await readSafeWallet(safe);
const recovered = loadMnemonicSigner(mnemonic, discovered.index);
if (recovered.toLowerCase() !== discovered.owner.toLowerCase()) throw new Error("Mnemonic did not recover the active Safe owner.");
await verifyRecoverySequence(safe);
const before = await readSafeWallet(safe);
const recipient = "0x000000000000000000000000000000000000BEEF";
const recipientBefore = BigInt(await rpc("eth_getBalance", [recipient, "latest"]) as string);
await demoSendETH(safe, recipient, parseEther("0.01"));
const after = await readSafeWallet(safe);
const recipientAfter = BigInt(await rpc("eth_getBalance", [recipient, "latest"]) as string);
if (before.index !== 0 || after.index !== 1) throw new Error("Safe owner index did not advance.");
if (before.owner.toLowerCase() === after.owner.toLowerCase()) throw new Error("Safe owner did not rotate.");
if (recipientAfter - recipientBefore !== parseEther("0.01")) throw new Error("Recipient did not receive exact ETH amount.");
if (before.balance - after.balance !== parseEther("0.011")) throw new Error("Safe did not fund the recipient and next owner exactly.");
console.log("Safe Anvil smoke passed.");
