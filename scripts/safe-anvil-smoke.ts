import { parseEther } from "viem";
import { createBurnerSession, SEPOLIA_RPC } from "../apps/web/src/burner";
import official from "../tests/fixtures/sepolia-safe-1.4.1.json";
const { recoverSigner, selectNextSigner, clearEphemeralBurner, demoSendETH, deploySafeWallet, loadMnemonicSigner, readSafeWallet, verifyRecoverySequence } = createBurnerSession();

if (!SEPOLIA_RPC.includes("127.0.0.1") && !SEPOLIA_RPC.includes("localhost")) throw new Error("This smoke test must run against local Anvil.");
const rpc = async (method: string, params: unknown[]) => {
  const response = await fetch(SEPOLIA_RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const body = await response.json() as { result?: unknown; error?: unknown };
  if (body.error) throw new Error(`${method} failed`);
  return body.result;
};

if (await rpc("eth_chainId", []) !== "0xaa36a7") throw new Error("Expected disposable Sepolia-chain Anvil.");
for (const code of Object.values(official.codes)) await rpc("anvil_setCode", [code.address, code.runtime]);

const mnemonic = `${"abandon ".repeat(23)}art`;
const setup = loadMnemonicSigner(mnemonic);
await rpc("anvil_setBalance", [setup, `0x${parseEther("100").toString(16)}`]);
const safe = await deploySafeWallet();
clearEphemeralBurner();
const discovered = await readSafeWallet(safe);
recoverSigner(mnemonic, discovered.owner);
await verifyRecoverySequence(safe);
const before = await readSafeWallet(safe);
const recipient = "0x000000000000000000000000000000000000beef";
const recipientBefore = BigInt(await rpc("eth_getBalance", [recipient, "latest"]) as string);
await demoSendETH(safe, recipient, parseEther("0.01"));
const after = await readSafeWallet(safe);
const recipientAfter = BigInt(await rpc("eth_getBalance", [recipient, "latest"]) as string);
if (before.index !== 0 || after.index !== 1) throw new Error("Safe owner index did not advance.");
if (before.owner.toLowerCase() === after.owner.toLowerCase()) throw new Error("Safe owner did not rotate.");
if (recipientAfter - recipientBefore !== parseEther("0.01")) throw new Error("Recipient did not receive exact ETH amount.");
if (before.balance - after.balance !== parseEther("0.011")) throw new Error("Safe did not fund the recipient and next owner exactly.");
// Race two submissions in one session: only one preparation can proceed.
const race = await Promise.allSettled([demoSendETH(safe, recipient, parseEther("0.001")), demoSendETH(safe, recipient, parseEther("0.001"))]);
if (race.filter(x=>x.status === "fulfilled").length !== 1) throw new Error("Concurrent browser rotation was not serialized.");
for (let i = 2; i < 25; i++) await demoSendETH(safe, recipient, parseEther("0.001"));
if ((await readSafeWallet(safe)).index !== 25) throw new Error("25 rotations failed.");
// Intentional non-sequential selection; recover with no local state.
selectNextSigner(147);
await demoSendETH(safe, recipient, parseEther("0.001"));
clearEphemeralBurner();
const arbitrary = await readSafeWallet(safe);
if (recoverSigner(mnemonic, arbitrary.owner, 140, 20) !== 147) throw new Error("Lost-state recovery failed.");
await verifyRecoverySequence(safe);
// Switch seeds, then prove the new seed controls the next default rotation.
const secondMnemonic = `${"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"}`;
selectNextSigner(73, secondMnemonic);
await demoSendETH(safe, recipient, parseEther("0.001"));
clearEphemeralBurner();
const switched = await readSafeWallet(safe);
if (recoverSigner(secondMnemonic, switched.owner, 70, 10) !== 73) throw new Error("Seed-switch recovery failed.");
await demoSendETH(safe, recipient, parseEther("0.001"));
if ((await readSafeWallet(safe)).index !== 28) throw new Error("Post-recovery rotation failed.");
console.log("Safe Anvil smoke passed: 28 rotations, concurrent submission, arbitrary index and seed-switch recovery.");
