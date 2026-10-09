import { chmod } from "node:fs/promises";
import { isAddress, parseEther } from "viem";
import { mnemonicToAccount } from "viem/accounts";
import { validMnemonic } from "../packages/vault/src";
import { createBurnerSession, readSepoliaBalance } from "../apps/web/src/burner";
const { clearEphemeralBurner, demoSendETH, loadMnemonicSigner, readSafeWallet, verifyRecoverySequence } = createBurnerSession();

async function main() {
  if (process.env.BUNKER_E2E_LIVE !== "1" || process.env.BUNKER_SEPOLIA_CHAIN_ID !== "11155111") throw new Error("Live Sepolia funding is disabled.");
  const mnemonic = process.env.BUNKER_SEPOLIA_MNEMONIC;
  const recipient = process.env.BUNKER_BROWSER_SETUP_ADDRESS;
  const manifestPath = process.env.BUNKER_SEPOLIA_MANIFEST;
  if (!mnemonic || !validMnemonic(mnemonic) || !recipient || !isAddress(recipient) || !manifestPath) throw new Error("Funding inputs are invalid.");
  const manifest = await Bun.file(manifestPath).json() as { safe?: `0x${string}`; rotationIndex?: number; [key: string]: unknown };
  if (!manifest.safe || manifest.rotationIndex === undefined) throw new Error("Protected E2E manifest is incomplete.");

  loadMnemonicSigner(mnemonic, manifest.rotationIndex);
  const before = await readSafeWallet(manifest.safe);
  if (before.index !== manifest.rotationIndex) throw new Error("Sponsor Safe index mismatch.");
  await verifyRecoverySequence(manifest.safe);
  const nextOwner = mnemonicToAccount(mnemonic, { path: `m/44'/60'/7331'/0/${before.index + 1}` }).address;
  const [recipientBefore, nextOwnerBefore] = await Promise.all([readSepoliaBalance(recipient), readSepoliaBalance(nextOwner)]);
  const amount = parseEther("0.035");
  await demoSendETH(manifest.safe, recipient, amount);
  const after = await readSafeWallet(manifest.safe);
  const [recipientAfter, nextOwnerAfter] = await Promise.all([readSepoliaBalance(recipient), readSepoliaBalance(nextOwner)]);
  if (after.index !== before.index + 1 || after.owner.toLowerCase() !== nextOwner.toLowerCase()) throw new Error("Sponsor owner rotation mismatch.");
  if (before.balance - after.balance !== amount + parseEther("0.001")) throw new Error("Sponsor Safe balance delta mismatch.");
  if (recipientAfter - recipientBefore !== amount) throw new Error("Browser setup funding mismatch.");
  if (nextOwnerAfter - nextOwnerBefore !== parseEther("0.001")) throw new Error("Sponsor next-owner funding mismatch.");

  await Bun.write(manifestPath, JSON.stringify({ ...manifest, rotationIndex: after.index, browserFundingCompletedAt: new Date().toISOString(), browserFundingEth: "0.035" }, null, 2) + "\n");
  await chmod(manifestPath, 0o600);
  clearEphemeralBurner();
  console.log("Browser E2E setup funding passed.");
}

main().catch(() => {
  clearEphemeralBurner();
  console.error("Browser E2E setup funding failed.");
  process.exit(1);
});
