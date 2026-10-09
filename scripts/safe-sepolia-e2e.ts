import { chmod } from "node:fs/promises";
import { createPublicClient, formatEther, http, parseEther } from "viem";
import { mnemonicToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import { validMnemonic } from "../packages/vault/src";
import {
  clearEphemeralBurner,
  demoSendETH,
  deploySafeWallet,
  loadMnemonicSigner,
  readSafeWallet,
  readSepoliaBalance,
  SEPOLIA_RPC,
  verifyRecoverySequence,
} from "../apps/web/src/burner";

const fail = (message: string): never => { throw new Error(message); };

async function main() {
  if (process.env.BUNKER_E2E_LIVE !== "1") fail("Live E2E is disabled.");
  if (process.env.BUNKER_SEPOLIA_CHAIN_ID !== "11155111") fail("Wrong configured chain.");
  const mnemonic = process.env.BUNKER_SEPOLIA_MNEMONIC;
  const expectedSetup = process.env.BUNKER_SEPOLIA_SETUP_ADDRESS;
  const maxBalance = process.env.BUNKER_SEPOLIA_MAX_BALANCE_ETH;
  const manifestPath = process.env.BUNKER_SEPOLIA_MANIFEST;
  if (!mnemonic || !validMnemonic(mnemonic) || !expectedSetup || !maxBalance || !manifestPath) throw new Error("Live E2E secrets are incomplete.");

  const client = createPublicClient({ chain: sepolia, transport: http(SEPOLIA_RPC) });
  if (await client.getChainId() !== sepolia.id) fail("RPC is not Ethereum Sepolia.");
  const setup = loadMnemonicSigner(mnemonic, 0);
  if (setup.toLowerCase() !== expectedSetup.toLowerCase()) fail("Setup derivation mismatch.");
  const balance = await readSepoliaBalance(setup);
  if (balance < parseEther("0.03") || balance > parseEther(maxBalance)) fail("Setup balance is outside the approved range.");

  const recipient = mnemonicToAccount(mnemonic, { path: "m/44'/60'/7331'/0/100" }).address;
  const recipientBefore = await readSepoliaBalance(recipient);
  const safe = await deploySafeWallet();
  const before = await readSafeWallet(safe);
  if (before.index !== 0 || before.owner.toLowerCase() !== setup.toLowerCase()) fail("Initial Safe state mismatch.");

  await demoSendETH(safe, recipient, parseEther("0.0001"));
  const after = await readSafeWallet(safe);
  if (after.index !== 1 || after.owner.toLowerCase() !== mnemonicToAccount(mnemonic, { path: "m/44'/60'/7331'/0/1" }).address.toLowerCase()) fail("Owner rotation mismatch.");
  if (await readSepoliaBalance(recipient) !== recipientBefore + parseEther("0.0001")) fail("Recipient balance mismatch.");

  clearEphemeralBurner();
  const recovered = loadMnemonicSigner(mnemonic, after.index);
  if (recovered.toLowerCase() !== after.owner.toLowerCase()) fail("Recovery owner mismatch.");
  await readSafeWallet(safe);
  await verifyRecoverySequence(safe);

  await Bun.write(manifestPath, JSON.stringify({
    schema: 1,
    network: "ethereum-sepolia",
    chainId: sepolia.id,
    completedAt: new Date().toISOString(),
    result: "pass",
    safe,
    rotationIndex: after.index,
    sentEth: formatEther(parseEther("0.0001")),
    checks: ["official-components", "atomic-setup", "safe-attestation", "eth-send", "next-owner-funding", "owner-rotation", "recipient-delta", "phrase-recovery", "sequence-verification"],
  }, null, 2) + "\n");
  await chmod(manifestPath, 0o600);
  clearEphemeralBurner();
  console.log("Funded Ethereum Sepolia Safe E2E passed.");
}

main().catch(() => {
  clearEphemeralBurner();
  console.error("Funded Ethereum Sepolia Safe E2E failed.");
  process.exit(1);
});
