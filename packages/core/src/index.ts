import { isAddress, type Address } from "viem";
export const GUARD_VERSION = 2;
export const SUPPORTED_CHAIN_IDS = [31337, 11155111] as const;
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;
export class SecurityPolicyError extends Error { override name = "SecurityPolicyError"; }
export function assertSupportedChain(chainId: number): asserts chainId is 31337 | 11155111 {
  if (!SUPPORTED_CHAIN_IDS.includes(chainId as 31337 | 11155111)) throw new SecurityPolicyError("Only local Anvil and Ethereum Sepolia are enabled. Mainnet is locked.");
}
// nextIndex is a display counter, never a derivation index or owner commitment.
export type TransferIntent = { chainId: number; safe: Address; recipient: Address; value: bigint; nonce: bigint; currentOwner: Address; nextOwner: Address; nextIndex: number };
export function validateTransferIntent(intent: TransferIntent): TransferIntent {
  assertSupportedChain(intent.chainId);
  for (const [label, value] of [["Safe", intent.safe], ["recipient", intent.recipient], ["current owner", intent.currentOwner], ["next owner", intent.nextOwner]] as const) if (!isAddress(value, { strict: true }) || value === ZERO_ADDRESS) throw new SecurityPolicyError(`${label} is invalid.`);
  if (intent.value <= 0n || intent.value > 10n ** 22n) throw new SecurityPolicyError("Transfer value must be positive and at most 10,000 ETH.");
  if (intent.nonce < 0n || intent.nonce >= 2n ** 256n) throw new SecurityPolicyError("Invalid nonce.");
  if (!Number.isSafeInteger(intent.nextIndex) || intent.nextIndex < 0) throw new SecurityPolicyError("Invalid rotation counter.");
  if (intent.currentOwner.toLowerCase() === intent.nextOwner.toLowerCase() || intent.nextOwner.toLowerCase() === intent.safe.toLowerCase() || BigInt(intent.nextOwner) === 1n) throw new SecurityPolicyError("Rotation must advance to a fresh EOA.");
  if (intent.recipient.toLowerCase() === intent.safe.toLowerCase()) throw new SecurityPolicyError("Recipient cannot be the Safe.");
  return intent;
}
