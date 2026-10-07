import { concatHex, encodePacked, getAddress, isAddress, keccak256, stringToHex, type Address, type Hex } from "viem";

export const BATCH_SIZE = 20;
export const RESERVED_ROTATIONS = 1;
export const SUPPORTED_CHAIN_IDS = [31337, 11155111] as const;
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;
const DOMAIN = keccak256(stringToHex("BUNKER_OWNER_V1"));
const EMPTY = keccak256("0x02");

export class SecurityPolicyError extends Error { override name = "SecurityPolicyError"; }
export type SequenceContext = { chainId: number; safe: Address; version: number };
export type MerkleProof = { index: number; siblings: Hex[] };

export function assertSupportedChain(chainId: number): asserts chainId is 31337 | 11155111 {
  if (!SUPPORTED_CHAIN_IDS.includes(chainId as 31337 | 11155111)) throw new SecurityPolicyError("Only local Anvil and Sepolia are enabled. Mainnet is locked.");
}
export function normalizeAddresses(input: readonly string[]): Address[] {
  if (input.length !== BATCH_SIZE) throw new SecurityPolicyError(`Exactly ${BATCH_SIZE} future owners are required.`);
  const addresses = input.map((value) => {
    if (!isAddress(value, { strict: true })) throw new SecurityPolicyError("Owner sequence contains an invalid address.");
    return getAddress(value);
  });
  if (new Set(addresses.map((a) => a.toLowerCase())).size !== addresses.length) throw new SecurityPolicyError("Owner sequence contains a reused address.");
  if (addresses.includes(ZERO_ADDRESS)) throw new SecurityPolicyError("Zero address cannot own a Safe.");
  return addresses;
}
export function ownerLeaf(context: SequenceContext, index: number, owner: Address): Hex {
  assertSupportedChain(context.chainId);
  if (!Number.isSafeInteger(index) || index < 0 || index >= BATCH_SIZE) throw new SecurityPolicyError("Owner index is outside the fixed batch.");
  return keccak256(encodePacked(["bytes1", "bytes32", "uint256", "address", "uint32", "uint8", "address"], ["0x00", DOMAIN, BigInt(context.chainId), context.safe, context.version, index, owner]));
}
function parent(left: Hex, right: Hex): Hex { return keccak256(concatHex(["0x01", left, right])); }
function levels(context: SequenceContext, owners: readonly string[]): Hex[][] {
  const normalized = normalizeAddresses(owners);
  let row = normalized.map((owner, index) => ownerLeaf(context, index, owner));
  while (row.length < 32) row.push(EMPTY);
  const out = [row];
  while (row.length > 1) {
    const next: Hex[] = [];
    for (let i = 0; i < row.length; i += 2) next.push(parent(row[i]!, row[i + 1]!));
    out.push(next); row = next;
  }
  return out;
}
export function commitmentRoot(context: SequenceContext, owners: readonly string[]): Hex { return levels(context, owners).at(-1)![0]!; }
export function commitmentProof(context: SequenceContext, owners: readonly string[], index: number): MerkleProof {
  if (index < 0 || index >= BATCH_SIZE) throw new SecurityPolicyError("Proof index is outside the fixed batch.");
  const tree = levels(context, owners); let cursor = index; const siblings: Hex[] = [];
  for (let depth = 0; depth < tree.length - 1; depth++) { siblings.push(tree[depth]![cursor ^ 1]!); cursor >>= 1; }
  return { index, siblings };
}
export function verifyProof(root: Hex, leaf: Hex, proof: MerkleProof): boolean {
  if (proof.siblings.length !== 5 || proof.index < 0 || proof.index >= BATCH_SIZE) return false;
  let hash = leaf; let index = proof.index;
  for (const sibling of proof.siblings) { hash = index & 1 ? parent(sibling, hash) : parent(hash, sibling); index >>= 1; }
  return hash === root;
}
export function rotationsRemaining(nextIndex: number): number {
  if (!Number.isInteger(nextIndex) || nextIndex < 0 || nextIndex > BATCH_SIZE) throw new SecurityPolicyError("Invalid rotation index.");
  return Math.max(0, BATCH_SIZE - RESERVED_ROTATIONS - nextIndex);
}

export type TransferIntent = { chainId: number; safe: Address; recipient: Address; value: bigint; nonce: bigint; currentOwner: Address; nextOwner: Address; nextIndex: number };
export function validateTransferIntent(intent: TransferIntent): TransferIntent {
  assertSupportedChain(intent.chainId);
  for (const [label, value] of [["Safe", intent.safe], ["recipient", intent.recipient], ["current owner", intent.currentOwner], ["next owner", intent.nextOwner]] as const) if (!isAddress(value, { strict: true }) || value === ZERO_ADDRESS) throw new SecurityPolicyError(`${label} is invalid.`);
  if (intent.value <= 0n) throw new SecurityPolicyError("Transfer value must be positive.");
  if (intent.value > 10n ** 22n) throw new SecurityPolicyError("Alpha transfer exceeds the 10,000 ETH hard limit.");
  if (intent.nonce < 0n) throw new SecurityPolicyError("Nonce cannot be negative.");
  if (rotationsRemaining(intent.nextIndex) < 1) throw new SecurityPolicyError("The final rotation is reserved; this sequence cannot send again.");
  if (intent.currentOwner.toLowerCase() === intent.nextOwner.toLowerCase()) throw new SecurityPolicyError("Rotation must advance to a fresh owner.");
  return intent;
}
