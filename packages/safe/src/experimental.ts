export { encodeHybridSignatures, c10KeyId } from "./hybrid";
import { concatHex, encodeAbiParameters, isAddress, keccak256, padHex, size, sliceHex, stringToHex, toHex, type Address, type Hex } from "viem";

// Separately versioned experimental trusted-client Sepolia protocol.
const DOMAIN = keccak256(stringToHex("BUNKER_EXPERIMENTAL_PQ_V1"));
const SAFE_DOMAIN = keccak256(stringToHex("EIP712Domain(uint256 chainId,address verifyingContract)"));
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
function hex(value: Hex, length: number) {
  if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(value) || size(value) !== length) throw new Error(`Expected ${length} bytes`);
}
function address(value: Address) {
  if (!isAddress(value, { strict: true }) || BigInt(value) <= 1n) throw new Error("Invalid hybrid address");
}
function uint(value: bigint) {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << 256n) throw new Error("Invalid uint256");
}
function signatureLength(algorithm: 1 | 2) {
  if (algorithm !== 1 && algorithm !== 2) throw new Error("Unsupported algorithm");
  return algorithm === 1 ? 4008 : 2420;
}
function c10KeyId(seed: Hex, root: Hex): Hex {
  for (const key of [seed, root]) {
    hex(key, 32);
    if (BigInt(key) === 0n || BigInt(key) % (1n << 128n) !== 0n) throw new Error("C10 keys must be left-aligned 16-byte values");
  }
  return keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }], [seed, root]));
}
export type HybridMessage = {
  chainId: 11155111; safe: Address; preimage: Hex; algorithm: 1 | 2; version: 1;
  adapter: Address; keyId: Hex; verifier: Address; verifierCodeHash: Hex; epoch: bigint;
};
/** keccak256(abi.encode(domain,chainId,safe,keccak256(preimage),algorithm,version,adapter,keyId,verifier,verifierCodeHash,epoch)). */
export function hybridMessageDigest(input: HybridMessage): Hex {
  const { chainId, safe, preimage, algorithm, version, adapter, keyId, verifier, verifierCodeHash, epoch } = input;
  if (chainId !== 11155111 || version !== 1) throw new Error("Experimental Sepolia version only");
  signatureLength(algorithm); address(safe); address(adapter); address(verifier); uint(epoch);
  hex(preimage, 66); hex(keyId, 32); hex(verifierCodeHash, 32);
  if (BigInt(keyId) === 0n || BigInt(verifierCodeHash) === 0n) throw new Error("Missing identity");
  const domain = keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "uint256" }, { type: "address" }], [SAFE_DOMAIN, BigInt(chainId), safe]));
  if (sliceHex(preimage, 0, 2) !== "0x1901" || sliceHex(preimage, 2, 34).toLowerCase() !== domain) throw new Error("Wrong Safe domain");
  return keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "bytes32" }, { type: "uint256" }, { type: "uint256" }, { type: "address" }, { type: "bytes32" }, { type: "address" }, { type: "bytes32" }, { type: "uint256" }],
    [DOMAIN, BigInt(chainId), safe, keccak256(preimage), BigInt(algorithm), BigInt(version), adapter, keyId, verifier, verifierCodeHash, epoch],
  ));
}
