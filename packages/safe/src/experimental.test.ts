import { expect, test } from 'bun:test';
import {
  concatHex,
  encodeAbiParameters,
  keccak256,
  stringToHex,
  toHex,
  type Address,
  type Hex,
} from 'viem';
import { hybridMessageDigest, type HybridMessage } from './experimental';

const address = (n: number) => toHex(n, { size: 20 }) as Address;
const safe = address(100);
const preimage = concatHex([
  '0x1901',
  keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'uint256' }, { type: 'address' }],
      [
        keccak256(stringToHex('EIP712Domain(uint256 chainId,address verifyingContract)')),
        11155111n,
        safe,
      ],
    ),
  ),
  toHex(123, { size: 32 }),
]);
const input: HybridMessage = {
  chainId: 11155111,
  safe,
  preimage,
  algorithm: 1,
  version: 1,
  adapter: address(200),
  keyId: keccak256('0x12'),
  verifier: address(300),
  verifierCodeHash: keccak256('0x34'),
  epoch: 0n,
};

test('experimental digest binds all public identities', () => {
  const digest = hybridMessageDigest(input);
  expect(digest).toMatch(/^0x[0-9a-f]{64}$/);
  for (const change of [
    { preimage: concatHex([preimage.slice(0, -2) as Hex, '0xff']) },
    { algorithm: 2 },
    { adapter: address(201) },
    { keyId: keccak256('0x13') },
    { verifier: address(301) },
    { verifierCodeHash: keccak256('0x35') },
    { epoch: 1n },
  ]) {
    expect(hybridMessageDigest({ ...input, ...change } as HybridMessage)).not.toBe(digest);
  }
});

test('experimental digest rejects wrong chain, Safe domain, overflow, and missing identities', () => {
  for (const change of [
    { chainId: 31337 },
    { chainId: 1 },
    { safe: address(101) },
    { safe: address(1) },
    { version: 2 },
    { epoch: -1n },
    { epoch: 1n << 256n },
    { algorithm: 3 },
    { keyId: toHex(0, { size: 32 }) },
    { verifier: address(0) },
    { verifierCodeHash: '0x12' },
    { preimage: '0x19' },
    { preimage: `0x1902${preimage.slice(6)}` },
  ]) {
    expect(() => hybridMessageDigest({ ...input, ...change } as HybridMessage)).toThrow();
  }
});
