import { describe, expect, test } from 'bun:test';
import { toHex, type Address } from 'viem';
import {
  BATCH_SIZE,
  SecurityPolicyError,
  commitmentProof,
  commitmentRoot,
  normalizeAddresses,
  ownerLeaf,
  rotationsRemaining,
  validateTransferIntent,
  verifyProof,
} from './index';

const address = (n: number) => toHex(n, { size: 20 }) as Address;
const owners = Array.from({ length: BATCH_SIZE }, (_, i) => address(i + 2));
const context = { chainId: 31337, safe: address(0xaa), version: 1 };

describe('finite committed owner sequence', () => {
  test('matches a fixed BUNKER_OWNER_V1 commitment vector with admissible owners', () => {
    expect(commitmentRoot(context, owners)).toBe(
      '0xe264c01e2ed0ba5a816d5b3361d8c2c8b692d9fdc40aebfafc93de264f4eb028',
    );
    // The older mathematical vector used address(1), Safe's forbidden sentinel.
    expect(() =>
      commitmentRoot(
        context,
        Array.from({ length: BATCH_SIZE }, (_, i) => address(i + 1)),
      ),
    ).toThrow();
  });

  test('proves every owner and rejects changed leaves, sibling, index and root', () => {
    const root = commitmentRoot(context, owners);
    for (let i = 0; i < BATCH_SIZE; ++i) {
      const leaf = ownerLeaf(context, i, owners[i]!);
      const proof = commitmentProof(context, owners, i);
      expect(verifyProof(root, leaf, proof)).toBe(true);
      expect(verifyProof(root, ownerLeaf(context, i, owners[(i + 1) % BATCH_SIZE]!), proof)).toBe(
        false,
      );
      expect(
        verifyProof(root, leaf, { ...proof, siblings: [root, ...proof.siblings.slice(1)] }),
      ).toBe(false);
      expect(verifyProof(root, leaf, { ...proof, index: (i + 1) % BATCH_SIZE })).toBe(false);
      expect(verifyProof(ownerLeaf(context, 0, owners[0]!), leaf, proof)).toBe(false);
    }
  });

  test('binds chain, Safe and sequence version; rejects invalid context and owners', () => {
    expect(commitmentRoot(context, owners)).not.toBe(
      commitmentRoot({ ...context, chainId: 11155111 }, owners),
    );
    expect(commitmentRoot(context, owners)).not.toBe(
      commitmentRoot({ ...context, safe: address(0xbb) }, owners),
    );
    for (const changed of [
      { chainId: 1 },
      { safe: address(0) },
      { safe: address(1) },
      { safe: '0xinvalid' },
      { version: 0 },
      { version: 2 },
      { version: 1.5 },
    ]) {
      expect(() => commitmentRoot({ ...context, ...changed } as typeof context, owners)).toThrow();
    }
    for (const bad of [address(0), address(1), '0xinvalid']) {
      const changed = [...owners];
      changed[0] = bad as Address;
      expect(() => normalizeAddresses(changed)).toThrow(SecurityPolicyError);
    }
    expect(() => commitmentRoot(context, [context.safe, ...owners.slice(1)])).toThrow();
    expect(() => normalizeAddresses([...owners.slice(0, -1), owners[0]!])).toThrow();
    expect(() => normalizeAddresses(owners.slice(1))).toThrow();
  });

  test('rejects fractional and malformed proof inputs instead of truncating indices', () => {
    const leaf = ownerLeaf(context, 0, owners[0]!);
    const root = commitmentRoot(context, owners);
    const proof = commitmentProof(context, owners, 0);
    for (const index of [-1, 0.5, 20, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => ownerLeaf(context, index, owners[0]!)).toThrow(SecurityPolicyError);
      expect(() => commitmentProof(context, owners, index)).toThrow(SecurityPolicyError);
      expect(verifyProof(root, leaf, { ...proof, index })).toBe(false);
    }
    expect(
      verifyProof(root, leaf, { ...proof, siblings: [...proof.siblings.slice(0, 4), '0x12'] }),
    ).toBe(false);
    expect(verifyProof('0x12', leaf, proof)).toBe(false);
  });

  test('reserves final rotation and bounds next index', () => {
    expect(rotationsRemaining(0)).toBe(19);
    expect(rotationsRemaining(18)).toBe(1);
    expect(rotationsRemaining(19)).toBe(0);
    for (const index of [-1, 1.5, Number.NaN, 21]) {
      expect(() => rotationsRemaining(index)).toThrow(SecurityPolicyError);
    }
  });
});

test('transfer policy rejects bad value, nonce, owner or invalid rotation', () => {
  const intent = {
    chainId: 31337,
    safe: address(40),
    recipient: address(41),
    value: 1n,
    nonce: 0n,
    currentOwner: address(42),
    nextOwner: address(43),
    nextIndex: 18,
  };
  expect(validateTransferIntent(intent)).toBe(intent);
  for (const change of [
    { chainId: 1 },
    { value: 0n },
    { value: -1n },
    { value: 10n ** 22n + 1n },
    { value: '1' },
    { nonce: -1n },
    { nonce: 1n << 256n },
    { nonce: '0' },
    { nextIndex: -1 },
    { nextIndex: Number.MAX_SAFE_INTEGER + 1 },
    { nextOwner: intent.safe },
    { recipient: intent.safe },
    { nextIndex: 0.5 },
    { nextOwner: intent.currentOwner.toUpperCase() },
    { nextOwner: address(1) },
  ]) {
    expect(() => validateTransferIntent({ ...intent, ...change } as typeof intent)).toThrow();
  }
});

const intent = {
  chainId: 31337,
  safe: '0x0000000000000000000000000000000000000010' as const,
  recipient: '0x0000000000000000000000000000000000000011' as const,
  currentOwner: '0x0000000000000000000000000000000000000012' as const,
  nextOwner: '0x0000000000000000000000000000000000000013' as const,
  nonce: 25n,
  value: 1n,
  nextIndex: 25,
};
test('accepts dynamic rotation beyond 20 without commitments', () =>
  expect(validateTransferIntent(intent)).toEqual(intent));
test('rejects owner reuse within intent', () =>
  expect(() => validateTransferIntent({ ...intent, nextOwner: intent.currentOwner })).toThrow());
test('restricts chains', () =>
  expect(() => validateTransferIntent({ ...intent, chainId: 1 })).toThrow());
