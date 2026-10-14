import { expect, test } from 'bun:test';
import { toHex } from 'viem';
import { artifacts, dataCreation, runtime, validateRecord, type WalletRecord } from './wallet';

const address = (n: number) => toHex(n, { size: 20 });
const record: WalletRecord = {
  version: 1,
  chainId: 11155111,
  mode: 'c10',
  account: 0,
  index: 0,
  epoch: 0,
  ecSequenceVersion: 1,
  publicKey: toHex(1, { size: 32 }),
  parts: {},
};

test('experimental checkpoint rejects malformed version, identity, address and intent hash', () => {
  expect(validateRecord(structuredClone(record))).toEqual(record);
  expect(
    validateRecord({
      ...record,
      pending: {
        kind: 'send',
        hash: toHex(1, { size: 32 }),
        sealed: { iv: toHex(1, { size: 12 }), ciphertext: '0x00' },
      },
    }).pending?.kind,
  ).toBe('send');
  for (const change of [
    null,
    { ...record, chainId: 1 },
    { ...record, mode: 'invalid' },
    { ...record, index: 1 },
    { ...record, publicKey: '0x12' },
    { ...record, parts: [] },
    { ...record, parts: { factory: '0xinvalid' } },
    { ...record, parts: { factory: address(0) } },
    { ...record, parts: { factory: address(1) } },
    { ...record, safe: '0xinvalid' },
    { ...record, safe: address(0) },
    { ...record, safe: address(1) },
    { ...record, pending: { kind: 'unknown', hash: toHex(1, { size: 32 }) } },
    { ...record, pending: { kind: 'create', hash: '0x12' } },
    {
      ...record,
      pending: {
        kind: 'send',
        hash: toHex(1, { size: 32 }),
        sealed: { iv: '0x12', ciphertext: '0x00' },
      },
    },
    {
      ...record,
      pending: {
        kind: 'send',
        hash: toHex(1, { size: 32 }),
        sealed: { iv: toHex(1, { size: 12 }), ciphertext: '0xzz' },
      },
    },
  ]) {
    expect(() => validateRecord(change as WalletRecord)).toThrow();
  }
});

test('data-contract constructor encodes exact byte length and rejects malformed/oversized code', () => {
  const code = '0x000102' as const;
  const initcode = dataCreation(code);
  expect(initcode.endsWith(code.slice(2))).toBe(true);
  expect(initcode.startsWith('0x610003600e6000396100036000f3')).toBe(true);
  expect(dataCreation(`0x${'00'.repeat(24576)}`).length).toBeGreaterThan(24576 * 2);
  for (const invalid of ['0x', '0x0', '0xzz', `0x${'00'.repeat(24577)}`]) {
    expect(() => dataCreation(invalid as `0x${string}`)).toThrow();
  }
});

test('runtime binding requires known artifact and every immutable value', () => {
  expect(() => runtime('NotAnArtifact', {})).toThrow('Unknown artifact');
  expect(() => runtime('ExperimentalSetup', {})).toThrow('Missing guard');
  const encoded = runtime('ExperimentalSetup', { guard: address(10), proxyFactory: address(11) });
  const artifact = artifacts.ExperimentalSetup!;
  expect(encoded.length).toBe(artifact.runtime.length);
  for (const [key, ref] of Object.entries(artifact.immutables)) {
    const expected = toHex(key === 'guard' ? 10 : 11, { size: 32 }).slice(2);
    for (const { start, length } of ref) {
      expect(encoded.slice(start * 2 + 2, (start + length) * 2 + 2)).toBe(expected);
    }
  }
});
