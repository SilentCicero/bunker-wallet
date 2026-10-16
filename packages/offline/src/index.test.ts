import { describe, expect, test } from 'bun:test';
import { MAX_ENVELOPE_BYTES, parseEnvelope, sealEnvelope, serializeEnvelope } from './index';

const zero = '0x0000000000000000000000000000000000000000' as const;
const base = {
  version: 2 as const,
  kind: 'bunker-transfer' as const,
  chainId: 31337 as const,
  safe: '0x0000000000000000000000000000000000000002' as const,
  safeVersion: '1.4.1' as const,
  guard: '0x0000000000000000000000000000000000000003' as const,
  guardVersion: 2 as const,
  manifestId: `0x${'11'.repeat(32)}` as const,
  nonce: '0',
  to: '0x0000000000000000000000000000000000000004' as const,
  value: '1',
  data: '0x' as const,
  operation: 1 as const,
  safeTxGas: '100000',
  baseGas: '0' as const,
  gasPrice: '0' as const,
  gasToken: zero,
  refundReceiver: zero,
  currentOwner: '0x0000000000000000000000000000000000000005' as const,
  nextOwner: '0x0000000000000000000000000000000000000006' as const,
  nextIndex: 25,
  safeTxHash: `0x${'33'.repeat(32)}` as const,
};

describe('bounded offline envelope', () => {
  test('round trips canonical, stable payloads', () => {
    const envelope = sealEnvelope(base);
    expect(parseEnvelope(serializeEnvelope(envelope))).toEqual(envelope);
    expect(serializeEnvelope(envelope)).toBe(serializeEnvelope(envelope));
  });

  test('rejects tampering, malformed JSON, unknown and absent fields', () => {
    const envelope = sealEnvelope(base);
    expect(() => parseEnvelope(JSON.stringify({ ...envelope, value: '2' }))).toThrow('checksum');
    expect(() => parseEnvelope(JSON.stringify({ ...envelope, extra: true }))).toThrow('unknown');
    expect(() => parseEnvelope(JSON.stringify({ ...envelope, checksum: undefined }))).toThrow();
    expect(() => parseEnvelope('{')).toThrow('valid JSON');
    expect(() => parseEnvelope('x'.repeat(MAX_ENVELOPE_BYTES + 1))).toThrow('64 KiB');
  });

  test('rejects wrong runtime types, decimal forms and uint256 boundaries', () => {
    for (const change of [
      { chainId: '31337' },
      { chainId: 31337.5 },
      { version: '1' },
      { operation: 0 },
      { nonce: -1 },
      { nonce: '01' },
      { nonce: '-1' },
      { nonce: (1n << 256n).toString() },
      { value: '0' },
      { value: '1e3' },
      { value: (10n ** 22n + 1n).toString() },
      { safeTxGas: '1.5' },
    ]) {
      expect(() => sealEnvelope({ ...base, ...change } as never)).toThrow();
    }
  });

  test('rejects refunds, reused owner, invalid rotation/proof/address/signature framing', () => {
    for (const change of [
      { gasPrice: '1' },
      { baseGas: '1' },
      { gasToken: base.safe },
      { refundReceiver: base.safe },
      { currentOwner: base.nextOwner },
      { nextIndex: -1 },
      { nextIndex: Number.MAX_SAFE_INTEGER + 1 },
      { version: 1 },
      { guardVersion: 1 },
      { nextIndex: 1.5 },
      { merkleProof: [] }, // Removed V1 field must not be accepted.
      { guard: zero },
      { signature: '0x12' },
    ]) {
      expect(() => sealEnvelope({ ...base, ...change } as never)).toThrow();
    }
  });
});
