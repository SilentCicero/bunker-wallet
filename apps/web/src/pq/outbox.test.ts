import { expect, test } from 'bun:test';
import { outboxKey, sealTransaction, openTransaction } from './outbox';

const phrase = `${'abandon '.repeat(23)}art`;
const aad = 'kind:fund/hash:abc';

test('outbox is encrypted and binds identity, hash, intent and a fresh nonce', async () => {
  const key = await outboxKey(phrase, 'Sepolia c10 public identity');
  const intent = { raw: '0x02public-test-only', nonce: 3, value: '123' };
  const first = await sealTransaction(key, intent, aad);
  const second = await sealTransaction(key, intent, aad);
  expect(first.iv).not.toBe(second.iv);
  expect(JSON.stringify(first)).not.toContain(intent.raw);
  expect(await openTransaction(key, first, aad)).toEqual(intent);
  await expect(openTransaction(key, first, 'kind:fund/hash:substituted')).rejects.toThrow();
  const other = await outboxKey(phrase, 'Sepolia mldsa44 public identity');
  await expect(openTransaction(other, first, aad)).rejects.toThrow();
  const changed = {
    ...first,
    ciphertext:
      `${first.ciphertext.slice(0, -2)}${first.ciphertext.endsWith('00') ? '01' : '00'}` as `0x${string}`,
  };
  await expect(openTransaction(key, changed, aad)).rejects.toThrow();
});

test('outbox rejects malformed identity, phrase, AAD, payload and ciphertext framing', async () => {
  await expect(outboxKey('not a recovery phrase', 'identity')).rejects.toThrow('phrase');
  await expect(outboxKey(`${'abandon '.repeat(11)}about`, 'identity')).rejects.toThrow('phrase');
  await expect(outboxKey(phrase, '')).rejects.toThrow('identity');
  await expect(outboxKey(phrase, 'x'.repeat(4097))).rejects.toThrow('identity');
  expect(
    await outboxKey(phrase, JSON.stringify({ publicKey: `0x${'11'.repeat(1312)}` })),
  ).toBeDefined();
  const key = await outboxKey(phrase, 'identity');
  await expect(sealTransaction(key, { nonce: 1 }, '')).rejects.toThrow('AAD');
  await expect(sealTransaction(key, { nonce: 1 }, 'x'.repeat(4097))).rejects.toThrow('AAD');
  await expect(sealTransaction(key, undefined, aad)).rejects.toThrow('payload');
  await expect(sealTransaction(key, { raw: 'x'.repeat(200_000) }, aad)).rejects.toThrow('payload');
  const circular: { self?: unknown } = {};
  circular.self = circular;
  await expect(sealTransaction(key, circular, aad)).rejects.toThrow('payload');
  const sealed = await sealTransaction(key, { nonce: 1 }, aad);
  for (const broken of [
    { ...sealed, iv: '0x12' as `0x${string}` },
    { ...sealed, ciphertext: '0xzz' as `0x${string}` },
    { ...sealed, ciphertext: `0x${'00'.repeat(200001)}` as `0x${string}` },
  ]) {
    await expect(openTransaction(key, broken, aad)).rejects.toThrow('Invalid encrypted outbox');
  }
  await expect(openTransaction(key, sealed, '')).rejects.toThrow('AAD');
  await expect(openTransaction(key, sealed, 'x'.repeat(4097))).rejects.toThrow('AAD');
  const mldsaAAD = JSON.stringify({ publicKey: `0x${'11'.repeat(1312)}`, hash: aad });
  expect(
    await openTransaction(key, await sealTransaction(key, { nonce: 1 }, mldsaAAD), mldsaAAD),
  ).toEqual({ nonce: 1 });
});
