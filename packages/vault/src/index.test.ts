import { describe, expect, test } from 'bun:test';
import {
  decryptMnemonic,
  encryptMnemonic,
  newMnemonic,
  validMnemonic,
  type VaultMetadata,
} from './index';

const metadata: VaultMetadata = {
  chainId: 31337,
  derivation: "m/44'/60'/7331'/0/index",
  sequenceVersion: 1,
};
const password = 'correct horse battery staple';

const encrypt = () => encryptMnemonic(newMnemonic(), password, metadata);

describe('encrypted vault integrity', () => {
  test('creates a 24-word phrase and rejects malformed phrases', () => {
    expect(validMnemonic(newMnemonic())).toBe(true);
    expect(validMnemonic('abandon '.repeat(24))).toBe(false);
    expect(validMnemonic('')).toBe(false);
  });

  test('encrypts, restores and excludes plaintext secrets', async () => {
    const phrase = newMnemonic();
    const vault = await encryptMnemonic(phrase, password, metadata);
    const stored = JSON.stringify(vault);
    expect(stored).not.toContain(phrase);
    expect(stored).not.toMatch(/"(?:mnemonic|seed|phrase|privateKey)"/);
    expect(await decryptMnemonic(vault, password)).toBe(phrase);
    await expect(decryptMnemonic(vault, 'wrong-password-value')).rejects.toThrow(
      'could not be opened',
    );
  });

  test('rejects ciphertext, nonce, salt and authenticated metadata tampering', async () => {
    const vault = await encrypt();
    await expect(
      decryptMnemonic(
        {
          ...vault,
          cipher: {
            ...vault.cipher,
            ciphertext: `${vault.cipher.ciphertext.slice(0, -2)}${vault.cipher.ciphertext.endsWith('00') ? '01' : '00'}`,
          },
        },
        password,
      ),
    ).rejects.toThrow();
    await expect(
      decryptMnemonic({ ...vault, cipher: { ...vault.cipher, nonce: '00'.repeat(12) } }, password),
    ).rejects.toThrow();
    await expect(
      decryptMnemonic({ ...vault, kdf: { ...vault.kdf, salt: '00'.repeat(16) } }, password),
    ).rejects.toThrow();
    await expect(
      decryptMnemonic(
        { ...vault, metadata: { ...metadata, safe: '0x0000000000000000000000000000000000000002' } },
        password,
      ),
    ).rejects.toThrow();
  });

  test('rejects malformed or unsafe KDF and encoding parameters before derivation', async () => {
    const vault = await encrypt();
    for (const kdf of [
      { ...vault.kdf, memoryKiB: 16383 },
      { ...vault.kdf, memoryKiB: 131073 },
      { ...vault.kdf, memoryKiB: Number.NaN },
      { ...vault.kdf, memoryKiB: undefined },
      { ...vault.kdf, iterations: 1 },
      { ...vault.kdf, iterations: 2.5 },
      { ...vault.kdf, parallelism: 2 },
    ]) {
      await expect(decryptMnemonic({ ...vault, kdf } as typeof vault, password)).rejects.toThrow(
        'unsafe',
      );
    }
    await expect(
      decryptMnemonic({ ...vault, cipher: { ...vault.cipher, nonce: '0x12' } }, password),
    ).rejects.toThrow('encoding');
    await expect(
      decryptMnemonic(
        { ...vault, cipher: { ...vault.cipher, ciphertext: '00'.repeat(2050) } },
        password,
      ),
    ).rejects.toThrow('encoding');
  });

  test('rejects non-object vault structures before accessing KDF or metadata', async () => {
    const vault = await encrypt();
    for (const broken of [
      null,
      [],
      { ...vault, kdf: null },
      { ...vault, kdf: [] },
      { ...vault, cipher: null },
      { ...vault, cipher: [] },
      { ...vault, metadata: null },
      { ...vault, metadata: [] },
    ]) {
      await expect(decryptMnemonic(broken as unknown as typeof vault, password)).rejects.toThrow(
        'Vault',
      );
    }
  });

  test('dynamic V2 metadata round trips and stays authenticated', async () => {
    const phrase = newMnemonic();
    const vault = await encryptMnemonic(phrase, password, { ...metadata, sequenceVersion: 2 });
    expect(await decryptMnemonic(vault, password)).toBe(phrase);
    await expect(
      decryptMnemonic({ ...vault, metadata: { ...vault.metadata, sequenceVersion: 1 } }, password),
    ).rejects.toThrow();
  });

  test('rejects invalid passwords and metadata on creation', async () => {
    const phrase = newMnemonic();
    for (const invalid of ['short', 'x'.repeat(257)]) {
      await expect(encryptMnemonic(phrase, invalid, metadata)).rejects.toThrow('Password');
    }
    for (const change of [
      { chainId: 1 },
      { chainId: '31337' },
      { derivation: "m/44'/60'/7331'/0/0" },
      { sequenceVersion: 3 },
      { safe: '0xinvalid' },
      {
        experimental: {
          mode: 'c10',
          derivationVersion: 1,
          account: 0,
          index: 0,
          epoch: 0,
          ecSequenceVersion: 1,
          publicKey: '0x12',
        },
      },
    ]) {
      await expect(
        encryptMnemonic(phrase, password, { ...metadata, ...change } as VaultMetadata),
      ).rejects.toThrow('metadata');
    }
  });
});
