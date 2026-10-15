import { mnemonicToSeed, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, type Hex } from 'viem';
export type SealedTransaction = { iv: Hex; ciphertext: Hex };
const utf8 = new TextEncoder();
/** Separate mnemonic-derived AEAD key; never persisted. No raw transaction or root seed enters localStorage. */
export async function outboxKey(mnemonic: string, identity: string) {
  if (
    typeof mnemonic !== 'string' ||
    mnemonic.trim().split(/\s+/).length !== 24 ||
    !validateMnemonic(mnemonic, wordlist)
  )
    throw new Error('Invalid outbox recovery phrase');
  if (typeof identity !== 'string' || !identity.trim() || utf8.encode(identity).length > 4096)
    throw new Error('Invalid outbox identity');
  const seed = await mnemonicToSeed(mnemonic);
  let key: Uint8Array;
  try {
    key = hkdf(sha512, seed, utf8.encode('BUNKER_TX_OUTBOX_V1'), utf8.encode(identity), 32);
  } finally {
    seed.fill(0);
  }
  try {
    return await crypto.subtle.importKey('raw', Uint8Array.from(key).buffer, 'AES-GCM', false, [
      'encrypt',
      'decrypt',
    ]);
  } finally {
    key.fill(0);
  }
}
export async function sealTransaction(
  key: CryptoKey,
  value: unknown,
  aad: string,
): Promise<SealedTransaction> {
  if (typeof aad !== 'string' || !aad || utf8.encode(aad).length > 4096)
    throw new Error('Invalid outbox AAD');
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new Error('Invalid outbox payload');
  }
  if (typeof serialized !== 'string') throw new Error('Invalid outbox payload');
  const plain = utf8.encode(serialized);
  if (plain.length > 199_900) {
    plain.fill(0);
    throw new Error('Invalid outbox payload');
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  try {
    return {
      iv: bytesToHex(iv),
      ciphertext: bytesToHex(
        new Uint8Array(
          await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: utf8.encode(aad) },
            key,
            plain,
          ),
        ),
      ),
    };
  } finally {
    plain.fill(0);
  }
}
export async function openTransaction(
  key: CryptoKey,
  sealed: SealedTransaction,
  aad: string,
): Promise<unknown> {
  if (typeof aad !== 'string' || !aad || utf8.encode(aad).length > 4096)
    throw new Error('Invalid outbox AAD');
  if (
    !sealed ||
    !/^0x[0-9a-f]{24}$/.test(sealed.iv) ||
    !/^0x(?:[0-9a-f]{2})+$/.test(sealed.ciphertext) ||
    sealed.ciphertext.length > 400000
  )
    throw new Error('Invalid encrypted outbox');
  const plain = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: Uint8Array.from(hexToBytes(sealed.iv)).buffer,
        additionalData: utf8.encode(aad),
      },
      key,
      Uint8Array.from(hexToBytes(sealed.ciphertext)).buffer,
    ),
  );
  try {
    return JSON.parse(new TextDecoder().decode(plain));
  } finally {
    plain.fill(0);
  }
}
