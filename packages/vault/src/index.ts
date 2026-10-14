import { argon2idAsync } from '@noble/hashes/argon2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { generateMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { isAddress } from 'viem';
import { SecurityPolicyError } from '@bunker/core';

type KdfParams = { memoryKiB: number; iterations: number; parallelism: 1 };
const KDF: KdfParams = { memoryKiB: 19456, iterations: 2, parallelism: 1 };
export type VaultMetadata = {
  chainId: 31337 | 11155111 | 84532 | 421614;
  safe?: `0x${string}`;
  derivation: "m/44'/60'/7331'/0/index";
  sequenceVersion: 1;
  experimental?: {
    mode: 'c10' | 'mldsa44';
    derivationVersion: 1;
    account: 0;
    index: 0;
    epoch: 0;
    ecSequenceVersion: 1;
    publicKey: `0x${string}`;
  };
};
export type EncryptedVault = {
  version: 1;
  kdf: {
    name: 'argon2id';
    memoryKiB: number;
    iterations: number;
    parallelism: number;
    salt: string;
  };
  cipher: { name: 'AES-256-GCM'; nonce: string; ciphertext: string };
  metadata: VaultMetadata;
};

export function newMnemonic(): string {
  return generateMnemonic(wordlist, 256);
}
export function validMnemonic(value: string): boolean {
  return value.trim().split(/\s+/).length === 24 && validateMnemonic(value.trim(), wordlist);
}

function validateMetadata(metadata: VaultMetadata) {
  if (
    !metadata ||
    typeof metadata !== 'object' ||
    Array.isArray(metadata) ||
    ![31337, 11155111, 84532, 421614].includes(metadata.chainId) ||
    metadata.derivation !== "m/44'/60'/7331'/0/index" ||
    metadata.sequenceVersion !== 1 ||
    (metadata.safe !== undefined &&
      (!isAddress(metadata.safe, { strict: true }) || BigInt(metadata.safe) <= 1n))
  ) {
    throw new SecurityPolicyError('Vault metadata is invalid.');
  }
  const experimental = metadata.experimental;
  if (
    experimental !== undefined &&
    (!experimental ||
      !['c10', 'mldsa44'].includes(experimental.mode) ||
      experimental.derivationVersion !== 1 ||
      experimental.account !== 0 ||
      experimental.index !== 0 ||
      experimental.epoch !== 0 ||
      experimental.ecSequenceVersion !== 1 ||
      typeof experimental.publicKey !== 'string' ||
      !/^0x(?:[0-9a-fA-F]{2})+$/.test(experimental.publicKey) ||
      experimental.publicKey.length !== (experimental.mode === 'c10' ? 66 : 2626))
  ) {
    throw new SecurityPolicyError('Vault metadata is invalid.');
  }
}

const aad = (metadata: VaultMetadata) =>
  new TextEncoder().encode(
    JSON.stringify({ version: 1, kdf: 'argon2id', cipher: 'AES-256-GCM', metadata }),
  );

async function key(password: string, salt: Uint8Array, params: KdfParams = KDF) {
  if (password.length < 12 || password.length > 256) {
    throw new SecurityPolicyError('Password must be 12–256 characters.');
  }
  return argon2idAsync(new TextEncoder().encode(password), salt, {
    m: params.memoryKiB,
    t: params.iterations,
    p: params.parallelism,
    dkLen: 32,
  });
}

export async function encryptMnemonic(
  mnemonic: string,
  password: string,
  metadata: VaultMetadata,
): Promise<EncryptedVault> {
  if (!validMnemonic(mnemonic)) throw new SecurityPolicyError('Recovery phrase is invalid.');
  validateMetadata(metadata);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const derived = await key(password, salt);
  const plain = new TextEncoder().encode(mnemonic);
  try {
    const k = await crypto.subtle.importKey(
      'raw',
      Uint8Array.from(derived).buffer,
      'AES-GCM',
      false,
      ['encrypt'],
    );
    const cipher = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: Uint8Array.from(nonce).buffer,
          additionalData: Uint8Array.from(aad(metadata)).buffer,
        },
        k,
        Uint8Array.from(plain).buffer,
      ),
    );
    return {
      version: 1,
      kdf: { name: 'argon2id', ...KDF, salt: bytesToHex(salt) },
      cipher: { name: 'AES-256-GCM', nonce: bytesToHex(nonce), ciphertext: bytesToHex(cipher) },
      metadata,
    };
  } finally {
    derived.fill(0);
    plain.fill(0);
  }
}

function validate(v: EncryptedVault) {
  if (
    !v ||
    typeof v !== 'object' ||
    Array.isArray(v) ||
    !v.kdf ||
    typeof v.kdf !== 'object' ||
    Array.isArray(v.kdf) ||
    !v.cipher ||
    typeof v.cipher !== 'object' ||
    Array.isArray(v.cipher) ||
    v.version !== 1 ||
    v.kdf.name !== 'argon2id' ||
    v.cipher.name !== 'AES-256-GCM'
  ) {
    throw new SecurityPolicyError('Vault format is unsupported.');
  }
  if (
    !Number.isInteger(v.kdf.memoryKiB) ||
    v.kdf.memoryKiB < 16384 ||
    v.kdf.memoryKiB > 131072 ||
    !Number.isInteger(v.kdf.iterations) ||
    v.kdf.iterations < 2 ||
    v.kdf.iterations > 8 ||
    v.kdf.parallelism !== 1
  ) {
    throw new SecurityPolicyError('Vault KDF parameters are unsafe.');
  }
  if (
    !/^[0-9a-f]{32}$/.test(v.kdf.salt) ||
    !/^[0-9a-f]{24}$/.test(v.cipher.nonce) ||
    !/^([0-9a-f]{2})+$/.test(v.cipher.ciphertext) ||
    v.cipher.ciphertext.length > 4096
  ) {
    throw new SecurityPolicyError('Vault encoding is invalid.');
  }
  validateMetadata(v.metadata);
}

export async function decryptMnemonic(vault: EncryptedVault, password: string): Promise<string> {
  validate(vault);
  const salt = hexToBytes(vault.kdf.salt);
  const nonce = hexToBytes(vault.cipher.nonce);
  const derived = await key(password, salt, {
    memoryKiB: vault.kdf.memoryKiB,
    iterations: vault.kdf.iterations,
    parallelism: 1,
  });
  try {
    const k = await crypto.subtle.importKey(
      'raw',
      Uint8Array.from(derived).buffer,
      'AES-GCM',
      false,
      ['decrypt'],
    );
    const plain = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: Uint8Array.from(nonce).buffer,
          additionalData: Uint8Array.from(aad(vault.metadata)).buffer,
        },
        k,
        Uint8Array.from(hexToBytes(vault.cipher.ciphertext)).buffer,
      ),
    );
    const mnemonic = new TextDecoder().decode(plain);
    plain.fill(0);
    if (!validMnemonic(mnemonic)) throw new Error();
    return mnemonic;
  } catch {
    throw new SecurityPolicyError('Vault could not be opened. The password or file is invalid.');
  } finally {
    derived.fill(0);
  }
}
