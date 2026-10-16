import { mnemonicToAccount } from 'viem/accounts';
import type { Address } from 'viem';

type HintStorage = Pick<Storage, 'getItem' | 'setItem'>;
type RecoverSigner = (mnemonic: string, owner: Address, start?: number, count?: number) => number;

const hintKey = (safe: Address) => `bunker-derivation-index-v1:${safe.toLowerCase()}`;

export function saveRecoveryHint(
  storage: HintStorage,
  safe: Address,
  mnemonic: string,
  owner: Address,
  index: number,
) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** 31)
    throw new Error('Invalid derivation index.');
  const derived = mnemonicToAccount(mnemonic, { path: `m/44'/60'/7331'/0/${index}` }).address;
  if (derived.toLowerCase() !== owner.toLowerCase())
    throw new Error('Derivation index does not match the on-chain owner.');
  storage.setItem(hintKey(safe), JSON.stringify({ owner, index }));
}

export function recoverWithHint(
  storage: HintStorage,
  safe: Address,
  mnemonic: string,
  owner: Address,
  recover: RecoverSigner,
  start = 0,
  count = 100,
): number {
  let index: number | undefined;
  try {
    const hint = JSON.parse(storage.getItem(hintKey(safe)) ?? 'null');
    if (Number.isSafeInteger(hint?.index) && hint.index >= 0 && hint.index < 2 ** 31) {
      // The index is only a hint: recover checks the derived key against the live owner.
      index = recover(mnemonic, owner, hint.index, 1);
    }
  } catch {
    // Corrupt or stale hints must not block a user-selected recovery range.
  }
  index ??= recover(mnemonic, owner, start, count);
  saveRecoveryHint(storage, safe, mnemonic, owner, index);
  return index;
}
