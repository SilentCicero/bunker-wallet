import { expect, test } from 'bun:test';
import { file } from 'bun';

test('App retains cached recovery access and exposes a range retry after restore failure', async () => {
  const source = await file(new URL('./App.tsx', import.meta.url)).text();
  const start = source.indexOf('  onMount(() => {');
  const mount = source.slice(start, source.indexOf('  onCleanup(() => {', start));
  const failure = mount.slice(mount.indexOf('} catch (e) {'));
  expect(failure).not.toContain('clearUnlockedMnemonic');
  expect(source).toContain('Retry cached phrase with this range');
  expect(source).toContain('recoverWithHint(');
  expect(source).toContain('saveRecoveryHint(');
});
import { mnemonicToAccount } from 'viem/accounts';
import { recoverWithHint, saveRecoveryHint } from './recoveryHint';
import { createBurnerSession } from './burner';

const phrase = 'test test test test test test test test test test test junk';
const safe = '0x1111111111111111111111111111111111111111';
const ownerAt = (index: number, mnemonic = phrase) =>
  mnemonicToAccount(mnemonic, { path: `m/44'/60'/7331'/0/${index}` }).address;
const storage = () => {
  const data = new Map<string, string>();
  return {
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => {
      data.set(key, value);
    },
  };
};

test('seed-switch recovery replaces stale hint metadata even at the same derivation index', () => {
  const store = storage();
  const switched =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  saveRecoveryHint(store, safe, phrase, ownerAt(321), 321);
  expect(
    recoverWithHint(
      store,
      safe,
      switched,
      ownerAt(321, switched),
      createBurnerSession().recoverSigner,
    ),
  ).toBe(321);
  expect(JSON.parse(store.getItem(`bunker-derivation-index-v1:${safe}`)!).owner).toBe(
    ownerAt(321, switched),
  );
});

test('expanded-range recovery repairs the hint after a bounded miss', () => {
  const store = storage();
  const recover = createBurnerSession().recoverSigner;
  expect(() => recoverWithHint(store, safe, phrase, ownerAt(321), recover)).toThrow(
    'recovery range',
  );
  expect(recoverWithHint(store, safe, phrase, ownerAt(321), recover, 320, 2)).toBe(321);
  expect(
    recoverWithHint(store, safe, phrase, ownerAt(321), createBurnerSession().recoverSigner),
  ).toBe(321);
});

test('only persists an index verified with the active seed and on-chain owner', () => {
  const store = storage();
  expect(() => saveRecoveryHint(store, safe, phrase, ownerAt(321), 3)).toThrow('does not match');
  expect(store.getItem(`bunker-derivation-index-v1:${safe}`)).toBeNull();
});

test('stale hint is verified against the on-chain owner and falls back to the requested range', () => {
  const store = storage();
  saveRecoveryHint(store, safe, phrase, ownerAt(321), 321);
  const session = createBurnerSession();
  expect(recoverWithHint(store, safe, phrase, ownerAt(4), session.recoverSigner)).toBe(4);
});

test('restores index above 99 from persisted derivation hint, not rotation count', () => {
  const store = storage();
  saveRecoveryHint(store, safe, phrase, ownerAt(321), 321);
  const session = createBurnerSession();
  expect(recoverWithHint(store, safe, phrase, ownerAt(321), session.recoverSigner)).toBe(321);
  expect(session.getActiveMnemonic()).toBe(phrase);
});
