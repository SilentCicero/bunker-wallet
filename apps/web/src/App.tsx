import { createEffect, createSignal, lazy, For, onCleanup, onMount, Show } from 'solid-js';
import { formatEther, isAddress, parseEther, type Address, type Hex } from 'viem';
import { mnemonicToAccount } from 'viem/accounts';
import {
  decryptMnemonic,
  encryptMnemonic,
  newMnemonic,
  validMnemonic,
  type EncryptedVault,
} from '@bunker/vault';
import {
  createBurnerSession,
  deriveLocalPreviewOwnerAddress,
  deriveLocalPreviewWalletAddress,
  readSepoliaBalance,
  resolveRecipient,
  SEPOLIA_FAUCET,
} from './burner';
import {
  cacheUnlockedMnemonic,
  clearUnlockedMnemonic,
  restoreUnlockedMnemonic,
} from './unlockedSession';
import type { Activity } from './activity';
import { HistoryEntry } from './HistoryEntry';
import { SigningModes } from './SigningModes';
import { experimentalEnabled } from './pq/config';
const ExperimentalWallet = lazy(() => import('./pq/ExperimentalWallet'));

type View =
  | 'landing'
  | 'setup'
  | 'wallet'
  | 'advanced'
  | 'phrase'
  | 'confirm'
  | 'vault'
  | 'load'
  | 'recover'
  | 'pq';
const STANDARD_SETUP = 'bunker-standard-setup-v1',
  PQ_RECORD = 'bunker-experimental-wallet-v1',
  PQ_VAULT = 'bunker-experimental-vault-v1',
  PQ_ARCHIVE = 'bunker-experimental-archive-v1:';
type SetupJournal = {
  version: 1;
  state: 'ready' | 'deploying';
  address: Address;
  factoryHash?: `0x${string}`;
};
const readSetupJournal = (): SetupJournal | undefined => {
  try {
    const value = JSON.parse(localStorage.getItem(STANDARD_SETUP) ?? 'null') as SetupJournal;
    return value?.version === 1 &&
      isAddress(value.address) &&
      ['ready', 'deploying'].includes(value.state) &&
      (!('factoryHash' in value) ||
        (value.state === 'deploying' &&
          typeof value.factoryHash === 'string' &&
          /^0x[0-9a-fA-F]{64}$/.test(value.factoryHash)))
      ? value
      : undefined;
  } catch {
    return undefined;
  }
};
const uncertainStandardSetup = () =>
  localStorage.getItem(STANDARD_SETUP) !== null && readSetupJournal()?.state !== 'ready';
const short = (value: string) => `${value.slice(0, 8)}…${value.slice(-6)}`;
const NavIcon = (p: { name: 'github' | 'sun' | 'moon' }) => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path
      d={
        p.name === 'github'
          ? 'M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.86c-2.78.6-3.37-1.18-3.37-1.18-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.9 1.53 2.34 1.09 2.91.83.09-.65.35-1.09.64-1.34-2.22-.25-4.56-1.11-4.56-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02A9.6 9.6 0 0 1 12 6.84a9.6 9.6 0 0 1 2.5.34c1.91-1.3 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85V21c0 .27.18.58.69.48A10 10 0 0 0 12 2Z'
          : p.name === 'sun'
            ? 'M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10Zm0-5h1v3h-2V2h1Zm0 17h1v3h-2v-3h1ZM2 11h3v2H2v-2Zm17 0h3v2h-3v-2ZM4.22 5.64l1.42-1.42 2.12 2.12-1.42 1.42-2.12-2.12Zm12.02 12.02 1.42-1.42 2.12 2.12-1.42 1.42-2.12-2.12Zm2.12-13.44 1.42 1.42-2.12 2.12-1.42-1.42 2.12-2.12ZM6.34 16.24l1.42 1.42-2.12 2.12-1.42-1.42 2.12-2.12Z'
            : 'M20.2 15.3A8.5 8.5 0 0 1 8.7 3.8 8.5 8.5 0 1 0 20.2 15.3Z'
      }
    />
  </svg>
);
const SepoliaCreationStepper = (p: {
  current: 1 | 2 | 3 | 4 | 5;
  experimental?: boolean;
  onStep?: ((step: number) => void) | undefined;
  revisitCurrent?: boolean;
}) => (
  <>
    <ol
      class="stepper"
      classList={{ 'five-steps': p.experimental }}
      aria-label="Sepolia wallet creation progress"
    >
      <For
        each={
          p.experimental
            ? [
                'Choose signing mode',
                'Back up recovery phrase',
                'Protect browser',
                'Fund setup key',
                'Create Safe wallet',
              ]
            : ['Back up recovery phrase', 'Protect browser', 'Fund setup key', 'Create Safe wallet']
        }
      >
        {(label, index) => (
          <li
            classList={{ done: index() + 1 < p.current }}
            aria-current={index() + 1 === p.current ? 'step' : undefined}
            title={
              index() + 1 < p.current && !p.onStep
                ? 'Earlier steps cannot be reopened after browser protection; saved setup remains intact.'
                : undefined
            }
          >
            <Show
              when={
                (index() + 1 < p.current || (p.revisitCurrent && index() + 1 === p.current)) &&
                p.onStep
              }
              fallback={
                <>
                  <span>{index() + 1}</span>
                  <b>{label}</b>
                </>
              }
            >
              <button
                type="button"
                aria-label={`Return to ${label}`}
                onClick={() => p.onStep?.(index() + 1)}
              >
                <span>{index() + 1}</span>
                <b>{label}</b>
              </button>
            </Show>
          </li>
        )}
      </For>
    </ol>
    <Show when={p.current >= (p.experimental ? 4 : 3)}>
      <p class="stepper-hint">
        Earlier steps cannot be reopened after setup is saved. Your wallet and pending transactions
        remain intact.
      </p>
    </Show>
  </>
);
const Icon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M7 14a5 5 0 1 1 4.7-6.7L22 7v4h-3v3h-3v3h-4.3A5 5 0 0 1 7 14Zm0-2a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" />
  </svg>
);
export default function App() {
  const [pqMode, setPQMode] = createSignal<'standard' | 'c10' | 'mldsa44'>('standard');
  const [pqBootstrap, setPQBootstrap] = createSignal<{
    mnemonic?: string;
    password?: string;
    safe?: Address;
    fromVault?: boolean;
    readOnlyPendingHash?: Hex;
  }>();
  const [pqEntry, setPQEntry] = createSignal<'unlock' | 'resume'>('unlock');
  const [replacingPQ, setReplacingPQ] = createSignal(false),
    [invalidPQ, setInvalidPQ] = createSignal(false),
    [pendingPQ, setPendingPQ] = createSignal(false),
    [ackPQ, setAckPQ] = createSignal(false);
  const [replacingStandard, setReplacingStandard] = createSignal(false),
    [ackStandard, setAckStandard] = createSignal(false);
  let secretMnemonic: string | undefined,
    generation = 0;
  const wipe = () => {
    secretMnemonic = undefined;
  };
  const sepoliaEnabled =
    experimentalEnabled() ||
    (import.meta.env.VITE_BROWSER_SEPOLIA_E2E === '1' &&
      (import.meta.env.PROD
        ? window.location.hostname === 'bunker-wallet-pq-sepolia-test.pages.dev'
        : [
            'localhost',
            '127.0.0.1',
            'sepolia-test.bunker-wallet.pages.dev',
            'bunker.supplies',
          ].includes(window.location.hostname)));
  const {
    clearEphemeralBurner,
    demoSendETH,
    deploySafeWallet,
    finalizeSafeWallet,
    loadMnemonicSigner,
    readSafeWallet,
    verifyRecoverySequence,
  } = createBurnerSession();
  const [view, setView] = createSignal<View>('landing'),
    [theme, setTheme] = createSignal<'light' | 'dark'>('light'),
    [setupAddress, setSetupAddress] = createSignal<Address>(),
    [setupBalance, setSetupBalance] = createSignal(0n),
    [walletAddress, setWalletAddress] = createSignal<Address>(),
    [walletBalance, setWalletBalance] = createSignal(0n),
    [owner, setOwner] = createSignal<Address>(),
    [rotation, setRotation] = createSignal(0),
    [busy, setBusy] = createSignal(''),
    [checking, setChecking] = createSignal(false),
    [notice, setNotice] = createSignal(''),
    [activity, setActivity] = createSignal<Activity[]>([]),
    [confirmed, setConfirmed] = createSignal(false),
    [recoverable, setRecoverable] = createSignal(false),
    [savedVault, setSavedVault] = createSignal(Boolean(localStorage.getItem('bunker-vault'))),
    [savedPQ, setSavedPQ] = createSignal(
      Boolean(
        localStorage.getItem('bunker-experimental-vault-v1') ||
          localStorage.getItem('bunker-experimental-wallet-v1'),
      ),
    ),
    [mode, setMode] = createSignal<'local' | 'sepolia'>('local'),
    [nextSigner, setNextSigner] = createSignal<Address>();
  let phraseList!: HTMLOListElement,
    restore!: HTMLTextAreaElement,
    password!: HTMLInputElement,
    recoverPassword!: HTMLInputElement,
    savedPQPassword!: HTMLInputElement,
    to!: HTMLInputElement,
    amount!: HTMLInputElement,
    walletInput!: HTMLInputElement;
  let confirmInputs: HTMLInputElement[] = [];
  let localPreviewMnemonic: string | undefined;
  const previewOwner = (index: number) => {
    if (!localPreviewMnemonic) throw new Error('Local preview keys are unavailable.');
    return deriveLocalPreviewOwnerAddress(localPreviewMnemonic, index);
  };
  const creationStep = (current: 1 | 2 | 3 | 4) =>
    (experimentalEnabled() ? current + 1 : current) as 1 | 2 | 3 | 4 | 5;
  const go = (next: View) => {
    if (busy() === 'Locking browser…') return;
    generation++;
    if (view() === 'advanced' && next !== 'advanced') {
      setReplacingPQ(false);
      setInvalidPQ(false);
      setPendingPQ(false);
      setAckPQ(false);
      setReplacingStandard(false);
      setAckStandard(false);
    }
    if (view() === 'pq' && next !== 'pq') {
      setPQBootstrap();
    }
    if (
      ['phrase', 'confirm', 'vault'].includes(view()) &&
      ['advanced', 'landing', 'load', 'recover'].includes(next)
    )
      wipe();
    setNotice('');
    setView(next);
  };
  const copy = (value?: string) => {
    if (value && navigator.clipboard)
      void navigator.clipboard
        .writeText(value)
        .then(() => setNotice('Address copied.'))
        .catch(() => setNotice('Select the address to copy it.'));
  };
  const loadPost = () => {
    const x = window as unknown as { twttr?: { widgets: { load: () => void } } };
    if (document.querySelector('#x-widgets')) {
      x.twttr?.widgets.load();
      return;
    }
    const script = document.createElement('script');
    script.id = 'x-widgets';
    script.src = 'https://platform.twitter.com/widgets.js';
    script.async = true;
    script.charset = 'utf-8';
    script.onload = () => x.twttr?.widgets.load();
    document.head.append(script);
  };
  const begin = () => {
    setMode('local');
    setRecoverable(false);
    localPreviewMnemonic = newMnemonic();
    const wallet = deriveLocalPreviewWalletAddress(localPreviewMnemonic),
      current = previewOwner(0);
    setWalletAddress(wallet);
    setWalletBalance(parseEther('1'));
    setOwner(current);
    setNextSigner(previewOwner(1));
    setRotation(0);
    setActivity([{ label: 'Preview wallet created', index: 0, activeSigner: current }]);
    go('wallet');
  };
  const openFaucet = () => {
    const address = setupAddress();
    if (!address) return;
    copy(address);
    window.open(SEPOLIA_FAUCET, '_blank', 'noopener,noreferrer');
  };
  const checkFunding = async () => {
    const address = setupAddress();
    if (!address) return;
    setBusy('Checking testnet balance…');
    try {
      const balance = await readSepoliaBalance(address);
      setSetupBalance(balance);
      setNotice(
        balance >= parseEther('0.03')
          ? 'Funds received. Your Safe is ready to create.'
          : 'No test ETH yet. Faucets can take a minute.',
      );
    } catch (e) {
      setNotice(e instanceof Error ? e.message : 'Could not read Ethereum Sepolia.');
    } finally {
      setBusy('');
    }
  };
  const refreshWallet = async (expectedGeneration?: number) => {
    if (mode() === 'local') return;
    const wallet = walletAddress();
    if (!wallet) return;
    const state = await readSafeWallet(wallet);
    if (expectedGeneration !== undefined && expectedGeneration !== generation) return;
    setWalletBalance(state.balance);
    setOwner(state.owner);
    setRotation(state.index);
    return state;
  };
  const checkCreatedSafe = async () => {
    const wallet = walletAddress();
    if (!wallet)
      return setNotice(
        'The Safe address is not available yet. Keep this tab open and try again shortly.',
      );
    setChecking(true);
    try {
      await finalizeSafeWallet(wallet);
      const state = await refreshWallet();
      if (!state || state.balance === 0n)
        return setNotice(
          'Your Safe exists, but funding is still confirming. Try again in a moment.',
        );
      setActivity([{ label: 'Safe creation reconciled', index: state.index }]);
      setView('wallet');
      setNotice('Safe creation confirmed on Ethereum Sepolia.');
    } catch {
      setNotice('The Safe is still deploying. Keep this tab open and check again shortly.');
    } finally {
      setChecking(false);
    }
  };
  const createStableWallet = async () => {
    const g = generation;
    setBusy('Creating your guarded Safe…');
    try {
      if (mode() === 'local') {
        localPreviewMnemonic ??= newMnemonic();
        const address = deriveLocalPreviewWalletAddress(localPreviewMnemonic),
          current = previewOwner(0);
        setWalletAddress(address);
        setWalletBalance(parseEther('1'));
        setOwner(current);
        setNextSigner(previewOwner(1));
        setRotation(0);
        setActivity([
          { label: 'Local wallet created · simulated', index: 0, activeSigner: current },
        ]);
        go('wallet');
        return;
      }
      let creationHash: string | undefined;
      const onCreated = (created: Address, hash: `0x${string}`) => {
        creationHash = hash;
        localStorage.setItem('bunker-safe-wallet', created);
        if (experimentalEnabled()) localStorage.removeItem(STANDARD_SETUP);
        if (g === generation) setWalletAddress(created);
      };
      const onHash = (hash: `0x${string}`) => {
        const journal = readSetupJournal();
        if (journal?.state === 'deploying')
          localStorage.setItem(
            STANDARD_SETUP,
            JSON.stringify({ ...journal, factoryHash: hash } satisfies SetupJournal),
          );
      };
      const deploy = () => deploySafeWallet(onCreated, experimentalEnabled() ? onHash : undefined);
      let address: Address;
      if (experimentalEnabled())
        address = await navigator.locks.request(
          'bunker-standard-deploy',
          { ifAvailable: true },
          async (held) => {
            if (!held) throw new Error('Another tab is deploying this Standard wallet');
            const journal = readSetupJournal();
            if (
              journal?.state !== 'ready' ||
              journal.address.toLowerCase() !== setupAddress()?.toLowerCase()
            )
              throw new Error(
                'Standard deployment is already in progress or setup was not verified. Do not create another Safe.',
              );
            localStorage.setItem(
              STANDARD_SETUP,
              JSON.stringify({ ...journal, state: 'deploying' } satisfies SetupJournal),
            );
            return deploy();
          },
        );
      else address = await deploy();
      if (g !== generation) {
        clearEphemeralBurner();
        return;
      }
      setWalletAddress(address);
      await refreshWallet(g);
      if (g !== generation) {
        clearEphemeralBurner();
        return;
      }
      setActivity([
        { label: 'Safe proxy created', index: 0, hash: creationHash!, kind: 'deployment' },
      ]);
      setBusy('');
      go('wallet');
    } catch (e) {
      if (g !== generation) {
        clearEphemeralBurner();
        return;
      }
      if (walletAddress() && mode() === 'sepolia') {
        try {
          await refreshWallet(g);
          if (g !== generation) return;
          setActivity([{ label: 'Safe creation reconciled', index: rotation() }]);
          setView('wallet');
          setNotice('Safe created. Funding status was reconciled after an uncertain receipt.');
        } catch {
          if (g === generation)
            setNotice(
              'The Safe proxy was created but Sepolia is still confirming it. Check its status; do not create another Safe.',
            );
        }
      } else
        setNotice(
          experimentalEnabled() && readSetupJournal()?.state === 'deploying'
            ? 'Deployment outcome is unknown. Do not create another Safe. Inspect the original setup address and factory transaction; recover with the Safe address once confirmed.'
            : e instanceof Error
              ? e.message
              : 'Safe creation failed.',
        );
    } finally {
      if (g === generation) setBusy('');
    }
  };
  const afterAction = async (label: string, hash?: string, sentAmount?: bigint) => {
    if (mode() === 'local') {
      const used = owner(),
        active = nextSigner(),
        next = rotation() + 1;
      if (!used || !active || sentAmount === undefined) return;
      setWalletBalance((balance) => balance - sentAmount);
      setRotation(next);
      setOwner(active);
      setNextSigner(previewOwner(next + 1));
      setActivity((rows) => [
        { label: `${label} · simulated`, index: next, usedSigner: used, activeSigner: active },
        ...rows,
      ]);
      setNotice('Simulated locally — not broadcast. A fresh owner key is now active.');
      return;
    }
    await refreshWallet();
    setActivity((rows) => [{ label, hash: hash!, kind: 'rotation', index: rotation() }, ...rows]);
    setNotice('Confirmed on Ethereum Sepolia. A fresh owner key is now active.');
  };
  const runETH = async () => {
    if (!walletAddress() || !to.value.trim() || !amount.value)
      return setNotice('Enter a valid recipient and ETH amount.');
    let value: bigint;
    try {
      value = parseEther(amount.value);
    } catch {
      return setNotice('Enter a valid ETH amount.');
    }
    if (value <= 0n) return setNotice('Enter an ETH amount greater than zero.');
    if (mode() === 'local' && value > walletBalance())
      return setNotice('Preview balance is too low for that amount.');
    if (mode() === 'sepolia' && value + parseEther('0.001') > walletBalance())
      return setNotice('Keep 0.001 ETH in the Safe to fund the next signer.');
    if (mode() === 'sepolia' && rotation() >= 19)
      return setNotice('This fixed signer sequence is exhausted.');
    try {
      let recipient: Address | undefined;
      if (mode() === 'sepolia') {
        setBusy('Resolving recipient…');
        recipient = await resolveRecipient(to.value);
      }
      setBusy('Sending ETH and rotating the owner key…');
      await afterAction(
        `Sent ${formatEther(value)} ETH`,
        mode() === 'local' ? undefined : await demoSendETH(walletAddress()!, recipient!, value),
        value,
      );
    } catch (e) {
      setNotice(e instanceof Error ? e.message : 'Transfer failed.');
    } finally {
      setBusy('');
    }
  };
  const showPhrase = (mnemonic: string) => {
    setMode('sepolia');
    setConfirmed(false);
    secretMnemonic = mnemonic;
    queueMicrotask(() => {
      phraseList.replaceChildren(
        ...mnemonic.split(' ').map((word, index) => {
          const li = document.createElement('li'),
            n = document.createElement('span');
          n.textContent = String(index + 1);
          li.append(n, word);
          return li;
        }),
      );
    });
    go('phrase');
  };
  const rewindDraft = (step: number) => {
    if (busy() || !secretMnemonic) return;
    if (experimentalEnabled() && step === 1) {
      if (
        window.confirm(
          'Discard this unsaved recovery phrase and return to signing mode? You will need to back up a new phrase before continuing.',
        )
      )
        go('advanced');
      return;
    }
    if (step === (experimentalEnabled() ? 2 : 1)) showPhrase(secretMnemonic);
  };
  const pqArchiveKeys = () =>
    Array.from({ length: localStorage.length }, (_, i) => localStorage.key(i)).filter(
      (key): key is string => Boolean(key?.startsWith(PQ_ARCHIVE)),
    );
  const pendingPQHash = (raw: string | null): Hex | undefined => {
    try {
      const hash = JSON.parse(raw ?? 'null')?.pending?.hash;
      return typeof hash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(hash)
        ? (hash as Hex)
        : undefined;
    } catch {
      return undefined;
    }
  };
  const unresolvedArchiveFor = (
    safe: Address,
    activePublicKey?: Hex,
  ): Hex | 'unknown' | undefined => {
    for (const key of pqArchiveKeys())
      try {
        const raw = JSON.parse(localStorage.getItem(key) ?? 'null')?.checkpoint,
          record = JSON.parse(raw ?? 'null');
        if (
          record &&
          typeof record === 'object' &&
          'pending' in record &&
          (!isAddress(record.safe) || record.safe.toLowerCase() === safe.toLowerCase())
        ) {
          if (
            activePublicKey &&
            typeof record.publicKey === 'string' &&
            record.publicKey.toLowerCase() !== activePublicKey.toLowerCase()
          )
            continue;
          return pendingPQHash(raw) ?? 'unknown';
        }
      } catch {
        return 'unknown';
      }
  };
  const archivedPendingHash = () => {
    for (const key of pqArchiveKeys())
      try {
        const hash = pendingPQHash(JSON.parse(localStorage.getItem(key) ?? 'null')?.checkpoint);
        if (hash) return hash;
      } catch {}
    return undefined;
  };
  const archiveInvalidCheckpoint = async (removeVault: boolean) =>
    navigator.locks.request(
      'bunker-experimental-operation',
      { ifAvailable: true },
      async (held) => {
        if (!held)
          throw new Error(
            'Another tab is using this wallet. Close it and retry; nothing was removed.',
          );
        const raw = localStorage.getItem(PQ_RECORD),
          vault = localStorage.getItem(PQ_VAULT);
        if (!raw && !vault) {
          if (!pqArchiveKeys().length) throw new Error('No saved checkpoint or archive remains.');
          return;
        }
        if (raw) {
          let parsed: unknown;
          try {
            parsed = JSON.parse(raw);
          } catch {}
          if (
            !removeVault &&
            (!parsed || typeof parsed !== 'object' || ('pending' in parsed && !pendingPQHash(raw)))
          )
            throw new Error(
              'A signed intent may still be pending but its original hash cannot be verified. Keep this checkpoint and inspect it manually.',
            );
          let valid = false;
          try {
            const { validateRecord } = await import('./pq/wallet');
            validateRecord(parsed as Parameters<typeof validateRecord>[0]);
            valid = true;
          } catch {}
          if (
            valid &&
            (!removeVault || !parsed || typeof parsed !== 'object' || !('pending' in parsed))
          )
            throw new Error(
              'The checkpoint is valid now. Use normal wallet recovery instead; nothing was removed.',
            );
        }
        const key = PQ_ARCHIVE + crypto.randomUUID(),
          copy = JSON.stringify({ version: 1, checkpoint: raw, vault });
        localStorage.setItem(key, copy);
        if (
          localStorage.getItem(key) !== copy ||
          localStorage.getItem(PQ_RECORD) !== raw ||
          localStorage.getItem(PQ_VAULT) !== vault
        )
          throw new Error('Could not verify the archived copy. Nothing was removed.');
        localStorage.removeItem(PQ_RECORD);
        if (removeVault) localStorage.removeItem(PQ_VAULT);
        if (
          localStorage.getItem(PQ_RECORD) !== null ||
          (removeVault && localStorage.getItem(PQ_VAULT) !== null)
        )
          throw new Error(
            'Local removal was interrupted. The archived copy remains; inspect browser data before retrying.',
          );
      },
    );
  const downloadPQCheckpoint = () => {
    const copy = JSON.stringify({
      checkpoint: localStorage.getItem(PQ_RECORD),
      vault: localStorage.getItem(PQ_VAULT),
      archives: pqArchiveKeys().map((key) => ({ key, copy: localStorage.getItem(key) })),
    });
    const url = URL.createObjectURL(new Blob([copy], { type: 'application/json' })),
      link = document.createElement('a');
    link.href = url;
    link.download = 'bunker-experimental-checkpoint-private.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const createPhrase = async () => {
    if (busy()) return;
    if (experimentalEnabled() && uncertainStandardSetup())
      return setNotice(
        'A Standard Safe deployment is uncertain. Inspect its original transaction before creating another wallet; no data was deleted.',
      );
    if (
      experimentalEnabled() &&
      pqMode() === 'standard' &&
      (localStorage.getItem('bunker-vault') ||
        localStorage.getItem('bunker-safe-wallet') ||
        localStorage.getItem(STANDARD_SETUP))
    )
      return setNotice(
        'This browser already has a Standard wallet. Recover it or use a separate browser profile; saved data was not replaced.',
      );
    if (
      experimentalEnabled() &&
      pqMode() !== 'standard' &&
      (localStorage.getItem(PQ_RECORD) || localStorage.getItem(PQ_VAULT))
    ) {
      const raw = localStorage.getItem(PQ_RECORD);
      if (!raw) {
        setInvalidPQ(true);
        setPendingPQ(false);
        setNotice('');
        return;
      }
      const g = generation;
      try {
        const { validateRecord } = await import('./pq/wallet');
        if (g !== generation) return;
        const record = validateRecord(JSON.parse(raw));
        if ('pending' in record) {
          setReplacingPQ(false);
          setInvalidPQ(true);
          setPendingPQ(true);
          setNotice('');
          return;
        }
        setInvalidPQ(false);
        setPendingPQ(false);
        setReplacingPQ(true);
      } catch {
        if (g === generation) {
          setReplacingPQ(false);
          setInvalidPQ(true);
          setPendingPQ(false);
          setNotice('');
        }
      }
      return;
    }
    showPhrase(newMnemonic());
  };
  createEffect(() => {
    if (view() !== 'advanced' || !experimentalEnabled()) return;
    const selected = pqMode(),
      raw = localStorage.getItem(PQ_RECORD),
      vault = localStorage.getItem(PQ_VAULT);
    setAckPQ(false);
    setReplacingPQ(false);
    setInvalidPQ(false);
    setPendingPQ(false);
    if (selected === 'standard' || (!raw && !vault)) return;
    if (!raw) {
      setInvalidPQ(true);
      return;
    }
    let cancelled = false;
    void import('./pq/wallet')
      .then(({ validateRecord }) => {
        if (cancelled || view() !== 'advanced' || pqMode() !== selected) return;
        try {
          const record = validateRecord(JSON.parse(raw));
          if ('pending' in record) {
            setPendingPQ(true);
            setInvalidPQ(true);
          } else setReplacingPQ(true);
        } catch {
          setInvalidPQ(true);
        }
      })
      .catch(() => {
        if (!cancelled) setInvalidPQ(true);
      });
    onCleanup(() => {
      cancelled = true;
    });
  });
  const startAfterArchive = async () => {
    if (!invalidPQ() || !ackPQ() || busy()) return;
    const g = generation;
    setBusy('Archiving unverified setup…');
    try {
      if (uncertainStandardSetup())
        throw new Error(
          'Standard deployment is uncertain. Resolve it before starting another wallet.',
        );
      const next = newMnemonic();
      await archiveInvalidCheckpoint(true);
      if (g !== generation) return;
      setSavedPQ(false);
      setInvalidPQ(false);
      setPendingPQ(false);
      setAckPQ(false);
      setBusy('');
      showPhrase(next);
    } catch (e) {
      if (g === generation)
        setNotice(
          e instanceof Error
            ? e.message
            : 'Could not preserve the checkpoint; nothing was removed.',
        );
    } finally {
      if (g === generation) setBusy('');
    }
  };
  const replaceSavedStandard = async () => {
    if (
      !replacingStandard() ||
      !ackStandard() ||
      busy() ||
      view() !== 'advanced' ||
      pqMode() !== 'standard'
    )
      return;
    const g = generation;
    let deletionStarted = false;
    setBusy('Removing local Standard wallet…');
    try {
      await navigator.locks.request(
        'bunker-standard-deploy',
        { ifAvailable: true },
        async (held) => {
          if (!held)
            throw new Error(
              'Another tab is deploying this Standard wallet. Close it and retry; nothing was removed.',
            );
          if (g !== generation || view() !== 'advanced' || uncertainStandardSetup())
            throw new Error('Standard setup outcome is uncertain. Nothing was removed.');
          const vault = localStorage.getItem('bunker-vault'),
            safe = localStorage.getItem('bunker-safe-wallet'),
            journal = localStorage.getItem(STANDARD_SETUP);
          if (!vault && !safe && !journal)
            throw new Error('No saved Standard wallet remains; nothing was removed.');
          if (safe && !isAddress(safe))
            throw new Error(
              'Saved Safe address is invalid. Recover or inspect this wallet; nothing was removed.',
            );
          await clearUnlockedMnemonic();
          if (
            g !== generation ||
            view() !== 'advanced' ||
            !ackStandard() ||
            [vault, safe, journal].some(
              (value, i) =>
                value !==
                localStorage.getItem(['bunker-vault', 'bunker-safe-wallet', STANDARD_SETUP][i]!),
            )
          )
            throw new Error('Saved wallet changed or deletion was cancelled. Nothing was removed.');
          clearEphemeralBurner();
          deletionStarted = true;
          localStorage.removeItem('bunker-vault');
          localStorage.removeItem('bunker-safe-wallet');
          localStorage.removeItem(STANDARD_SETUP);
          if (
            ['bunker-vault', 'bunker-safe-wallet', STANDARD_SETUP].some(
              (key) => localStorage.getItem(key) !== null,
            )
          )
            throw new Error(
              'Local removal was interrupted. Inspect this browser’s saved data before retrying.',
            );
          setSavedVault(false);
          setWalletAddress();
          setSetupAddress();
          setRecoverable(false);
        },
      );
      if (g !== generation) return;
      setReplacingStandard(false);
      setAckStandard(false);
      setBusy('');
      showPhrase(newMnemonic());
    } catch (e) {
      if (g === generation)
        setNotice(
          deletionStarted
            ? 'Local removal was interrupted. Inspect this browser’s saved data before retrying.'
            : e instanceof Error
              ? e.message
              : 'Could not remove this browser wallet; nothing was changed.',
        );
    } finally {
      if (g === generation) setBusy('');
    }
  };
  const replaceSavedPQ = async () => {
    if (!ackPQ() || busy() || !replacingPQ() || view() !== 'advanced' || pqMode() === 'standard')
      return;
    const g = generation;
    let deletionStarted = false;
    setBusy('Checking saved test wallet…');
    try {
      const { validateRecord } = await import('./pq/wallet');
      if (g !== generation) return;
      const mnemonic = await navigator.locks.request(
        'bunker-experimental-operation',
        { ifAvailable: true },
        async (held) => {
          if (!held)
            throw new Error(
              'Another tab is using this test wallet. Close it and retry; nothing was deleted.',
            );
          if (g !== generation || view() !== 'advanced')
            throw new Error('Replacement cancelled; nothing was deleted.');
          if (uncertainStandardSetup())
            throw new Error('Standard deployment is uncertain. Do not replace local wallet data.');
          const raw = localStorage.getItem('bunker-experimental-wallet-v1');
          if (!raw)
            throw new Error(
              'Experimental checkpoint missing. Pending activity cannot be ruled out; nothing was deleted.',
            );
          const record = validateRecord(JSON.parse(raw));
          if ('pending' in record)
            throw new Error(
              'A signed transaction is pending or uncertain. Reconcile it before replacing this test wallet; nothing was deleted.',
            );
          const next = newMnemonic();
          deletionStarted = true;
          localStorage.removeItem('bunker-experimental-vault-v1');
          localStorage.removeItem('bunker-experimental-wallet-v1');
          if (
            localStorage.getItem('bunker-experimental-vault-v1') ||
            localStorage.getItem('bunker-experimental-wallet-v1')
          )
            throw new Error('Browser data was not fully deleted; do not start another wallet.');
          return next;
        },
      );
      if (g !== generation) return;
      setSavedPQ(false);
      setPQBootstrap();
      setReplacingPQ(false);
      setAckPQ(false);
      showPhrase(mnemonic);
    } catch (e) {
      if (g === generation)
        setNotice(
          deletionStarted
            ? 'Local deletion was interrupted. Inspect this browser’s saved data before retrying.'
            : e instanceof Error
              ? e.message
              : 'Could not verify saved test wallet; nothing was deleted.',
        );
    } finally {
      if (g === generation) setBusy('');
    }
  };
  const verifyWords = () => {
    const words = secretMnemonic?.split(' ');
    if (!words) return;
    if (
      confirmInputs.map((input) => input.value.trim().toLowerCase()).join('|') !==
      [2, 8, 17].map((i) => words[i]).join('|')
    )
      return setNotice('Those words do not match.');
    go('vault');
  };
  const finishSecure = async (persist: boolean) => {
    if (!secretMnemonic) return;
    const mnemonic = secretMnemonic,
      g = generation;
    if (experimentalEnabled() && uncertainStandardSetup())
      return setNotice(
        'A Standard Safe deployment is uncertain. Do not create another wallet until its original transaction is reconciled.',
      );
    if (
      experimentalEnabled() &&
      pqMode() === 'standard' &&
      (localStorage.getItem('bunker-vault') ||
        localStorage.getItem('bunker-safe-wallet') ||
        localStorage.getItem(STANDARD_SETUP))
    )
      return setNotice(
        'Another Standard wallet is already saved here. Recover it or use a separate browser profile; saved data was not replaced.',
      );
    if (experimentalEnabled() && pqMode() !== 'standard') {
      if (!persist)
        return setNotice(
          'Encrypt and save this browser before continuing. An interrupted setup cannot recover its phrase from a checkpoint alone.',
        );
      if (password.value.length < 12 || password.value.length > 256)
        return setNotice('Use a password of 12–256 characters.');
      setPQBootstrap({ mnemonic, ...(persist ? { password: password.value } : {}) });
      password.value = '';
      wipe();
      go('pq');
      return;
    }
    try {
      let encrypted: EncryptedVault | undefined;
      if (persist) {
        if (password.value.length < 12) return setNotice('Use at least 12 characters.');
        encrypted = await encryptMnemonic(mnemonic, password.value, {
          chainId: 11155111,
          derivation: "m/44'/60'/7331'/0/index",
          sequenceVersion: 1,
        });
        if (g !== generation) return;
        if (
          experimentalEnabled() &&
          (localStorage.getItem('bunker-vault') ||
            localStorage.getItem('bunker-safe-wallet') ||
            localStorage.getItem(STANDARD_SETUP))
        )
          return setNotice(
            'Another tab saved a wallet during encryption. Saved data was not replaced; return to Setup options.',
          );
      }
      if (g !== generation) return;
      const address = loadMnemonicSigner(mnemonic);
      if (experimentalEnabled())
        localStorage.setItem(
          STANDARD_SETUP,
          JSON.stringify({ version: 1, state: 'ready', address } satisfies SetupJournal),
        );
      if (encrypted) {
        try {
          localStorage.setItem('bunker-vault', JSON.stringify(encrypted));
        } catch (e) {
          if (experimentalEnabled()) localStorage.removeItem(STANDARD_SETUP);
          throw e;
        }
        setSavedVault(true);
        password.value = '';
      }
      await cacheUnlockedMnemonic(mnemonic);
      if (g !== generation) {
        await clearUnlockedMnemonic();
        clearEphemeralBurner();
        return;
      }
      setRecoverable(true);
      setSetupAddress(address);
      wipe();
      go('setup');
    } catch (e) {
      if (g === generation) {
        clearEphemeralBurner();
        setNotice(e instanceof Error ? e.message : 'Could not save this browser wallet');
      }
    }
  };
  const load = async (savedOnly = false) => {
    const g = generation;
    try {
      const entered =
        savedOnly || (experimentalEnabled() && view() === 'load')
          ? ''
          : (restore?.value?.trim() ?? '');
      let mnemonic: string;
      if (entered) {
        if (!validMnemonic(entered)) throw new Error('Enter a valid 24-word recovery phrase.');
        mnemonic = entered;
      } else if (localStorage.getItem('bunker-vault')) {
        mnemonic = await decryptMnemonic(
          JSON.parse(localStorage.getItem('bunker-vault')!) as EncryptedVault,
          password.value,
        );
        if (g !== generation) return;
      } else throw new Error('Enter a recovery phrase or load an encrypted vault.');
      const supplied =
          savedOnly || (experimentalEnabled() && view() === 'load')
            ? ''
            : (walletInput?.value?.trim() ?? ''),
        saved = (supplied || localStorage.getItem('bunker-safe-wallet')) as Address | null;
      if (supplied && !isAddress(supplied)) throw new Error('Enter a valid Safe address.');
      if (experimentalEnabled() && !saved && entered)
        throw new Error('Enter the existing Safe address to recover.');
      if (saved && !isAddress(saved))
        throw new Error('The saved Safe address is invalid. Enter the correct address to recover.');
      if (saved) {
        const state = await readSafeWallet(saved);
        if (g !== generation) return;
        const recovered = loadMnemonicSigner(mnemonic, state.index);
        if (recovered.toLowerCase() !== state.owner.toLowerCase())
          throw new Error('This recovery phrase does not control the saved wallet.');
        await verifyRecoverySequence(saved);
        if (g !== generation) return;
        if (experimentalEnabled()) localStorage.removeItem(STANDARD_SETUP);
        const currentBalance =
          state.balance === 0n ? await readSepoliaBalance(recovered) : undefined;
        if (g !== generation) return;
        await cacheUnlockedMnemonic(mnemonic);
        if (g !== generation) {
          await clearUnlockedMnemonic();
          return;
        }
        setRecoverable(true);
        setWalletAddress(saved);
        if (currentBalance !== undefined) {
          setSetupAddress(recovered);
          setSetupBalance(currentBalance);
          setNotice(
            'Your Safe exists but was not funded. Check Safe status to finish without creating another.',
          );
          if (password) password.value = '';
          go('setup');
          return;
        }
        setWalletBalance(state.balance);
        setOwner(state.owner);
        setRotation(state.index);
        setActivity([{ label: 'Recovered Safe wallet', index: state.index }]);
        if (password) password.value = '';
        go('wallet');
      } else {
        const address = loadMnemonicSigner(mnemonic);
        if (
          experimentalEnabled() &&
          (readSetupJournal()?.state !== 'ready' ||
            readSetupJournal()?.address.toLowerCase() !== address.toLowerCase())
        ) {
          clearEphemeralBurner();
          await clearUnlockedMnemonic();
          throw new Error(
            'Saved Standard setup is missing, mismatched or deployment is uncertain. Do not create another Safe; recover an existing Safe with your phrase and Safe address. The encrypted vault was not replaced.',
          );
        }
        if (g !== generation) return;
        await cacheUnlockedMnemonic(mnemonic);
        if (g !== generation) {
          await clearUnlockedMnemonic();
          return;
        }
        setRecoverable(true);
        setSetupAddress(address);
        if (password) password.value = '';
        go('setup');
      }
    } catch (e) {
      if (g === generation)
        setNotice(e instanceof Error ? e.message : 'Wallet could not be loaded.');
    } finally {
      if (g === generation && password) password.value = '';
    }
  };
  const recoverStandard = async (
    mnemonic: string,
    safe: Address,
    g: number,
    browserPassword: string,
  ) => {
    const state = await readSafeWallet(safe);
    if (g !== generation) {
      clearEphemeralBurner();
      return;
    }
    const recovered = loadMnemonicSigner(mnemonic, state.index);
    if (recovered.toLowerCase() !== state.owner.toLowerCase())
      throw new Error('This phrase does not control the supplied Safe');
    await verifyRecoverySequence(safe);
    if (g !== generation) {
      clearEphemeralBurner();
      return;
    }
    const existing = localStorage.getItem('bunker-safe-wallet'),
      journal = readSetupJournal();
    if (
      journal &&
      journal.address.toLowerCase() !==
        mnemonicToAccount(mnemonic, { path: "m/44'/60'/7331'/0/0" }).address.toLowerCase()
    )
      throw new Error(
        'Another Standard setup is saved here. Use a separate browser profile; saved data was not replaced.',
      );
    if (existing && existing.toLowerCase() !== safe.toLowerCase())
      throw new Error(
        'Another Safe is saved here. Use a separate browser profile; saved data was not replaced.',
      );
    const previousVault = localStorage.getItem('bunker-vault');
    let encrypted: EncryptedVault | undefined;
    if (previousVault) {
      const savedMnemonic = await decryptMnemonic(
        JSON.parse(previousVault) as EncryptedVault,
        browserPassword,
      );
      if (savedMnemonic !== mnemonic)
        throw new Error(
          'This browser stores a different Standard vault. Use its original phrase or a separate browser profile; nothing was replaced.',
        );
    } else
      encrypted = await encryptMnemonic(mnemonic, browserPassword, {
        chainId: 11155111,
        derivation: "m/44'/60'/7331'/0/index",
        sequenceVersion: 1,
      });
    const setupFunds = state.balance === 0n ? await readSepoliaBalance(recovered) : undefined;
    if (g !== generation) {
      clearEphemeralBurner();
      return;
    }
    const oldSafe = localStorage.getItem('bunker-safe-wallet');
    localStorage.setItem('bunker-safe-wallet', safe);
    try {
      if (encrypted) localStorage.setItem('bunker-vault', JSON.stringify(encrypted));
    } catch (e) {
      if (oldSafe === null) localStorage.removeItem('bunker-safe-wallet');
      else localStorage.setItem('bunker-safe-wallet', oldSafe);
      throw e;
    }
    setSavedVault(true);
    if (experimentalEnabled()) localStorage.removeItem(STANDARD_SETUP);
    await cacheUnlockedMnemonic(mnemonic);
    if (g !== generation) {
      await clearUnlockedMnemonic();
      clearEphemeralBurner();
      return;
    }
    setMode('sepolia');
    setRecoverable(true);
    setWalletAddress(safe);
    setBusy('');
    if (setupFunds !== undefined) {
      setSetupAddress(recovered);
      setSetupBalance(setupFunds);
      go('setup');
      setNotice('Existing Safe verified. Check its funding status; no new Safe was created.');
    } else {
      setWalletBalance(state.balance);
      setOwner(state.owner);
      setRotation(state.index);
      setActivity([{ label: 'Recovered Safe wallet', index: state.index }]);
      go('wallet');
    }
  };
  const recoverWallet = async () => {
    if (busy()) return;
    const mnemonic = restore.value.trim(),
      safe = walletInput.value.trim(),
      browserPassword = recoverPassword.value;
    if (!validMnemonic(mnemonic)) return setNotice('Enter your valid 24-word recovery phrase.');
    if (!isAddress(safe)) return setNotice('Enter the existing Safe address.');
    if (browserPassword.length < 12 || browserPassword.length > 256)
      return setNotice(
        'Enter a browser password of 12–256 characters to save the recovered wallet.',
      );
    const g = generation;
    setBusy('Checking Safe configuration on Sepolia…');
    try {
      const { detectSafeMode, validateRecord } = await import('./pq/wallet');
      if (g !== generation) return;
      const detected = await detectSafeMode(safe as Address);
      if (g !== generation) return;
      let readOnlyPendingHash: Hex | undefined;
      if (detected !== 'standard') {
        const raw = localStorage.getItem(PQ_RECORD);
        let active: import('./pq/wallet').WalletRecord | undefined;
        if (raw)
          try {
            active = validateRecord(JSON.parse(raw));
          } catch {}
        const archived = unresolvedArchiveFor(
          safe as Address,
          active?.safe?.toLowerCase() === safe.toLowerCase() && !active.pending
            ? active.publicKey
            : undefined,
        );
        if (archived === 'unknown')
          throw new Error(
            'An archived signed intent lacks a verifiable hash. Keep its copy and inspect it manually; no new transaction is allowed.',
          );
        readOnlyPendingHash = archived;
        if (raw) {
          if (!active) {
            const pending = JSON.parse(raw)?.pending;
            if (pending && !pendingPQHash(raw))
              throw new Error(
                'The saved pending intent lacks a verifiable hash. Keep its checkpoint and inspect it manually.',
              );
            readOnlyPendingHash ??= pendingPQHash(raw);
            await archiveInvalidCheckpoint(false);
          }
          if (g !== generation) return;
        }
      }
      if (detected === 'standard') {
        await recoverStandard(mnemonic, safe as Address, g, browserPassword);
        recoverPassword.value = '';
        return;
      }
      setPQMode(detected);
      setPQBootstrap({
        mnemonic,
        safe: safe as Address,
        password: browserPassword,
        ...(readOnlyPendingHash ? { readOnlyPendingHash } : {}),
      });
      restore.value = '';
      walletInput.value = '';
      recoverPassword.value = '';
      setBusy('');
      go('pq');
    } catch (e) {
      if (g === generation) {
        clearEphemeralBurner();
        setNotice(e instanceof Error ? e.message : 'Could not verify this Safe');
      }
    } finally {
      if (g === generation) setBusy('');
    }
  };
  const resumeStandardSetup = async () => {
    if (busy()) return;
    const mnemonic = restore.value.trim(),
      journal = readSetupJournal();
    if (journal?.state !== 'ready' || localStorage.getItem('bunker-safe-wallet'))
      return setNotice(
        'No unfinished Standard setup is available. Recover an existing Safe with phrase and Safe address.',
      );
    if (!validMnemonic(mnemonic)) return setNotice('Enter the original valid 24-word phrase.');
    const address = mnemonicToAccount(mnemonic, { path: "m/44'/60'/7331'/0/0" }).address;
    if (address.toLowerCase() !== journal.address.toLowerCase())
      return setNotice(
        'This phrase does not match the unfinished setup; saved data was not changed.',
      );
    const g = generation;
    setBusy('Checking saved setup key…');
    try {
      const balance = await readSepoliaBalance(address);
      if (g !== generation) return;
      loadMnemonicSigner(mnemonic);
      await cacheUnlockedMnemonic(mnemonic);
      if (g !== generation) {
        await clearUnlockedMnemonic();
        clearEphemeralBurner();
        return;
      }
      setMode('sepolia');
      setRecoverable(true);
      setSetupAddress(address);
      setSetupBalance(balance);
      restore.value = '';
      setBusy('');
      go('setup');
    } catch (e) {
      if (g === generation) {
        clearEphemeralBurner();
        setNotice(e instanceof Error ? e.message : 'Could not resume setup');
      }
    } finally {
      if (g === generation) setBusy('');
    }
  };
  const recoverSavedPQ = () => {
    try {
      const raw = localStorage.getItem('bunker-experimental-vault-v1');
      if (!raw || !localStorage.getItem('bunker-experimental-wallet-v1'))
        throw new Error(
          'Saved experimental checkpoint missing. Recover with phrase and Safe address; the vault was not changed.',
        );
      const mode = JSON.parse(raw)?.metadata?.experimental?.mode;
      if (mode !== 'c10' && mode !== 'mldsa44')
        throw new Error('Saved experimental wallet metadata is invalid');
      const value = savedPQPassword.value;
      if (value.length < 12 || value.length > 256)
        throw new Error('Enter the saved vault password (12–256 characters).');
      setPQMode(mode);
      setPQBootstrap({ fromVault: true, password: value });
      savedPQPassword.value = '';
      go('pq');
    } catch (e) {
      setNotice(e instanceof Error ? e.message : 'Could not recover saved wallet');
    }
  };
  const openSavedPQ = (source: 'unlock' | 'resume') => {
    try {
      const raw = localStorage.getItem(
        source === 'unlock' ? 'bunker-experimental-vault-v1' : 'bunker-experimental-wallet-v1',
      );
      const data = JSON.parse(raw ?? 'null');
      const detected = source === 'unlock' ? data?.metadata?.experimental?.mode : data?.mode;
      if (detected !== 'c10' && detected !== 'mldsa44')
        throw new Error('Saved experimental wallet metadata is invalid');
      if (source === 'resume' && data.safe)
        throw new Error(
          'This Safe already exists. Use Recover wallet with its phrase and Safe address.',
        );
      setPQMode(detected);
      setPQEntry(source);
      go('pq');
    } catch (e) {
      setNotice(e instanceof Error ? e.message : 'Could not open saved wallet');
    }
  };
  const exit = async () => {
    if (busy() === 'Locking browser…') return;
    const g = ++generation;
    setBusy('Locking browser…');
    try {
      await clearUnlockedMnemonic();
      if (g !== generation) return;
      wipe();
      setPQBootstrap();
      setChecking(false);
      localPreviewMnemonic = undefined;
      clearEphemeralBurner();
      setSetupAddress();
      setWalletAddress();
      setOwner();
      setNextSigner();
      setActivity([]);
      setBusy('');
      go('landing');
    } catch {
      if (g === generation) {
        setBusy('');
        setNotice('Could not clear the browser session. Retry Lock; this wallet remains open.');
      }
    }
  };
  onMount(() => {
    loadPost();
    void (async () => {
      const g = generation;
      if (!sepoliaEnabled) return;
      const mnemonic = await restoreUnlockedMnemonic();
      if (g !== generation) {
        await clearUnlockedMnemonic();
        return;
      }
      if (mnemonic) {
        try {
          setMode('sepolia');
          setRecoverable(true);
          const saved = localStorage.getItem('bunker-safe-wallet') as Address | null;
          if (saved && isAddress(saved)) {
            const state = await readSafeWallet(saved);
            if (g !== generation) {
              clearEphemeralBurner();
              return;
            }
            const signer = loadMnemonicSigner(mnemonic, state.index);
            await verifyRecoverySequence(saved);
            if (g !== generation) {
              clearEphemeralBurner();
              return;
            }
            if (experimentalEnabled()) localStorage.removeItem(STANDARD_SETUP);
            setWalletAddress(saved);
            if (state.balance === 0n) {
              setSetupAddress(signer);
              const currentBalance = await readSepoliaBalance(signer);
              if (g !== generation) {
                clearEphemeralBurner();
                return;
              }
              setSetupBalance(currentBalance);
              setNotice(
                'Your Safe exists but was not funded. Check Safe status to finish without creating another.',
              );
              setView('setup');
              return;
            }
            setWalletBalance(state.balance);
            setOwner(state.owner);
            setRotation(state.index);
            setActivity([{ label: 'Unlocked session restored', index: state.index }]);
            setView('wallet');
          } else {
            const address = loadMnemonicSigner(mnemonic);
            if (
              experimentalEnabled() &&
              (readSetupJournal()?.state !== 'ready' ||
                readSetupJournal()?.address.toLowerCase() !== address.toLowerCase())
            ) {
              clearEphemeralBurner();
              await clearUnlockedMnemonic();
              if (g !== generation) return;
              setNotice(
                'Saved Standard setup is missing or deployment is uncertain. Do not create another Safe; recover with your phrase and Safe address. The vault remains intact.',
              );
              setView(savedVault() ? (experimentalEnabled() ? 'recover' : 'load') : 'landing');
              return;
            }
            setSetupAddress(address);
            setView('setup');
          }
          return;
        } catch {
          if (g === generation) await clearUnlockedMnemonic();
        }
      }
      if (g !== generation) return;
      if (
        savedVault() ||
        (experimentalEnabled() && (savedPQ() || readSetupJournal()?.state === 'ready'))
      ) {
        setMode('sepolia');
        setView(experimentalEnabled() && (savedVault() || savedPQ()) ? 'recover' : 'load');
      } else if (localStorage.getItem('bunker-safe-wallet'))
        setNotice(
          'This Safe has no encrypted browser backup and cannot be restored after refresh. Create a new recoverable wallet.',
        );
    })();
  });
  onCleanup(() => {
    wipe();
    localPreviewMnemonic = undefined;
    clearEphemeralBurner();
  });
  return (
    <div class={`site ${theme()}${experimentalEnabled() ? ' experimental' : ''}`}>
      <header class="top">
        <button class="brand" onClick={() => go('landing')}>
          <span>B</span>Bunker
        </button>
        <nav>
          <Show when={walletAddress()}>
            <button class="nav-wallet" onClick={() => go('wallet')}>
              Wallet
            </button>
          </Show>
          <button class="nav-setup" onClick={() => go('advanced')}>
            Setup options
          </button>
          <Show when={experimentalEnabled()}>
            <button class="nav-recover" onClick={() => go('recover')}>
              Recover wallet
            </button>
          </Show>
          <a
            class="nav-icon"
            href="https://github.com/SilentCicero/bunker-wallet"
            target="_blank"
            rel="noreferrer"
            aria-label="View Bunker on GitHub"
          >
            <NavIcon name="github" />
          </a>
          <button
            class="nav-icon"
            aria-label={theme() === 'light' ? 'Use dark mode' : 'Use light mode'}
            title={theme() === 'light' ? 'Use dark mode' : 'Use light mode'}
            onClick={() => setTheme(theme() === 'light' ? 'dark' : 'light')}
          >
            <NavIcon name={theme() === 'light' ? 'moon' : 'sun'} />
          </button>
          <Show when={walletAddress() || (mode() === 'sepolia' && setupAddress())}>
            <button class="nav-exit" disabled={busy() === 'Locking browser…'} onClick={exit}>
              {busy() === 'Locking browser…' ? 'Locking…' : mode() === 'sepolia' ? 'Lock' : 'Exit'}
            </button>
          </Show>
        </nav>
      </header>
      <Show when={notice()}>
        <div class="toast" role="status">
          {notice()}
        </div>
      </Show>
      <main>
        <Show when={view() === 'landing'}>
          <section class="hero-new">
            <div class="hero-copy">
              <h1>
                One address.
                <br />
                Fresh keys.
              </h1>
              <p>
                Keep one familiar Ethereum address while Bunker rotates the signing owner after
                every action—<strong>reducing exposure to future quantum attacks.</strong>
              </p>
              <div class="hero-actions">
                <Show
                  when={experimentalEnabled()}
                  fallback={
                    <button class="primary" onClick={begin}>
                      Try It (Simulation)
                    </button>
                  }
                >
                  <button class="primary" onClick={() => go('advanced')}>
                    Create wallet (Testnet)
                  </button>
                </Show>
                <button
                  class="button-link"
                  disabled={!experimentalEnabled() && !sepoliaEnabled}
                  onClick={
                    experimentalEnabled()
                      ? begin
                      : sepoliaEnabled
                        ? () => {
                            if (savedVault()) {
                              setMode('sepolia');
                              go('load');
                            } else createPhrase();
                          }
                        : undefined
                  }
                >
                  {experimentalEnabled()
                    ? 'Try It (Simulation)'
                    : sepoliaEnabled
                      ? savedVault()
                        ? 'Resume saved wallet'
                        : 'Create Wallet (Testnet)'
                      : 'Use Ethereum Sepolia (Soon)'}
                </button>
              </div>
              <Show when={sepoliaEnabled}>
                <small class="test-label">Sepolia testnet · Unaudited · Test ETH only</small>
              </Show>
              <Show when={experimentalEnabled() && readSetupJournal()?.state === 'deploying'}>
                <p role="alert" class="ephemeral-note">
                  A Standard Safe deployment may already exist. Do not create another; inspect the
                  original setup address and factory transaction, then recover with the Safe
                  address.
                </p>
              </Show>
            </div>
            <div class="mechanism" aria-label="Stable Safe address with rotating owner keys">
              <div class="address-head">
                <span>YOUR WALLET ADDRESS</span>
                <b>Stays the same</b>
              </div>
              <code>0x71A4…92F0</code>
              <div class="key-track">
                <div class="key spent">
                  <Icon />
                  <span>Key 08</span>
                  <small>Used</small>
                </div>
                <i>→</i>
                <div class="key active">
                  <Icon />
                  <span>Key 09</span>
                  <small>Active</small>
                </div>
                <i>→</i>
                <div class="key next">
                  <Icon />
                  <span>Key 10</span>
                  <small>Next</small>
                </div>
              </div>
              <div class="action-line">
                <span>Send ETH</span>
                <b>Signer advances</b>
              </div>
            </div>
          </section>
          <div class="trust-line">
            <span>BIP-39 · Standard ECDSA</span>
            <span>MIT open source</span>
            <span>Safe under the hood</span>
          </div>
          <section class="external-post">
            <div class="post-context">
              <span>External perspective</span>
              <h2>A call to plan for “bunker mode.”</h2>
              <p>
                This post loads from X and is included for discussion, not as a Bunker security
                assessment. Bunker does not endorse predictions about ECDSA-break timing or causes.
              </p>
            </div>
            <div class="post-embed">
              <blockquote class="twitter-tweet" data-dnt="true">
                <a href="https://x.com/drakefjustin/status/2107837081313505768">
                  Read the post by Justin Drake on X
                </a>
              </blockquote>
              <a
                class="post-link"
                href="https://x.com/drakefjustin/status/2107837081313505768"
                target="_blank"
                rel="noreferrer"
              >
                Open directly on X →
              </a>
            </div>
          </section>
          <section class="why" id="how-it-works">
            <div class="why-head">
              <span>Why Bunker?</span>
              <h2>
                Rotate the keys.
                <br />
                Keep the wallet.
              </h2>
            </div>
            <div class="why-list">
              <article>
                <b>01</b>
                <div>
                  <h3>One address</h3>
                  <p>Receive assets and build history without changing your wallet identity.</p>
                </div>
              </article>
              <article>
                <b>02</b>
                <div>
                  <h3>Atomic rotation</h3>
                  <p>A supported action and the move to its next owner succeed together.</p>
                </div>
              </article>
              <article>
                <b>03</b>
                <div>
                  <h3>Your keys, your control</h3>
                  <p>Quick keys stay in memory. Recovery setup stays local and can be encrypted.</p>
                </div>
              </article>
              <article>
                <b>04</b>
                <div>
                  <h3>Familiar Ethereum</h3>
                  <p>
                    {experimentalEnabled()
                      ? 'Standard ECDSA, plus optional experimental PQ signing on Sepolia. Test ETH only.'
                      : 'Standard ECDSA and open-source contracts. No new chain or experimental cryptography.'}
                  </p>
                </div>
              </article>
            </div>
          </section>
          <section class="flow">
            <span>How it works</span>
            <h2>
              One wallet. Fresh keys.
              <br />
              Every action.
            </h2>
            <ol>
              <li>
                <b>Create</b>
                <small>Make a browser key.</small>
              </li>
              <li>
                <b>Fund</b>
                <small>Skipped in local mode.</small>
              </li>
              <li>
                <b>Deploy</b>
                <small>Get one wallet address.</small>
              </li>
              <li>
                <b>Use</b>
                <small>Act and rotate atomically.</small>
              </li>
            </ol>
          </section>
          <section class="roadmap">
            <div>
              <span>The important distinction</span>
              <h2>
                Reduce quantum-
                <br />
                attack exposure.
              </h2>
            </div>
            <p>
              Bunker still uses standard ECDSA. Rotation reduces how long an exposed owner remains
              useful; it does not make Ethereum post-quantum secure.
            </p>
            <div class="roadmap-links">
              <button class="primary" onClick={begin}>
                Try It (Simulation)
              </button>
              <a
                href="https://github.com/SilentCicero/bunker-wallet"
                target="_blank"
                rel="noreferrer"
              >
                View the source →
              </a>
            </div>
            <small>Ledger, Trezor, and offline signing remain planned and audit-gated.</small>
          </section>
        </Show>
        <Show when={view() === 'setup'}>
          <section class="setup">
            <Show when={mode() === 'sepolia'}>
              <SepoliaCreationStepper
                current={creationStep(setupBalance() >= parseEther('0.03') ? 4 : 3)}
                experimental={experimentalEnabled()}
              />
            </Show>
            <h1>
              {mode() === 'local'
                ? 'Your local preview is ready.'
                : setupBalance() >= parseEther('0.03')
                  ? 'Create your Safe wallet.'
                  : 'Add Ethereum Sepolia test ETH.'}
            </h1>
            <p>
              {mode() === 'local'
                ? 'No faucet, wallet connection, or blockchain transaction. Everything stays in this tab.'
                : setupBalance() >= parseEther('0.03')
                  ? experimentalEnabled()
                    ? 'Your setup key is funded. Create and fund your permanent Safe address.'
                    : 'Your setup key is funded. Create the guarded Safe and move the test ETH into its permanent address.'
                  : 'Your temporary setup address is ready and copied when you open the faucet. The unaudited Safe supports 19 rotations and has no migration path. This unaudited public test build is restricted to Sepolia test ETH.'}
            </p>
            <p class="signing-status">
              <strong>Standard</strong> · ECDSA only · No PQ signature
            </p>
            <Show when={!recoverable()}>
              <p class="ephemeral-note">
                Quick setup is memory-only. Do not refresh during funding or after wallet creation.
                Use Recovery phrase setup if you want restoration later.
              </p>
            </Show>
            <Show when={recoverable()}>
              <p class="saved-note">
                {savedVault()
                  ? 'Saved on this browser, encrypted with your password. Refresh requires unlock.'
                  : 'Saved to this browser with a non-extractable device key. Keep the recovery phrase offline.'}
              </p>
            </Show>
            <div class="setup-address">
              <span>Setup address</span>
              <code>{setupAddress()}</code>
              <button onClick={() => copy(setupAddress())}>Copy</button>
            </div>
            <div class="balance-row">
              <span>{mode() === 'local' ? 'Preview balance' : 'Setup balance'}</span>
              <strong>{Number(formatEther(setupBalance())).toFixed(4)} ETH</strong>
            </div>
            <Show
              when={mode() === 'local' || setupBalance() >= parseEther('0.03')}
              fallback={
                <div class="setup-actions">
                  <button class="primary" onClick={openFaucet}>
                    Open Google Cloud faucet
                  </button>
                  <button onClick={checkFunding} disabled={Boolean(busy())}>
                    {busy() || 'I funded it — check balance'}
                  </button>
                </div>
              }
            >
              <button
                class="primary wide"
                onClick={walletAddress() ? checkCreatedSafe : createStableWallet}
                disabled={
                  Boolean(busy()) ||
                  checking() ||
                  Boolean(
                    experimentalEnabled() &&
                      !walletAddress() &&
                      readSetupJournal()?.state === 'deploying',
                  )
                }
              >
                {busy() ||
                  checking() ||
                  (walletAddress()
                    ? 'Check Safe status'
                    : experimentalEnabled()
                      ? 'Create Safe wallet'
                      : 'Create guarded Safe')}
              </button>
              <Show when={mode() === 'sepolia' && busy()}>
                <section class="deploy-status" aria-live="polite">
                  <div class="deploy-spinner" aria-hidden="true" />
                  <div>
                    <h2>Deploying your guarded Safe</h2>
                    <p>
                      Creating the guard, Safe proxy, and funding transaction. This usually takes
                      1–3 minutes. Keep this tab open.
                    </p>
                  </div>
                  <ol>
                    <li>Verify official Safe components</li>
                    <li>Install the rotation guard</li>
                    <li>Create and fund your stable address</li>
                  </ol>
                  <button onClick={checkCreatedSafe} disabled={checking()}>
                    {checking() ? 'Checking Sepolia…' : 'Check deployment status'}
                  </button>
                </section>
              </Show>
            </Show>
            <Show
              when={
                experimentalEnabled() &&
                !busy() &&
                !walletAddress() &&
                readSetupJournal()?.state === 'deploying'
              }
            >
              <p class="ephemeral-note">
                Safe deployment may already be on-chain. Do not create another Safe. Inspect the
                original setup key’s transactions
                {readSetupJournal()?.factoryHash && (
                  <>
                    {' '}
                    (factory hash <code>{readSetupJournal()?.factoryHash}</code>)
                  </>
                )}{' '}
                and recover with the confirmed Safe address.
              </p>
            </Show>
            <button class="text-button" onClick={() => go('advanced')}>
              Use another setup method
            </button>
          </section>
        </Show>
        <Show when={view() === 'wallet' && walletAddress()}>
          <section class="wallet">
            <div class="wallet-top">
              <div>
                <span class="status-dot">
                  {mode() === 'local'
                    ? 'Local preview · simulated, not broadcast'
                    : 'Ethereum Sepolia Safe · live'}
                </span>
                <h1>{Number(formatEther(walletBalance())).toFixed(4)} ETH</h1>
              </div>
              <div class="rotation-card">
                <span>ECDSA ROTATION</span>
                <strong>Key {rotation() + 1}</strong>
                <p>Single elliptic rotation</p>
                <div>
                  <i style={{ width: `${Math.min(100, (rotation() + 1) * 8)}%` }} />
                </div>
              </div>
            </div>
            <p class="signing-status">
              <strong>Standard</strong> · ECDSA only · No PQ signature
            </p>
            <Show when={mode() === 'sepolia'}>
              <p class="session-note">
                This browser stays unlocked across refreshes and restarts until you select Lock or
                clear site data. Anyone controlling this browser profile, origin, or an extension
                can use an unlocked wallet.
              </p>
            </Show>
            <div class="stable">
              <span>Stable Safe address</span>
              <button
                class="stable-copy"
                aria-label="Copy stable Safe address"
                onClick={() => copy(walletAddress())}
              >
                <code>{walletAddress()}</code>
                <span>Copy</span>
              </button>
              <b>Does not change</b>
            </div>
            <Show when={mode() === 'local'}>
              <section class="signer-sequence">
                <div>
                  <span>Preview signing sequence</span>
                  <small>
                    BIP-39 → hardened BIP-32 · memory-only mnemonic · separate wallet and owner
                    branches
                  </small>
                </div>
                <div class="signer-steps">
                  <div>
                    <small>Last signer</small>
                    <code>
                      {activity()[0]?.usedSigner ? short(activity()[0]?.usedSigner!) : '—'}
                    </code>
                  </div>
                  <i>→</i>
                  <div class="current">
                    <small>Active signer · Key {rotation() + 1}</small>
                    <code>{owner() && short(owner()!)}</code>
                  </div>
                  <i>→</i>
                  <div>
                    <small>Next signer · Key {rotation() + 2}</small>
                    <code>{nextSigner() && short(nextSigner()!)}</code>
                  </div>
                </div>
              </section>
            </Show>
            <div class="wallet-grid">
              <section class="actions-panel">
                <h2>Send ETH</h2>
                <label>
                  Recipient
                  <input ref={to} value="vitalik.eth" placeholder="0x… or name.eth" />
                  <small>
                    ENS uses Ethereum mainnet resolution. Paste a 0x address if name resolution is
                    unavailable.
                  </small>
                </label>
                <label>
                  Amount
                  <input ref={amount} value="0.0001" inputmode="decimal" placeholder="0.001" />
                </label>
                <button
                  class="primary wide"
                  onClick={runETH}
                  disabled={Boolean(busy()) || (mode() === 'sepolia' && rotation() >= 19)}
                >
                  {busy() ||
                    (mode() === 'sepolia' && rotation() >= 19
                      ? 'Sequence exhausted'
                      : 'Send + rotate key')}
                </button>
              </section>
              <aside class="activity">
                <h2>Signing rotation history</h2>
                <p class="history-intro">
                  {mode() === 'sepolia'
                    ? 'Linked sends transfer ETH and advance the Safe owner in one guarded operation. Open any entry to inspect its actual Sepolia transaction, calldata, and logs.'
                    : 'Your wallet address stays fixed. Each simulated action advances the signer.'}
                </p>
                <For each={activity()}>
                  {(item) => <HistoryEntry item={item} rotation={rotation()} />}
                </For>
              </aside>
            </div>
          </section>
        </Show>
        <Show when={view() === 'advanced'}>
          <section class="advanced">
            <Show
              when={experimentalEnabled()}
              fallback={
                <>
                  <button class="back" onClick={() => go('landing')}>
                    ← Back
                  </button>
                  <h1>Choose how to protect the setup key.</h1>
                  <p>Each method creates a stable Safe address with automatic owner rotation.</p>
                  <SigningModes selected={pqMode()} />
                </>
              }
            >
              <SepoliaCreationStepper current={1} experimental />
              <div class="workflow-heading">
                <button class="back" onClick={() => go('landing')}>
                  ← Back
                </button>
                <h1>Choose how to sign.</h1>
              </div>
              <SigningModes
                experimental
                selected={pqMode()}
                onSelect={(selected) => {
                  setPQMode(selected);
                  setReplacingStandard(false);
                  setAckStandard(false);
                }}
              />
              <Show
                when={
                  !uncertainStandardSetup() &&
                  !(
                    pqMode() === 'standard' &&
                    (localStorage.getItem('bunker-vault') ||
                      localStorage.getItem('bunker-safe-wallet') ||
                      localStorage.getItem(STANDARD_SETUP))
                  ) &&
                  !(
                    pqMode() !== 'standard' &&
                    (localStorage.getItem(PQ_RECORD) || localStorage.getItem(PQ_VAULT))
                  ) &&
                  !replacingPQ() &&
                  !invalidPQ()
                }
              >
                <div class="secure-actions">
                  <button class="primary" onClick={createPhrase}>
                    Create wallet
                  </button>
                </div>
              </Show>
              <Show
                when={
                  uncertainStandardSetup() ||
                  (pqMode() === 'standard' &&
                    (localStorage.getItem('bunker-vault') ||
                      localStorage.getItem('bunker-safe-wallet') ||
                      localStorage.getItem(STANDARD_SETUP)))
                }
              >
                <div class="replace-wallet" role="group" aria-label="Saved Standard setup">
                  <h2>
                    {uncertainStandardSetup()
                      ? 'Standard setup outcome uncertain'
                      : 'Standard wallet already saved'}
                  </h2>
                  <p>
                    {uncertainStandardSetup()
                      ? 'A Standard transaction may still confirm. Inspect its original hash before trying another setup. This browser cannot safely start another wallet until the outcome is resolved.'
                      : 'This browser already holds a Standard wallet. Recover it here, or explicitly delete only its local browser data before creating another. Its on-chain Safe and funds remain unchanged.'}
                  </p>
                  <Show when={readSetupJournal()?.factoryHash}>
                    {(hash) => (
                      <p>
                        <a
                          href={`https://sepolia.etherscan.io/tx/${hash()}`}
                          target="_blank"
                          rel="noreferrer"
                        >
                          Inspect the original Standard transaction
                        </a>
                      </p>
                    )}
                  </Show>
                  <Show when={!uncertainStandardSetup()}>
                    <Show
                      when={replacingStandard()}
                      fallback={
                        <button onClick={() => setReplacingStandard(true)}>
                          Delete local Standard data & create new
                        </button>
                      }
                    >
                      <p>
                        Deleting this browser's Standard vault and checkpoint does not delete the
                        old Safe or move its test ETH. Keep its original phrase and Safe address; a
                        transaction submitted before Lock may still confirm.
                      </p>
                      <label class="check">
                        <input
                          type="checkbox"
                          checked={ackStandard()}
                          onChange={(event) => setAckStandard(event.currentTarget.checked)}
                        />{' '}
                        I saved the old phrase and Safe address, or accept losing access to its test
                        ETH and unfinished setup.
                      </label>
                      <button
                        disabled={!ackStandard() || Boolean(busy())}
                        onClick={replaceSavedStandard}
                      >
                        {busy() || 'Delete local data & create new'}
                      </button>
                    </Show>
                  </Show>
                  <div class="secure-actions">
                    <button class="primary" onClick={() => go('recover')}>
                      Recover wallet
                    </button>
                    <button onClick={() => go('landing')}>Cancel</button>
                  </div>
                </div>
              </Show>
              <Show
                when={
                  pqMode() !== 'standard' &&
                  (localStorage.getItem(PQ_RECORD) || localStorage.getItem(PQ_VAULT)) &&
                  !replacingPQ() &&
                  !invalidPQ() &&
                  !uncertainStandardSetup()
                }
              >
                <div
                  class="replace-wallet"
                  role="group"
                  aria-label="Checking saved experimental setup"
                >
                  <h2>
                    {pendingPQHash(localStorage.getItem(PQ_RECORD))
                      ? 'Pending saved experimental setup'
                      : 'Checking saved experimental setup'}
                  </h2>
                  <p>
                    Saved browser data needs checking before another test wallet can be created. No
                    data was changed.
                  </p>
                  <div class="secure-actions">
                    <button class="primary" onClick={() => go('recover')}>
                      Recover wallet
                    </button>
                    <button onClick={downloadPQCheckpoint}>Download private checkpoint copy</button>
                    <button onClick={() => go('landing')}>Cancel</button>
                    <button disabled>Continue — checking saved setup</button>
                  </div>
                </div>
              </Show>
              <Show when={replacingPQ() && !uncertainStandardSetup()}>
                <div class="replace-wallet" role="group" aria-label="Replace saved test wallet">
                  <h2>Replace saved test wallet?</h2>
                  <p>
                    This deletes only the experimental wallet's browser backup and deployment
                    checkpoint. It does not delete its on-chain Safe or move its funds. To use that
                    Safe again you need its original phrase and Safe address. Abandoning an
                    unfinished setup also loses its saved deployment addresses; test ETH at its
                    setup key still needs the original phrase. Uncertain transactions cannot be
                    replaced.
                  </p>
                  <label class="check">
                    <input
                      type="checkbox"
                      checked={ackPQ()}
                      onChange={(event) => setAckPQ(event.currentTarget.checked)}
                    />{' '}
                    I saved the old phrase and Safe address (if created), or accept losing access to
                    its test ETH and unfinished setup.
                  </label>
                  <div class="secure-actions">
                    <button class="primary" onClick={() => go('recover')}>
                      Recover wallet
                    </button>
                    <button onClick={() => go('landing')}>Cancel</button>
                    <button disabled={!ackPQ() || Boolean(busy())} onClick={replaceSavedPQ}>
                      {busy() || 'Continue — replace local wallet'}
                    </button>
                  </div>
                </div>
              </Show>
              <Show when={invalidPQ() && !uncertainStandardSetup()}>
                <div
                  class="replace-wallet"
                  role="group"
                  aria-label={
                    pendingPQ()
                      ? 'Pending saved experimental setup'
                      : 'Unverified saved experimental setup'
                  }
                >
                  <h2>
                    {pendingPQ()
                      ? 'Pending saved experimental setup'
                      : 'Unverified saved experimental setup'}
                  </h2>
                  <p>
                    {pendingPQ()
                      ? 'The original signed transaction may still confirm on Sepolia. Restore or resume the saved setup to check its original outcome. Archiving local data cannot cancel the transaction or move any test ETH.'
                      : 'The browser checkpoint is missing or cannot be verified. A signed transaction may still confirm on Sepolia. Clearing this browser cannot cancel it; keep your original phrase, Safe address, and transaction hash if known. Without a Safe address, do not attempt automatic recovery.'}
                  </p>
                  <Show
                    when={pendingPQHash(localStorage.getItem(PQ_RECORD)) ?? archivedPendingHash()}
                  >
                    {(hash) => (
                      <p>
                        <a
                          href={`https://sepolia.etherscan.io/tx/${hash()}`}
                          target="_blank"
                          rel="noreferrer"
                        >
                          Inspect the original transaction
                        </a>{' '}
                        before choosing an action.
                      </p>
                    )}
                  </Show>
                  <div class="secure-actions">
                    <button onClick={downloadPQCheckpoint}>Download private checkpoint copy</button>
                    <button class="primary" onClick={() => go('recover')}>
                      {pendingPQ() ? 'Recover / resolve saved setup' : 'Recover wallet'}
                    </button>
                  </div>
                  <label class="check">
                    <input
                      type="checkbox"
                      checked={ackPQ()}
                      onChange={(event) => setAckPQ(event.currentTarget.checked)}
                    />{' '}
                    I saved the old phrase and Safe address (if any), understand an archived
                    transaction may still confirm, and accept losing access to unfinished setup.
                  </label>
                  <div class="secure-actions">
                    <button onClick={() => go('landing')}>Cancel</button>
                    <button disabled={!ackPQ() || Boolean(busy())} onClick={startAfterArchive}>
                      {busy() || 'Continue — archive local record & create new'}
                    </button>
                  </div>
                  <p>
                    The archive stays in this browser; download a private copy before clearing site
                    data. Neither option rebroadcasts a transaction.
                  </p>
                </div>
              </Show>
            </Show>
            <Show when={!experimentalEnabled()}>
              <div class="option-list">
                <button disabled>
                  <span>
                    {sepoliaEnabled
                      ? 'Quick Sepolia setup disabled'
                      : 'Use Ethereum Sepolia (Soon)'}
                  </span>
                  <small>
                    {sepoliaEnabled
                      ? 'Encrypted recovery is required so refresh cannot lose access'
                      : 'Unaudited · public Sepolia test build · 19 rotations'}
                  </small>
                  <b>Soon</b>
                </button>
                <button
                  disabled={!sepoliaEnabled}
                  onClick={sepoliaEnabled ? createPhrase : undefined}
                >
                  <span>Recovery phrase</span>
                  <small>24 words · available with Sepolia</small>
                  <b>{sepoliaEnabled ? 'Set up' : 'Soon'}</b>
                </button>
                <button
                  disabled={!sepoliaEnabled}
                  onClick={
                    sepoliaEnabled
                      ? () => {
                          setMode('sepolia');
                          go('load');
                        }
                      : undefined
                  }
                >
                  <span>Load existing wallet</span>
                  <small>Encrypted vault or 24 words</small>
                  <b>{sepoliaEnabled ? 'Load' : 'Soon'}</b>
                </button>
                <button disabled>
                  <span>Ledger</span>
                  <small>Hardware setup · compatibility verification in progress</small>
                  <b>Soon</b>
                </button>
                <button disabled>
                  <span>Trezor</span>
                  <small>Hardware setup · compatibility verification in progress</small>
                  <b>Soon</b>
                </button>
                <button disabled>
                  <span>EVM wallet</span>
                  <small>Manual next-key proof required</small>
                  <b>Soon</b>
                </button>
              </div>
            </Show>
          </section>
        </Show>
        <Show when={view() === 'phrase'}>
          <section class="secure">
            <SepoliaCreationStepper
              current={creationStep(1)}
              experimental={experimentalEnabled()}
              onStep={busy() ? undefined : rewindDraft}
            />
            <span class="status-dot">Secure setup</span>
            <h1>Write down these 24 words.</h1>
            <p>Keep them offline. They recover every owner key in sequence.</p>
            <Show
              when={experimentalEnabled()}
              fallback={
                <details class="signing-disclosure">
                  <summary>Signing mode: Standard (ECDSA only)</summary>
                  <SigningModes />
                </details>
              }
            >
              <p class="selected-mode">
                Signing mode:{' '}
                <strong>
                  {pqMode() === 'standard'
                    ? 'Standard'
                    : pqMode() === 'c10'
                      ? 'Quantum Shield'
                      : 'Maximum'}
                </strong>{' '}
                · chosen before backup
              </p>
            </Show>
            <ol class="words" ref={phraseList} />
            <label class="check">
              <input
                type="checkbox"
                checked={confirmed()}
                onChange={(e) => setConfirmed(e.currentTarget.checked)}
              />{' '}
              I saved the phrase offline.
            </label>
            <div class="secure-actions">
              <button class="primary" disabled={!confirmed()} onClick={() => go('confirm')}>
                Check my backup
              </button>
              <button disabled={!confirmed()} onClick={() => go('vault')}>
                Skip check
              </button>
            </div>
          </section>
        </Show>
        <Show when={view() === 'confirm'}>
          <section class="secure">
            <SepoliaCreationStepper
              current={creationStep(1)}
              experimental={experimentalEnabled()}
              onStep={busy() ? undefined : rewindDraft}
              revisitCurrent
            />
            <h1>Quick recovery check.</h1>
            <p>Enter words 3, 9, and 18.</p>
            <div class="confirm">
              <For each={[3, 9, 18]}>
                {(n, i) => (
                  <label>
                    Word {n}
                    <input ref={(el) => (confirmInputs[i()] = el)} />
                  </label>
                )}
              </For>
            </div>
            <button class="primary" onClick={verifyWords}>
              Continue
            </button>
          </section>
        </Show>
        <Show when={view() === 'vault'}>
          <section class="secure">
            <SepoliaCreationStepper
              current={creationStep(2)}
              experimental={experimentalEnabled()}
              onStep={busy() ? undefined : rewindDraft}
            />
            <h1>{sepoliaEnabled ? 'Protect this browser wallet.' : 'Add a password?'}</h1>
            <p>
              {experimentalEnabled() && pqMode() !== 'standard'
                ? 'Required to resume setup after refresh. A password encrypts a saved browser vault; unlock it with your password after refresh or Lock.'
                : sepoliaEnabled
                  ? 'Optional. This browser keeps the wallet encrypted and available across refreshes and restarts until you select Lock.'
                  : 'Optional. A password encrypts the recovery phrase on this device.'}
            </p>
            <label>
              Password · 12 characters minimum
              <input ref={password} type="password" autocomplete="new-password" />
            </label>
            <div class="secure-actions">
              <button class="primary" onClick={() => finishSecure(true)}>
                {sepoliaEnabled ? 'Encrypt and save this browser' : 'Encrypt and continue'}
              </button>
              <Show when={!experimentalEnabled() || pqMode() === 'standard'}>
                <button onClick={() => finishSecure(false)}>
                  {sepoliaEnabled ? 'Continue without password' : 'Continue without saving'}
                </button>
              </Show>
            </div>
            <Show when={sepoliaEnabled}>
              <p class="ephemeral-note">
                {experimentalEnabled() && pqMode() !== 'standard'
                  ? 'Keep an offline copy of your phrase and password: clearing site data removes the encrypted vault.'
                  : 'Without a password, this browser uses a non-extractable device key. It remains unlocked until Lock or site-data removal; keep the 24-word phrase for recovery elsewhere.'}
              </p>
            </Show>
          </section>
        </Show>
        <Show when={view() === 'pq' && experimentalEnabled() && pqMode() !== 'standard'}>
          <div class="pq-workflow">
            <ExperimentalWallet
              creationStepper={(current) => (
                <SepoliaCreationStepper current={current} experimental />
              )}
              mode={pqMode() as 'c10' | 'mldsa44'}
              bootstrap={pqBootstrap()}
              entry={pqEntry()}
              onBootstrapped={() => {
                setPQBootstrap();
                setSavedPQ(
                  Boolean(
                    localStorage.getItem('bunker-experimental-vault-v1') ||
                      localStorage.getItem('bunker-experimental-wallet-v1'),
                  ),
                );
              }}
              onLocked={() => go('landing')}
            />
          </div>
        </Show>
        <Show when={view() === 'recover' && experimentalEnabled()}>
          <section class="secure recover-screen">
            <div class="workflow-heading">
              <button class="back" onClick={() => go('landing')}>
                ← Back
              </button>
              <h1>Recover your wallet.</h1>
            </div>
            <Show
              when={savedVault() || Boolean(localStorage.getItem('bunker-experimental-vault-v1'))}
            >
              <div class="load-choice">
                <h2>Saved on this browser</h2>
                <p>
                  Use the password for the wallet already saved here. No new Safe or transaction is
                  created.
                </p>
                <Show when={savedVault()}>
                  <label>
                    Standard vault password
                    <input ref={password} type="password" autocomplete="current-password" />
                  </label>
                  <button
                    class="primary wide"
                    disabled={Boolean(busy())}
                    onClick={() => load(true)}
                  >
                    {busy() ||
                      (localStorage.getItem('bunker-experimental-vault-v1')
                        ? 'Recover saved Standard wallet'
                        : 'Recover saved wallet')}
                  </button>
                </Show>
                <Show when={localStorage.getItem('bunker-experimental-vault-v1')}>
                  <label>
                    Experimental vault password
                    <input ref={savedPQPassword} type="password" autocomplete="current-password" />
                  </label>
                  <button class="primary wide" disabled={Boolean(busy())} onClick={recoverSavedPQ}>
                    {savedVault() ? 'Recover saved experimental wallet' : 'Recover saved wallet'}
                  </button>
                </Show>
              </div>
            </Show>
            <Show
              when={
                localStorage.getItem('bunker-experimental-wallet-v1') &&
                !localStorage.getItem('bunker-experimental-vault-v1')
              }
            >
              <div class="load-choice">
                <h2>Recover interrupted setup</h2>
                <p>
                  This older checkpoint contains public setup progress, not your phrase. You must
                  enter the original phrase; do not share it.
                </p>
                <button onClick={() => openSavedPQ('resume')}>Enter original phrase</button>
              </div>
            </Show>
            <div class="load-choice">
              <h2>
                {savedVault() || savedPQ()
                  ? 'Or use phrase + Safe address'
                  : 'Recover with phrase + Safe address'}
              </h2>
              <p>
                Enter the original 24-word phrase and existing Safe address. The Safe determines its
                signing mode; nothing is deployed.
              </p>
              <label>
                24-word recovery phrase
                <textarea ref={restore} rows="3" autocomplete="off" spellcheck={false} />
              </label>
              <label>
                Existing Safe address
                <input ref={walletInput} placeholder="0x…" />
              </label>
              <label>
                Browser password · 12–256 characters
                <input ref={recoverPassword} type="password" autocomplete="new-password" />
              </label>
              <p>
                If a vault for this wallet is already saved here, enter its current password.
                Otherwise choose a new password to encrypt the recovered browser wallet.
              </p>
              <button class="primary wide" disabled={Boolean(busy())} onClick={recoverWallet}>
                {busy() || 'Recover and save wallet'}
              </button>
            </div>
          </section>
        </Show>
        <Show when={view() === 'load'}>
          <section class="secure">
            <Show
              when={experimentalEnabled()}
              fallback={
                <>
                  <button class="back" onClick={() => go('advanced')}>
                    ← Back
                  </button>
                  <h1>Resume or recover.</h1>
                  <Show when={localStorage.getItem('bunker-vault')}>
                    <div class="load-choice">
                      <h2>Unlock saved browser wallet</h2>
                      <p>Use the password that encrypted this browser’s vault.</p>
                      <label>
                        Vault password
                        <input ref={password} type="password" autocomplete="current-password" />
                      </label>
                      <button class="primary" onClick={() => load()}>
                        Unlock saved wallet
                      </button>
                    </div>
                  </Show>
                  <div class="load-choice">
                    <h2>Recover with 24-word phrase</h2>
                    <p>
                      No password is required. Enter the Safe address when recovering a wallet that
                      is not already saved here.
                    </p>
                    <label>
                      Recovery phrase
                      <textarea ref={restore} rows="4" autocomplete="off" spellcheck={false} />
                    </label>
                    <label>
                      Stable Safe address · optional
                      <input ref={walletInput} placeholder="0x… (needed on a new device)" />
                    </label>
                    <button class="primary" onClick={() => load()}>
                      Recover with phrase
                    </button>
                  </div>
                  <div class="load-choice">
                    <h2>Create a new wallet</h2>
                    <p>
                      Saving it later replaces this browser’s stored vault. Keep the old phrase and
                      Safe address before continuing.
                    </p>
                    <button onClick={createPhrase}>Create new wallet</button>
                  </div>
                </>
              }
            >
              <div class="workflow-heading">
                <button class="back" onClick={() => go('landing')}>
                  ← Back
                </button>
                <h1>Resume saved setup.</h1>
              </div>
              <Show when={savedVault()}>
                <div class="load-choice">
                  <h2>Standard vault</h2>
                  <label>
                    Vault password
                    <input ref={password} type="password" autocomplete="current-password" />
                  </label>
                  <button class="primary" onClick={() => load()}>
                    Recover saved wallet
                  </button>
                </div>
              </Show>
              <Show when={!savedVault() && readSetupJournal()?.state === 'ready'}>
                <div class="load-choice">
                  <h2>Resume unfinished Standard setup</h2>
                  <p>
                    No Safe exists yet. The original phrase must match this browser's saved setup
                    key; this is not Safe recovery.
                  </p>
                  <label>
                    Original 24-word phrase
                    <textarea ref={restore} rows="3" autocomplete="off" spellcheck={false} />
                  </label>
                  <button class="primary" disabled={Boolean(busy())} onClick={resumeStandardSetup}>
                    {busy() || 'Resume setup'}
                  </button>
                </div>
              </Show>
              <Show when={localStorage.getItem('bunker-experimental-vault-v1')}>
                <div class="load-choice">
                  <h2>Experimental vault</h2>
                  <button class="primary" onClick={() => openSavedPQ('unlock')}>
                    Unlock saved experimental wallet
                  </button>
                </div>
              </Show>
              <Show
                when={
                  localStorage.getItem('bunker-experimental-wallet-v1') &&
                  !localStorage.getItem('bunker-experimental-vault-v1')
                }
              >
                <div class="load-choice">
                  <h2>Unfinished experimental setup</h2>
                  <p>
                    The checkpoint alone cannot restore your phrase. Enter the original phrase to
                    continue.
                  </p>
                  <button onClick={() => openSavedPQ('resume')}>Enter original phrase</button>
                </div>
              </Show>
              <Show when={!savedVault() && !savedPQ() && readSetupJournal()?.state !== 'ready'}>
                <p>
                  No browser vault or setup checkpoint is saved here. Use Recover wallet with your
                  phrase and Safe address.
                </p>
              </Show>
            </Show>
          </section>
        </Show>
      </main>
      <footer>
        <span>
          {experimentalEnabled()
            ? 'Bunker · Experimental Sepolia · Test ETH only'
            : 'Bunker · Local preview · Ethereum Sepolia soon'}
        </span>
        <span>Stable address · Rotating ECDSA owners</span>
      </footer>
    </div>
  );
}
