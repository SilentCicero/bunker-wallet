# Security status

**Public status: unaudited local/testnet alpha. Do not use mainnet or meaningful funds.**

## Implemented

- Default local preview uses a hidden, memory-only BIP-39 mnemonic and fully hardened BIP-32 owner paths, with no RPC, faucet, broadcast, persistence, or real assets.
- Optional Ethereum Sepolia Safe 1.4.1 proxy deployment using the official canonical singleton, proxy factory, and `MultiSendCallOnly` addresses.
- Atomic Safe setup helper that initializes and installs a guard during proxy creation. Existing Standard Safes retain `BunkerRotationGuard`; fresh isolated-preview Standard Safes use `BunkerRotationGuardV3`.
- Runtime hash checks for official Safe components before deployment and Safe owner/module/guard/singleton attestation before funding.
- ETH send, exact next-owner gas funding, and owner rotation in one guarded Safe transaction.
- Fixed Standard 20-owner sequence with 19 ordinary rotations. Legacy guards reject arbitrary calls; V3 guards permit only 1–8 bounded external `CALL`s followed by exact atomic owner rotation. Safe administration, modules, refunds and inner delegatecalls remain rejected.
- Canonical ABI-padding support and 65-byte canonical-low-s ECDSA signature policy.
- Receipt-uncertainty reconciliation before promoting the next browser signer.
- Recovery-phrase mode derives owners deterministically; quick setup remains memory-only and unrecoverable after refresh.
- 24-word BIP-39 generation and authenticated Argon2id/AES-GCM local vaults.
- Runtime chain policy limited to local Anvil `31337` and Ethereum Sepolia `11155111`.

## Local-only hybrid research (not a PQ wallet release)

Separate C10/ML-DSA-44 Safe contract-owner adapters, atomic setup, 2-of-2 hybrid guard, EC/PQ rotation, sequence renewal and signature encoding remain restricted to chain **31337**. Standard contracts are unchanged. This research kernel uses fixture-only ML-DSA admission, not genuine-key registration, and mock-verifier policy tests do not prove post-quantum security. The original upstream C10 browser signer targets C13; a separate pinned C10-FIPS WASM adaptation and Sepolia experiment are described below. See [research plan](docs/hybrid-pq-plan.md) and [contract details](packages/contracts/README.md).

## Disabled

Mainnet; ERC-20, message and arbitrary contract-call UI (V3 contract-only external CALL support is separate); Safe refunds; modules; guard changes; Standard-wallet sequence refill (PQ renewal is separate); Ledger/Trezor signing; manual injected signing; WalletConnect; QR transport; production relayer deployment; emergency bypasses.

## Test status and release blockers

Foundry integration tests execute the vendored Safe 1.4.1 proxy, setup helper, guard, and MultiSend path locally. They cover atomic setup, canonical padded execution, ETH transfer, next-owner funding, owner rotation, malformed funding rejection, and sequence exhaustion. Browser checks cover the local preview, explicitly gated Standard Sepolia persistence and the separately gated experimental PQ flows on disposable local Anvil. Default builds leave experimental PQ disabled.

Restricted-value Ethereum Sepolia tests passed on 2026-10-09. The direct smoke covered deploy → fund → ETH send → exact next-owner funding → two successive owner rotations → phrase recovery. A separate local-only browser run generated a fresh 24-word phrase in the app, encrypted it into an Argon2id/AES-GCM browser vault, funded the displayed setup address through the protected sponsor Safe, clicked through Safe creation, submitted two ETH sends, reloaded and unlocked the encrypted vault, restored the same Safe at key 3, submitted a third rotation to key 4, and verified stable-address continuity against chain state. Sanitized evidence is stored locally with the E2E secret rather than committed with transaction identifiers. The unaudited Sepolia flow is enabled at `https://bunker.supplies` and `https://sepolia-test.bunker-wallet.pages.dev` for disposable test ETH only. Ethereum mainnet and meaningful-funds use remain disabled.

Still required before broader use:

1. Independent audit of the setup helper, guard, browser Safe transaction builder, and recovery flow.
2. Expanded parser fuzzing, malicious recipient/reentrancy tests, and bytecode/proxy attestation tests.
3. A reviewed sequence refill or migration protocol before the nineteenth rotation.
4. Physical Ledger/Trezor firmware testing before hardware support claims.

Browser encryption protects data at rest. A saved wallet survives refreshes and browser restarts using AES-GCM ciphertext and a non-extractable WebCrypto key in IndexedDB. Locking or cleared site data requires the vault password or recovery phrase again. There is no recovery backend. This cannot protect an entered or unlocked phrase from malicious same-origin code, extensions, browser compromise, or the operating system. JavaScript cannot guarantee secure erasure.

## Separately gated experimental browser PQ path

The user authorized trusted-client C10/ML-DSA-44 generation from one 24-word mnemonic for disposable Sepolia test ETH. `packages/contracts-experimental` and `apps/web/src/pq` implement that separate path; the chain-31337 research kernel remains separate. The isolated [Sepolia test preview](https://bunker-wallet-pq-sepolia-test.pages.dev) uses V3 for fresh Standard/C10/ML-DSA Safes; `bunker.supplies` remains on its previous bundle. The shared PQ V3 factory is `0x85e66387d341aa1e03f9165cfd2013340a738a45` (deployed in block 11912805). Existing V1/V2 Safes, exact runtime artifacts and pending signed intents retain their own recovery/reconciliation paths. V3 was released only for testnet after the user explicitly deferred independent review; it remains **unaudited**. Two disposable headless Sepolia tests deployed the real C10/ML-DSA dependencies and one 2-of-2 Safe per mode, funded each Safe, then sent test ETH and rotated its EC owner; all receipts and post-state checks passed. These transactions were **not** submitted from the hosted browser UI. Fresh V3 users fund a setup key and create their own Safe (and for ML-DSA, a prepared-key blob) through shared pinned infrastructure; they do not redeploy the shared verifier/factory. Example older Safes are not reusable user wallets. No public V3 Safe has been created or funded by the release operator. On-chain lengths, centered-lift floor, canonical key identity and code hashes do **not** establish genuine KeyGen provenance or the full public-key/blob mapping: the browser regenerates and attests it before funding/signing/recovery. The signer, verifier and integration remain unaudited. Local disposable-Anvil Playwright created all three modes, sent twice, recovered each from phrase+Safe and sent twice more; invalid guard/factory configurations were rejected. Standard V3 still has a 19-rotation ceiling. Reproduce the local matrix with `bash scripts/run-v3-lifecycle-browser-e2e.sh` and `bun scripts/pq-v3-lifecycle-check.ts` against disposable Anvil; it is not public-chain proof. See [protocol, recovery/outbox semantics, executable checks and release limits](docs/experimental-browser-pq.md).
